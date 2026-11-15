//! Minimalist AWS client for S3 and KMS services
//!
//! This client implements only the essential endpoints required for basic operations
//! while maintaining AWS security standards and following Zig's idioms.

const logger = std.log.scoped(.aws_client);

/// AWS Client configuration
pub const Config = struct {
    /// AWS Region (e.g., "us-east-1")
    region: []const u8,
    /// HTTP client timeout in milliseconds
    timeout_ms: u32 = 10000,
    /// Endpoint URL (optional, for custom endpoints)
    endpoint_url: ?[]const u8 = null,
    /// AWS Credentials
    credentials: Credentials,

    pub fn fromEnvironment(allocator: Allocator) !Config {
        const credentials: Credentials = try .fromEnvironment(allocator);

        const region = try getEnvVar(allocator, "AWS_REGION") orelse {
            std.log.err("Missing environment variabled: AWS_REGION", .{});
            return error.MissingAwsRegion;
        };

        const endpoint_url: ?[]const u8 = try getEnvVar(allocator, "AWS_ENDPOINT_URL");

        return Config{
            .region = region,
            .endpoint_url = endpoint_url,
            .credentials = credentials,
        };
    }

    fn getEnvVar(allocator: Allocator, key: []const u8) !?[]const u8 {
        if (@import("builtin").is_test) {
            return std.testing.environ.getAlloc(allocator, key) catch |err| switch (err) {
                error.EnvironmentVariableMissing => null,
                else => return err,
            };
        }
        return null;
    }

    pub fn forTesting() Config {
        const credentials: Credentials = .{
            .secret_access_key = "test",
            .access_key_id = "test",
        };

        return Config{
            .region = "us-east-1",
            .credentials = credentials,
        };
    }

    pub fn deinit(self: Config, allocator: Allocator) void {
        self.credentials.deinit(allocator);
        allocator.free(self.region);
        if (self.endpoint_url) |url| {
            allocator.free(url);
        }
    }
};

/// AWS Client errors
pub const Error = error{
    InvalidCredentials,
    InvalidRegion,
    RequestFailed,
    InvalidResponse,
    Unauthorized,
    AccessDenied,
    ServiceUnavailable,
    ThrottlingException,
} || Allocator.Error || std.fmt.ParseIntError;

/// Main AWS Client
pub const Client = struct {
    config: Config,

    const Self = @This();

    /// Initialize a new AWS client
    pub fn init(config: Config) Self {
        return Self{
            .config = config,
        };
    }

    /// Get S3 client for bucket operations
    pub fn s3(self: Self) S3Client {
        return .init(self.config);
    }

    /// Get KMS client for encryption operations
    pub fn kms(self: Self) KmsClient {
        return .init(self.config);
    }

    pub fn credentials(self: Self) Credentials {
        return self.config.credentials;
    }

    pub const RequestOptions = struct {
        method: HttpMethod = .GET,
        service: []const u8,
        endpoint: []const u8,
        headers: StringHashMap([]const u8) = .empty,
        body: ?[]const u8 = null,

        pub fn format(self: RequestOptions, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt; // autofix
            _ = options; // autofix

            try writer.print(
                \\RequestOptions
                \\  Method: {}
                \\  Service: {s}
                \\  Endpoint: {s}
                \\  Headers length: {d}
                \\  Body length: {d}
            , .{
                self.method,
                self.service,
                self.endpoint,
                self.headers.count(),
                if (self.body) |b| b.len else 0,
            });
        }
    };

    /// Perform authenticated HTTP request with SigV4 signing
    pub fn request(
        self: Self,
        allocator: Allocator,
        options: RequestOptions,
    ) !http.Response {
        logger.debug("request start: {}", .{options});

        var signed_headers: StringHashMap([]const u8) = .empty;
        defer signed_headers.deinit(allocator);

        // Add provided headers
        var it = options.headers.iterator();
        while (it.next()) |entry| {
            try signed_headers.put(allocator, entry.key_ptr.*, entry.value_ptr.*);
        }

        // Sign the request using AWS Signature Version 4
        var sign_result = try sigv4.signRequest(
            allocator,
            .{
                .credentials = self.config.credentials,
                .region = self.config.region,
                .service = options.service,
                .method = options.method,
                .uri = options.endpoint,
                .headers = signed_headers,
                .payload = options.body,
                .endpoint_url = self.config.endpoint_url,
                .include_content_hash = true,
            },
        );
        defer sign_result.deinit();

        var http_client: HttpClient = .default;

        return try http_client.request(allocator, .{
            .method = options.method,
            .uri = sign_result.endpoint,
            .headers = sign_result.headers,
            .body = options.body,
        });
    }
};

test "AWS Client S3 and KMS access" {
    const testing = std.testing;

    var client = Client.init(.{
        .credentials = .{
            .access_key_id = "AKIAIOSFODNN7EXAMPLE",
            .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
        .region = "us-west-2",
    });

    // Test S3 client access
    const s3_client = client.s3();
    try testing.expectEqualStrings("us-west-2", s3_client.region());

    // Test KMS client access
    const kms_client = client.kms();
    try testing.expectEqualStrings("us-west-2", kms_client.region());
}

test "AWS Client with session token" {
    const testing = std.testing;

    var client = Client.init(.{
        .credentials = .{
            .access_key_id = "ASIAIOSFODNN7EXAMPLE",
            .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            .session_token = "AQoDYXdzEJr...",
        },
        .region = "eu-west-1",
        .timeout_ms = 60000,
    });

    try testing.expect(client.credentials().isTemporary());
    try testing.expectEqual(60000, client.config.timeout_ms);
}

const Allocator = std.mem.Allocator;
const Credentials = @import("Credentials.zig");
const HttpClient = http.Client;
const HttpMethod = std.http.Method;
const KmsClient = kms_lib.Client;
const S3Client = s3_lib.Client;
const StringHashMap = std.StringHashMapUnmanaged;

const std = @import("std");
const http = @import("http.zig");
const sigv4 = @import("sigv4.zig");
const s3_lib = @import("s3.zig");
const kms_lib = @import("kms.zig");
