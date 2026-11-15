//! AWS KMS client implementation
//!
//! Provides essential KMS operations: Encrypt, Decrypt
//! Following Zig idioms with explicit error handling and memory management.

const logger = std.log.scoped(.aws_kms);

/// KMS service name for SigV4 signing
/// KMS API version
/// KMS client errors
pub const KmsError = error{
    KeyNotFound,
    AccessDenied,
    InvalidKeyId,
    InvalidCiphertext,
    DisabledKey,
    KeyUnavailable,
    LimitExceeded,
    InternalFailure,
    InvalidResponse,
    JsonParseError,
    InvalidPlaintext,
} || std.mem.Allocator.Error || http.HttpError || sigv4.SigV4Error;

/// KMS key spec for data key generation
pub const KeySpec = enum {
    AES_256,
    AES_128,

    pub fn toString(self: KeySpec) []const u8 {
        return switch (self) {
            .AES_256 => "AES_256",
            .AES_128 => "AES_128",
        };
    }

    pub fn keySize(self: KeySpec) u32 {
        return switch (self) {
            .AES_256 => 32,
            .AES_128 => 16,
        };
    }
};

/// Encryption result
pub const EncryptResult = struct {
    ciphertext: []const u8,
    key_id: []const u8,

    const Self = @This();

    pub fn deinit(self: Self, allocator: Allocator) void {
        allocator.free(self.ciphertext);
        allocator.free(self.key_id);
    }
};

/// Decryption result
pub const DecryptResult = struct {
    plaintext: []const u8,
    key_id: []const u8,

    const Self = @This();

    pub fn deinit(self: Self, allocator: Allocator) void {
        allocator.free(self.plaintext);
        allocator.free(self.key_id);
    }
};

/// Encryption context type
pub const EncryptionContext = std.StringHashMap([]const u8);

const service = "kms";

/// KMS Client
pub const Client = struct {
    config: AwsConfig,

    const Self = @This();

    /// Initialize KMS client
    pub fn init(config: AwsConfig) Self {
        return Self{ .config = config };
    }

    /// Get the region for this client
    pub fn region(self: Self) []const u8 {
        return self.config.region;
    }

    /// Get the credentials for this client
    pub fn credentials(self: Self) Credentials {
        return self.config.credentials;
    }

    fn awsClient(self: Self) AwsClient {
        return .init(self.config);
    }

    pub const EncryptOptions = struct {
        encryption_context: ?EncryptionContext = null,
        base64_decode_ciphertext: bool = false,
    };

    /// Encrypt data using a KMS key
    pub fn encrypt(
        self: Self,
        allocator: Allocator,
        key_id: []const u8,
        plaintext: []const u8,
        options: EncryptOptions,
    ) !EncryptResult {
        if (key_id.len == 0) return KmsError.InvalidKeyId;
        if (plaintext.len == 0) return KmsError.InvalidPlaintext;
        if (plaintext.len > 4096) return KmsError.InvalidPlaintext; // KMS limit

        const url = try self.buildKMSUrl(allocator);
        defer allocator.free(url);

        // Encode plaintext as base64
        const encoded_plaintext = try base64Encode(allocator, plaintext);
        defer allocator.free(encoded_plaintext);

        // Build request payload
        const payload = try self.buildEncryptPayload(allocator, key_id, encoded_plaintext, options.encryption_context);
        defer allocator.free(payload);

        var headers = StringHashMap([]const u8).empty;
        defer headers.deinit(allocator);

        try headers.put(allocator, "Content-Type", try allocator.dupe(u8, "application/x-amz-json-1.1"));
        try headers.put(allocator, "X-Amz-Target", try allocator.dupe(u8, "TrentService.Encrypt"));
        try headers.put(allocator, "Accept", try allocator.dupe(u8, "application/json"));

        // Make request
        const aws_client = self.awsClient();
        var response = try aws_client.request(allocator, .{
            .method = .POST,
            .service = service,
            .endpoint = url,
            .headers = headers,
            .body = payload,
        });
        defer response.deinit(allocator);

        if (!response.ok()) {
            try handleKmsError(allocator, response);
        }

        return self.parseEncryptResponse(allocator, response.body, .{
            .base64_decode = options.base64_decode_ciphertext,
        });
    }

    pub const DecryptOptions = struct {
        encryption_context: ?EncryptionContext = null,
    };

    /// Decrypt data using KMS
    pub fn decrypt(
        self: Self,
        allocator: Allocator,
        kms_key_id: []const u8,
        ciphertext_blob: []const u8,
        options: DecryptOptions,
    ) !DecryptResult {
        if (ciphertext_blob.len == 0) return KmsError.InvalidCiphertext;

        const url = try self.buildKMSUrl(allocator);
        defer allocator.free(url);

        // Build request payload
        const payload = try self.buildDecryptPayload(
            allocator,
            kms_key_id,
            ciphertext_blob,
            options.encryption_context,
        );
        defer allocator.free(payload);

        var headers = StringHashMap([]const u8).empty;
        defer headers.deinit(allocator);

        try headers.put(allocator, "Content-Type", try allocator.dupe(u8, "application/x-amz-json-1.1"));
        try headers.put(allocator, "X-Amz-Target", try allocator.dupe(u8, "TrentService.Decrypt"));

        // Make request
        var aws_client = self.awsClient();
        var response = try aws_client.request(allocator, .{
            .method = .POST,
            .service = service,
            .endpoint = url,
            .headers = headers,
            .body = payload,
        });
        defer response.deinit(allocator);

        if (!response.ok()) {
            try handleKmsError(allocator, response);
        }

        return self.parseDecryptResponse(allocator, response.body);
    }

    /// Build KMS endpoint URL
    fn buildKMSUrl(self: Self, allocator: Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "https://kms.{s}.amazonaws.com/", .{self.region()});
    }

    /// Build encrypt request payload
    fn buildEncryptPayload(
        self: Self,
        allocator: Allocator,
        key_id: []const u8,
        encoded_plaintext: []const u8,
        encryption_context: ?EncryptionContext,
    ) ![]u8 {
        _ = self; // autofix
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        var obj: std.json.ObjectMap = .empty;
        try obj.put(arena_allocator, "KeyId", .{ .string = key_id });
        try obj.put(arena_allocator, "Plaintext", .{ .string = encoded_plaintext });

        if (encryption_context) |ctx| {
            var enc_ctx: std.json.ObjectMap = .empty;
            var iter = ctx.iterator();
            while (iter.next()) |entry| {
                try enc_ctx.put(arena_allocator, entry.key_ptr.*, .{ .string = entry.value_ptr.* });
            }
            try obj.put(arena_allocator, "EncryptionContext", .{ .object = enc_ctx });
        }

        const json_value = std.json.Value{ .object = obj };
        return try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(json_value, .{})});
    }

    /// Build decrypt request payload
    fn buildDecryptPayload(
        self: Self,
        allocator: Allocator,
        key_id: []const u8,
        ciphertext: []const u8,
        encryption_context: ?EncryptionContext,
    ) ![]u8 {
        _ = self; // autofix
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        var obj: std.json.ObjectMap = .empty;
        try obj.put(arena_allocator, "CiphertextBlob", .{ .string = ciphertext });
        try obj.put(arena_allocator, "KeyId", .{ .string = key_id });

        if (encryption_context) |ctx| {
            var enc_ctx: std.json.ObjectMap = .empty;
            var iter = ctx.iterator();
            while (iter.next()) |entry| {
                try enc_ctx.put(arena_allocator, entry.key_ptr.*, .{ .string = entry.value_ptr.* });
            }
            try obj.put(arena_allocator, "EncryptionContext", .{ .object = enc_ctx });
        }

        const json_value = std.json.Value{ .object = obj };
        return try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(json_value, .{})});
    }

    pub const KmsEncryptResponse = struct {
        CiphertextBlob: []const u8,
        KeyId: []const u8,
    };

    pub const ParseEncryptOptions = struct {
        base64_decode: bool = false,
    };

    /// Parse encrypt response
    fn parseEncryptResponse(self: Self, allocator: Allocator, json: []const u8, options: ParseEncryptOptions) !EncryptResult {
        _ = self; // autofix
        const parsed = std.json.parseFromSlice(KmsEncryptResponse, allocator, json, .{
            .ignore_unknown_fields = true,
        }) catch return KmsError.JsonParseError;
        defer parsed.deinit();

        const ciphertext = blk: {
            if (options.base64_decode) {
                break :blk try base64Decode(allocator, parsed.value.CiphertextBlob);
            } else {
                break :blk try allocator.dupe(u8, parsed.value.CiphertextBlob);
            }
        };

        return EncryptResult{
            .ciphertext = ciphertext,
            .key_id = try allocator.dupe(u8, parsed.value.KeyId),
        };
    }

    /// Parse decrypt response
    fn parseDecryptResponse(self: Self, allocator: Allocator, json: []const u8) !DecryptResult {
        _ = self; // autofix
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return KmsError.JsonParseError;
        defer parsed.deinit();

        const root = parsed.value.object;

        const plaintext_b64 = root.get("Plaintext") orelse return KmsError.JsonParseError;
        const key_id_value = root.get("KeyId") orelse return KmsError.JsonParseError;

        const plaintext = try base64Decode(allocator, plaintext_b64.string);
        const key_id = try allocator.dupe(u8, key_id_value.string);

        return DecryptResult{
            .plaintext = plaintext,
            .key_id = key_id,
        };
    }
};

const KmsErrorResponse = struct {
    message: []const u8,
};

fn handleKmsError(allocator: Allocator, response: Response) !void {
    const payload = try std.json.parseFromSlice(KmsErrorResponse, allocator, response.body, .{
        .ignore_unknown_fields = true,
    });
    defer payload.deinit();

    logger.warn("KMS error: {s}", .{payload.value.message});

    return switch (response.status) {
        .bad_request,
        => KmsError.InvalidKeyId,
        .forbidden => KmsError.AccessDenied,
        .not_found => KmsError.KeyNotFound,
        .internal_server_error, .bad_gateway, .service_unavailable, .gateway_timeout => KmsError.InternalFailure,
        else => KmsError.InvalidResponse,
    };
}

fn base64Encode(allocator: Allocator, data: []const u8) ![]const u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(data.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    return encoder.encode(encoded, data);
}

fn base64Decode(allocator: Allocator, data: []const u8) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(data);
    const decoded = try allocator.alloc(u8, decoded_len);
    try decoder.decode(decoded, data);
    return decoded;
}

test "KMS client initialization" {
    const credentials = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .session_token = null,
    };

    const client = Client.init(.{ .region = "us-east-1", .credentials = credentials });

    try testing.expectEqualStrings("us-east-1", client.region());
    try testing.expectEqualStrings("AKIAIOSFODNN7EXAMPLE", client.credentials().access_key_id);
}

test "KMS KeySpec functionality" {
    try testing.expectEqualStrings("AES_256", KeySpec.AES_256.toString());
    try testing.expectEqualStrings("AES_128", KeySpec.AES_128.toString());
    try testing.expectEqual(@as(u32, 32), KeySpec.AES_256.keySize());
    try testing.expectEqual(@as(u32, 16), KeySpec.AES_128.keySize());
}

test "KMS base64 encoding/decoding" {
    const original = "Hello, World!";
    const encoded = try base64Encode(testing.allocator, original);
    defer testing.allocator.free(encoded);

    const decoded = try base64Decode(testing.allocator, encoded);
    defer testing.allocator.free(decoded);

    try testing.expectEqualStrings(original, decoded);
}

test "KMS URL building" {
    const credentials = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .session_token = null,
    };

    var client = Client.init(.{ .region = "eu-west-1", .credentials = credentials });

    const url = try client.buildKMSUrl(testing.allocator);
    defer testing.allocator.free(url);

    try testing.expectEqualStrings("https://kms.eu-west-1.amazonaws.com/", url);
}

test "KMS encrypt payload building" {
    const credentials = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .session_token = null,
    };

    var client = Client.init(.{ .region = "us-east-1", .credentials = credentials });

    const key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012";
    const plaintext = "SGVsbG8gV29ybGQ="; // "Hello World" base64 encoded

    const payload = try client.buildEncryptPayload(testing.allocator, key_id, plaintext, null);
    defer testing.allocator.free(payload);

    // Should contain both KeyId and Plaintext
    try testing.expect(std.mem.indexOf(u8, payload, "KeyId") != null);
    try testing.expect(std.mem.indexOf(u8, payload, "Plaintext") != null);
    try testing.expect(std.mem.indexOf(u8, payload, key_id) != null);
    try testing.expect(std.mem.indexOf(u8, payload, plaintext) != null);
}

test "KMS encrypt payload with encryption context" {
    const credentials = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .session_token = null,
    };

    var client = Client.init(.{ .region = "us-east-1", .credentials = credentials });

    var encryption_context = EncryptionContext.init(testing.allocator);
    defer encryption_context.deinit();
    try encryption_context.put("environment", "production");
    try encryption_context.put("service", "web-app");

    const key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012";
    const plaintext = "SGVsbG8gV29ybGQ=";

    const payload = try client.buildEncryptPayload(testing.allocator, key_id, plaintext, encryption_context);
    defer testing.allocator.free(payload);

    // Should contain encryption context
    try testing.expect(std.mem.indexOf(u8, payload, "EncryptionContext") != null);
    try testing.expect(std.mem.indexOf(u8, payload, "environment") != null);
    try testing.expect(std.mem.indexOf(u8, payload, "production") != null);
    try testing.expect(std.mem.indexOf(u8, payload, "service") != null);
    try testing.expect(std.mem.indexOf(u8, payload, "web-app") != null);
}

test "KMS decrypt payload building" {
    const credentials = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .session_token = null,
    };

    const key_id = "test-key-id";

    var client = Client.init(.{ .region = "us-east-1", .credentials = credentials });

    const ciphertext = "AQICAHhQzGXYzLJ9bJhJd..."; // Mock ciphertext blob

    const payload = try client.buildDecryptPayload(testing.allocator, key_id, ciphertext, null);
    defer testing.allocator.free(payload);

    try testing.expect(std.mem.indexOf(u8, payload, "CiphertextBlob") != null);
    try testing.expect(std.mem.indexOf(u8, payload, ciphertext) != null);
}

test "KMS encrypt validation" {
    const credentials = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .session_token = null,
    };

    var client = Client.init(.{ .region = "us-east-1", .credentials = credentials });

    // Test empty key ID
    try testing.expectError(KmsError.InvalidKeyId, client.encrypt(testing.allocator, "", "test", .{}));

    // Test empty plaintext
    try testing.expectError(KmsError.InvalidPlaintext, client.encrypt(testing.allocator, "key-id", "", .{}));

    // Test plaintext too large (> 4KB)
    const large_plaintext = try testing.allocator.alloc(u8, 5000);
    defer testing.allocator.free(large_plaintext);
    @memset(large_plaintext, 'A');

    try testing.expectError(KmsError.InvalidPlaintext, client.encrypt(testing.allocator, "key-id", large_plaintext, .{}));
}

test "KMS decrypt validation" {
    const credentials = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .session_token = null,
    };

    var client = Client.init(.{ .region = "us-east-1", .credentials = credentials });

    const key_id = "test-key-id";

    // Test empty ciphertext
    try testing.expectError(KmsError.InvalidCiphertext, client.decrypt(testing.allocator, key_id, "", .{}));
}

test "KMS response parsing" {
    const credentials = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .session_token = null,
    };

    var client = Client.init(.{ .region = "us-east-1", .credentials = credentials });

    // Test encrypt response parsing
    const encrypt_response =
        \\{
        \\  "CiphertextBlob": "SGVsbG8gV29ybGQ=",
        \\  "KeyId": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        \\}
    ;

    var encrypt_result = try client.parseEncryptResponse(testing.allocator, encrypt_response, .{
        .base64_decode = true,
    });
    defer encrypt_result.deinit(testing.allocator);

    try testing.expectEqualStrings("Hello World", encrypt_result.ciphertext);
    try testing.expectEqualStrings("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", encrypt_result.key_id);

    // Test decrypt response parsing
    const decrypt_response =
        \\{
        \\  "Plaintext": "SGVsbG8gV29ybGQ=",
        \\  "KeyId": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        \\}
    ;

    var decrypt_result = try client.parseDecryptResponse(testing.allocator, decrypt_response);
    defer decrypt_result.deinit(testing.allocator);

    try testing.expectEqualStrings("Hello World", decrypt_result.plaintext);
    try testing.expectEqualStrings("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", decrypt_result.key_id);
}

test "kms encrypt localstack" {
    var arena: ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const kms_key_id = std.testing.environ.getAlloc(allocator, "AWS_KMS_KEY_ID") catch return error.SkipZigTest;
    const plaintext = "hello, world!";

    const aws_config = AwsConfig.fromEnvironment(allocator) catch return error.SkipZigTest;

    {
        const aws_client: AwsClient = .init(aws_config);
        const kms_client = aws_client.kms();
        const encrypt_result = try kms_client.encrypt(allocator, kms_key_id, plaintext, .{});

        // one second in nanoseconds
        _ = std.posix.system.nanosleep(&.{ .sec = 1, .nsec = 0 }, null);

        const decrypt_result = try kms_client.decrypt(allocator, kms_key_id, encrypt_result.ciphertext, .{});

        try testing.expectEqualSlices(u8, plaintext, decrypt_result.plaintext);
    }
}

const AwsClient = @import("client.zig").Client;
const AwsConfig = @import("client.zig").Config;
const Credentials = @import("Credentials.zig");

const http = @import("http.zig");
const Response = http.Response;

const sigv4 = @import("sigv4.zig");

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const StringHashMap = std.StringHashMapUnmanaged;

const testing = std.testing;
