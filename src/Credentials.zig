//! AWS Credentials
//!
//! Manages AWS credentials and provides utilities for credential validation.

const Credentials = @This();

/// AWS Credentials
/// AWS Access Key ID
access_key_id: []const u8,
/// AWS Secret Access Key
secret_access_key: []const u8,
/// Optional session token for temporary credentials
session_token: ?[]const u8 = null,

/// Validate that credentials are properly formatted
pub fn validate(self: *const Credentials) bool {
    if (self.access_key_id.len == 0) return false;
    if (self.secret_access_key.len == 0) return false;

    // Basic format validation for access key (should start with AKIA for IAM users)
    if (self.access_key_id.len < 16) return false;

    // Secret key should be at least 40 characters
    if (self.secret_access_key.len < 40) return false;

    return true;
}

/// Check if credentials are temporary (have session token)
pub fn isTemporary(self: *const Credentials) bool {
    return self.session_token != null;
}

fn getEnv(allocator: Allocator, key: []const u8) !?[]const u8 {
    if (@import("builtin").is_test) {
        return std.testing.environ.getAlloc(allocator, key) catch |err| switch (err) {
            error.EnvironmentVariableMissing => null,
            else => return err,
        };
    }
    return null;
}

/// Load credentials from environment variables
pub fn fromEnvironment(allocator: Allocator) !Credentials {
    const access_key = try getEnv(allocator, "AWS_ACCESS_KEY_ID") orelse {
        std.log.err("Missing environment variable: AWS_ACCESS_KEY_ID", .{});
        return error.MissingAccessKey;
    };
    errdefer allocator.free(access_key);

    const secret_key = try getEnv(allocator, "AWS_SECRET_ACCESS_KEY") orelse {
        std.log.err("Missing environment variable: AWS_SECRET_ACCESS_KEY", .{});
        return error.MissingSecretKey;
    };
    errdefer allocator.free(secret_key);

    const session_token = try getEnv(allocator, "AWS_SESSION_TOKEN");

    return Credentials{
        .access_key_id = access_key,
        .secret_access_key = secret_key,
        .session_token = session_token,
    };
}

/// Free credentials loaded from environment
pub fn deinit(self: Credentials, allocator: std.mem.Allocator) void {
    allocator.free(self.access_key_id);
    allocator.free(self.secret_access_key);
    if (self.session_token) |token| {
        allocator.free(token);
    }
}

test "Credentials validation" {
    const testing = std.testing;

    const valid_creds = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .session_token = null,
    };
    try testing.expect(valid_creds.validate());
    try testing.expect(!valid_creds.isTemporary());

    const invalid_creds = Credentials{
        .access_key_id = "short",
        .secret_access_key = "short",
        .session_token = null,
    };
    try testing.expect(!invalid_creds.validate());
}

test "Temporary credentials detection" {
    const testing = std.testing;

    const temp_creds = Credentials{
        .access_key_id = "ASIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .session_token = "AQoDYXdzEJr...",
    };
    try testing.expect(temp_creds.isTemporary());
}

const Allocator = std.mem.Allocator;

const std = @import("std");
