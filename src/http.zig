//! HTTP client wrapper for AWS requests
//!
//! Provides a simple interface for making HTTP requests with proper error handling
//! and timeout management suitable for AWS API calls.

/// HTTP Response
pub const Response = struct {
    status: std.http.Status,
    headers: StringHashMap([]const u8),
    body: []const u8,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: Allocator) void {
        var iterator = self.headers.iterator();
        while (iterator.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit(allocator);
        allocator.free(self.body);
    }

    /// Check if response indicates success (2xx status)
    pub fn ok(self: *const Self) bool {
        return self.status.class() == .success;
    }

    /// Check if response indicates client error (4xx status)
    pub fn isClientError(self: *const Self) bool {
        return self.status.class() == .client_error;
    }

    /// Check if response indicates server error (5xx status)
    pub fn isServerError(self: *const Self) bool {
        return self.status.class() == .server_error;
    }
};

/// HTTP Client configuration
pub const ClientConfig = struct {
    timeout_ms: u32 = 30000,
    max_redirects: u8 = 5,
    user_agent: []const u8 = "byterix-labs-obsidian/v0.1",
};

/// HTTP Client errors
pub const HttpError = error{
    InvalidUrl,
    ConnectionFailed,
    Timeout,
    TooManyRedirects,
    InvalidResponse,
} || std.mem.Allocator.Error;

/// HTTP Client
pub const Client = struct {
    config: ClientConfig,

    const Self = @This();

    pub const default = init(.{});

    pub fn init(config: ClientConfig) Self {
        return Self{
            .config = config,
        };
    }

    pub const RequestOptions = struct {
        method: HttpMethod,
        uri: std.Uri,
        headers: ArrayList(Header),
        body: ?[]const u8,
    };

    /// Make an HTTP request
    pub fn request(
        self: Self,
        allocator: Allocator,
        options: RequestOptions,
    ) !Response {
        // Prepare headers
        var header_list = try options.headers.clone(allocator);
        defer header_list.deinit(allocator);

        // Add User-Agent
        try header_list.append(allocator, .{
            .name = "User-Agent",
            .value = self.config.user_agent,
        });

        // Make the request
        var http_client: HttpClient = .{
            .allocator = allocator,
            .io = std.testing.io,
        };
        defer http_client.deinit();

        var req = http_client.request(
            options.method,
            options.uri,
            .{
                .headers = .{
                    .user_agent = .omit,
                    .content_type = .omit,
                    .host = .omit,
                },
                .extra_headers = header_list.items,
            },
        ) catch return HttpError.ConnectionFailed;
        defer req.deinit();

        // Send body if present
        if (options.body) |b| {
            req.transfer_encoding = .{ .content_length = b.len };
            var body_writer = req.sendBodyUnflushed(&.{}) catch return HttpError.ConnectionFailed;
            body_writer.writer.writeAll(b) catch return HttpError.ConnectionFailed;
            body_writer.end() catch return HttpError.ConnectionFailed;
            if (req.connection) |conn| {
                conn.flush() catch return HttpError.ConnectionFailed;
            }
        } else {
            req.sendBodiless() catch return HttpError.ConnectionFailed;
        }

        const redirect_buffer = allocator.alloc(u8, 8 * 1024) catch return HttpError.InvalidResponse;
        defer allocator.free(redirect_buffer);

        var response = req.receiveHead(redirect_buffer) catch return HttpError.InvalidResponse;

        var transfer_buffer: [4096]u8 = undefined;
        var decompress: std.http.Decompress = undefined;
        var decompress_buffer: [std.compress.flate.max_window_len]u8 = undefined;
        var reader = response.readerDecompressing(&transfer_buffer, &decompress, &decompress_buffer);

        var allocating: std.Io.Writer.Allocating = .init(allocator);
        defer allocating.deinit();
        _ = reader.streamRemaining(&allocating.writer) catch |err| switch (err) {
            error.ReadFailed => return HttpError.InvalidResponse,
            else => return HttpError.InvalidResponse,
        };
        const response_body = try allocator.dupe(u8, allocating.writer.buffered());

        // Build response headers map
        var response_headers = StringHashMap([]const u8).empty;
        var header_iter = response.head.iterateHeaders();
        while (header_iter.next()) |header| {
            const name = try allocator.dupe(u8, header.name);
            const value = try allocator.dupe(u8, header.value);
            try response_headers.put(allocator, name, value);
        }

        return Response{
            .status = response.head.status,
            .headers = response_headers,
            .body = response_body,
        };
    }

    /// Make a GET request
    pub fn get(self: Self, allocator: Allocator, url: []const u8, headers: ArrayList(Header)) !Response {
        return self.request(allocator, .GET, url, headers, null);
    }

    /// Make a POST request
    pub fn post(self: Self, allocator: Allocator, url: []const u8, headers: ArrayList(Header), body: ?[]const u8) !Response {
        return self.request(allocator, .POST, url, headers, body);
    }

    /// Make a PUT request
    pub fn put(self: Self, allocator: Allocator, url: []const u8, headers: ArrayList(Header), body: ?[]const u8) !Response {
        return self.request(allocator, .PUT, url, headers, body);
    }

    /// Make a DELETE request
    pub fn delete(self: Self, allocator: Allocator, url: []const u8, headers: ArrayList(Header)) !Response {
        return self.request(allocator, .DELETE, url, headers, null);
    }

    /// Make a HEAD request
    pub fn head(self: Self, allocator: Allocator, url: []const u8, headers: ArrayList(Header)) !Response {
        return self.request(allocator, .HEAD, url, headers, null);
    }
};

test "HTTP response status checking" {
    const testing = std.testing;

    var headers = StringHashMap([]const u8).empty;
    defer headers.deinit(testing.allocator);

    var response_200 = Response{
        .status = .ok,
        .headers = headers,
        .body = try testing.allocator.dupe(u8, "OK"),
    };
    defer response_200.deinit(testing.allocator);

    try testing.expect(response_200.ok());
    try testing.expect(!response_200.isClientError());
    try testing.expect(!response_200.isServerError());

    var headers_404 = StringHashMap([]const u8).empty;
    defer headers_404.deinit(testing.allocator);

    var response_404 = Response{
        .status = .not_found,
        .headers = headers_404,
        .body = try testing.allocator.dupe(u8, "Not Found"),
    };
    defer response_404.deinit(testing.allocator);

    try testing.expect(!response_404.ok());
    try testing.expect(response_404.isClientError());
    try testing.expect(!response_404.isServerError());

    var headers_500 = StringHashMap([]const u8).empty;
    defer headers_500.deinit(testing.allocator);

    var response_500 = Response{
        .status = .internal_server_error,
        .headers = headers_500,
        .body = try testing.allocator.dupe(u8, "Internal Server Error"),
    };
    defer response_500.deinit(testing.allocator);

    try testing.expect(!response_500.ok());
    try testing.expect(!response_500.isClientError());
    try testing.expect(response_500.isServerError());
}

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayListUnmanaged;
const Header = std.http.Header;
const HttpClient = std.http.Client;
const HttpMethod = std.http.Method;
const StringHashMap = std.StringHashMapUnmanaged;

const std = @import("std");
