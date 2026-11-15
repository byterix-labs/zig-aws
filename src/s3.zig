//! AWS S3 client implementation
//!
//! Provides core S3 operations: PutObject, GetObject, DeleteObject, ListBuckets
//! Following Zig idioms with explicit error handling and memory management.

const logger = std.log.scoped(.aws_s3);
const service = "s3";

fn logError(comptime fmt: []const u8, args: anytype) void {
    if (!@import("builtin").is_test) {
        logger.err(fmt, args);
    } else {
        logger.warn(fmt, args);
    }
}

/// S3 service name for SigV4 signing
/// S3 client errors
pub const S3Error = error{
    BucketNotFound,
    ObjectNotFound,
    AccessDenied,
    InvalidBucketName,
    InvalidObjectKey,
    QuotaExceeded,
    InternalError,
    InvalidResponse,
    XmlParseError,
} || std.mem.Allocator.Error || http.HttpError || sigv4.SigV4Error;

/// S3 Object metadata
pub const ObjectMetadata = struct {
    key: []const u8,
    size: u64,
    last_modified: []const u8,
    etag: []const u8,
    storage_class: []const u8,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.free(self.key);
        allocator.free(self.last_modified);
        allocator.free(self.etag);
        allocator.free(self.storage_class);
    }
};

/// S3 Bucket information
pub const Bucket = struct {
    name: []const u8,
    creation_date: []const u8,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.creation_date);
    }
};

/// List objects options
pub const ListObjectsOptions = Client.ListObjectsOptions;

/// List objects result
pub const ListObjectsResult = struct {
    objects: []ObjectMetadata,
    is_truncated: bool,
    next_continuation_token: ?[]const u8,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: Allocator) void {
        for (self.objects) |*obj| {
            obj.deinit(allocator);
        }
        allocator.free(self.objects);
        if (self.next_continuation_token) |token| {
            allocator.free(token);
        }
    }
};

/// Put object options
pub const PutObjectOptions = struct {
    bucket: []const u8,
    key: []const u8,
    data: []const u8,
    content_type: ?[]const u8 = null,
    cache_control: ?[]const u8 = null,
    content_encoding: ?[]const u8 = null,
    metadata: ?std.StringHashMap([]const u8) = null,
    throw_on_response_error: bool = false,
    checksum_sha256: ?[]const u8 = null,
};

/// Get object result
pub const GetObjectResult = struct {
    data: []const u8,
    content_type: ?[]const u8,
    content_length: u64,
    last_modified: ?[]const u8,
    etag: ?[]const u8,
    response: http.Response,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.response.deinit(allocator);
    }

    pub fn getDataOwned(self: Self, allocator: Allocator) ![]const u8 {
        return allocator.dupe(u8, self.data);
    }
};

pub const HeadObjectResult = struct {
    content_type: ?[]const u8,
    content_length: u64,
    last_modified: ?[]const u8,
    etag: ?[]const u8,
    response: http.Response,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.response.deinit(allocator);
    }
};

/// S3 Client
pub const Client = struct {
    config: AwsConfig,
    request_signer: RequestSigner,

    const Self = @This();

    /// Initialize S3 client
    pub fn init(config: AwsConfig) Self {
        return Self{
            .config = config,
            .request_signer = .init(.{
                .service = "s3",
                .region = config.region,
                .credentials = config.credentials,
                .endpoint_url = config.endpoint_url,
            }),
        };
    }

    pub fn region(self: Self) []const u8 {
        return self.request_signer.options.region;
    }

    pub fn credentials(self: Self) Credentials {
        return self.request_signer.options.credentials;
    }

    pub fn endpointUrl(self: Self) ?[]const u8 {
        return self.request_signer.options.endpoint_url;
    }

    pub fn awsClient(self: Self) AwsClient {
        return AwsClient.init(self.config);
    }

    /// Put an object to S3
    pub fn putObject(
        self: Self,
        allocator: Allocator,
        options: PutObjectOptions,
    ) !http.Response {
        if (!isValidBucketName(options.bucket)) {
            logError("Invalid bucket name: {s}", .{options.bucket});
            return S3Error.InvalidBucketName;
        }
        if (!isValidObjectKey(options.key)) {
            logError("Invalid object key: {s}", .{options.key});
            return S3Error.InvalidObjectKey;
        }

        var arena = ArenaAllocator.init(allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const url = try self.buildUrl(alloc, .{
            .object = .{
                .bucket = options.bucket,
                .key = options.key,
            },
        });

        var headers = StringHashMap([]const u8).empty;

        // Set content type
        if (options.content_type) |ct| {
            try headers.put(alloc, "Content-Type", try alloc.dupe(u8, ct));
        } else {
            try headers.put(alloc, "Content-Type", try alloc.dupe(u8, "binary/octet-stream"));
        }

        // Add optional headers
        if (options.cache_control) |cc| {
            try headers.put(alloc, "Cache-Control", try alloc.dupe(u8, cc));
        }
        if (options.content_encoding) |ce| {
            try headers.put(alloc, "Content-Encoding", try alloc.dupe(u8, ce));
        }
        if (options.checksum_sha256) |cs| {
            try headers.put(alloc, "x-amz-checksum-sha256", try alloc.dupe(u8, cs));
        }

        // Add custom metadata
        if (options.metadata) |meta| {
            var iter = meta.iterator();
            while (iter.next()) |entry| {
                const meta_key = try std.fmt.allocPrint(alloc, "x-amz-meta-{s}", .{entry.key_ptr.*});
                try headers.put(alloc, meta_key, try alloc.dupe(u8, entry.value_ptr.*));
            }
        }

        // Make request
        const aws_client = self.awsClient();
        var response = try aws_client.request(allocator, .{
            .method = .PUT,
            .service = service,
            .endpoint = url,
            .headers = headers,
            .body = options.data,
        });

        if (options.throw_on_response_error and !response.ok()) {
            try self.handleS3Error(response);
        }

        return response;
    }

    pub const GetObjectOptions = struct {
        bucket: []const u8,
        key: []const u8,
        throw_on_response_error: bool = false,
    };

    /// Get an object from S3
    pub fn getObject(self: Self, allocator: Allocator, options: GetObjectOptions) !GetObjectResult {
        if (!isValidBucketName(options.bucket)) return S3Error.InvalidBucketName;
        if (!isValidObjectKey(options.key)) return S3Error.InvalidObjectKey;

        const url = try self.buildUrl(allocator, .{
            .object = .{
                .bucket = options.bucket,
                .key = options.key,
            },
        });
        defer allocator.free(url);

        var headers = StringHashMap([]const u8).empty;
        defer headers.deinit(allocator);

        var aws_client = self.awsClient();
        var response = try aws_client.request(allocator, .{
            .method = .GET,
            .service = service,
            .endpoint = url,
            .headers = headers,
        });

        if (options.throw_on_response_error and !response.ok()) {
            try self.handleS3Error(response);
        }

        // Extract metadata from response headers
        const content_type = if (response.headers.get("Content-Type")) |ct|
            ct
        else
            null;

        const last_modified = if (response.headers.get("Last-Modified")) |lm|
            lm
        else
            null;

        const etag = if (response.headers.get("ETag")) |et|
            et
        else
            null;

        const content_length = if (response.headers.get("Content-Length")) |cl|
            std.fmt.parseInt(u64, cl, 10) catch response.body.len
        else
            response.body.len;

        return GetObjectResult{
            .data = response.body,
            .content_type = content_type,
            .content_length = content_length,
            .last_modified = last_modified,
            .etag = etag,
            .response = response,
        };
    }

    pub const HeadObjectOptions = struct {
        bucket: []const u8,
        key: []const u8,
        throw_on_response_error: bool = false,
    };

    pub fn headObject(self: *Self, allocator: Allocator, options: HeadObjectOptions) !HeadObjectResult {
        if (!isValidBucketName(options.bucket)) return S3Error.InvalidBucketName;
        if (!isValidObjectKey(options.key)) return S3Error.InvalidObjectKey;

        logger.debug("HeadObjectOptions: bucket={s}, key={s}", .{ options.bucket, options.key });

        const url = try self.buildUrl(allocator, .{
            .object = .{
                .bucket = options.bucket,
                .key = options.key,
            },
        });
        errdefer allocator.free(url);

        var headers = StringHashMap([]const u8).empty;
        defer headers.deinit(allocator);

        logger.debug("Creating aws client", .{});

        var aws_client = self.awsClient();

        logger.debug("HEAD request to {s}", .{url});

        var response = try aws_client.request(allocator, .{
            .method = .HEAD,
            .service = service,
            .endpoint = url,
            .headers = headers,
        });
        errdefer response.deinit(allocator);

        logger.debug("HEAD response status: {}", .{response.status});

        if (options.throw_on_response_error and !response.ok()) {
            try self.handleS3Error(response);
        }

        errdefer comptime unreachable;
        defer allocator.free(url);

        // Extract metadata from response headers
        const content_type = if (response.headers.get("Content-Type")) |ct|
            ct
        else
            null;

        const last_modified = if (response.headers.get("Last-Modified")) |lm|
            lm
        else
            null;

        const etag = if (response.headers.get("ETag")) |et|
            et
        else
            null;

        const content_length = if (response.headers.get("Content-Length")) |cl|
            std.fmt.parseInt(u64, cl, 10) catch response.body.len
        else
            response.body.len;

        return HeadObjectResult{
            .content_type = content_type,
            .content_length = content_length,
            .last_modified = last_modified,
            .etag = etag,
            .response = response,
        };
    }

    pub const DeleteObjectOptions = struct {
        bucket: []const u8,
        key: []const u8,
        throw_on_response_error: bool = false,
    };

    /// Delete an object from S3
    pub fn deleteObject(self: *Self, allocator: Allocator, options: DeleteObjectOptions) !void {
        if (!isValidBucketName(options.bucket)) return S3Error.InvalidBucketName;
        if (!isValidObjectKey(options.key)) return S3Error.InvalidObjectKey;

        const url = try self.buildUrl(allocator, .{
            .object = .{
                .bucket = options.bucket,
                .key = options.key,
            },
        });
        defer allocator.free(url);

        logger.debug("Deleting object from S3: {s}", .{url});

        var headers = StringHashMap([]const u8).empty;
        defer headers.deinit(allocator);

        var aws_client = self.awsClient();
        var response = try aws_client.request(allocator, .{
            .method = .DELETE,
            .service = service,
            .endpoint = url,
            .headers = headers,
        });
        defer response.deinit(allocator);

        if (options.throw_on_response_error and !response.ok()) {
            try self.handleS3Error(response);
        }
    }

    pub const ListObjectsOptions = struct {
        bucket: []const u8,
        prefix: ?[]const u8 = null,
        max_keys: ?u32 = null,
        continuation_token: ?[]const u8 = null,
        delimiter: ?[]const u8 = null,
    };

    /// List objects in a bucket
    pub fn listObjects(
        self: Self,
        allocator: Allocator,
        options: Self.ListObjectsOptions,
    ) !ListObjectsResult {
        if (!isValidBucketName(options.bucket)) return S3Error.InvalidBucketName;

        var url = try self.buildUrl(allocator, .{
            .object = .{
                .bucket = options.bucket,
            },
        });
        defer allocator.free(url);

        // Build query parameters
        var query_params: std.ArrayList([]const u8) = .empty;
        defer {
            for (query_params.items) |param| {
                allocator.free(param);
            }
            query_params.deinit(allocator);
        }

        try query_params.append(allocator, try allocator.dupe(u8, "list-type=2"));

        if (options.prefix) |prefix| {
            const param = try std.fmt.allocPrint(allocator, "prefix={s}", .{prefix});
            try query_params.append(allocator, param);
        }

        if (options.max_keys) |max_keys| {
            const param = try std.fmt.allocPrint(allocator, "max-keys={d}", .{max_keys});
            try query_params.append(allocator, param);
        }

        if (options.continuation_token) |token| {
            const param = try std.fmt.allocPrint(allocator, "continuation-token={s}", .{token});
            try query_params.append(allocator, param);
        }

        if (options.delimiter) |delimiter| {
            const param = try std.fmt.allocPrint(allocator, "delimiter={s}", .{delimiter});
            try query_params.append(allocator, param);
        }

        // Append query string to URL
        if (query_params.items.len > 0) {
            const query_string = try std.mem.join(allocator, "&", query_params.items);
            defer allocator.free(query_string);

            const new_url = try std.fmt.allocPrint(allocator, "{s}?{s}", .{ url, query_string });
            allocator.free(url);
            url = new_url;
        }

        var headers = StringHashMap([]const u8).empty;
        defer headers.deinit(allocator);

        var aws_client = self.awsClient();
        var response = try aws_client.request(allocator, .{
            .method = .GET,
            .service = service,
            .endpoint = url,
            .headers = headers,
        });
        defer response.deinit(allocator);

        if (!response.ok()) {
            try self.handleS3Error(response);
        }

        // Parse XML response (simplified - real implementation would use proper XML parser)
        return parseListObjectsResponse(allocator, response.body);
    }

    const EndpointType = enum {
        list_buckets,
        bucket,
        object,
    };

    const Endpoint = union(EndpointType) {
        list_buckets: void,
        bucket: []const u8,
        object: struct {
            bucket: []const u8,
            key: ?[]const u8 = null,
        },
    };

    /// Build S3 URL for bucket and key
    fn buildUrl(self: Self, allocator: Allocator, endpoint: Endpoint) ![]u8 {
        switch (endpoint) {
            .list_buckets => {
                return std.fmt.allocPrint(allocator, "https://s3.{s}.amazonaws.com/", .{self.region()});
            },
            .bucket => |bucket| {
                if (self.config.endpoint_url) |endpoint_url| {
                    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ endpoint_url, bucket });
                }

                return std.fmt.allocPrint(allocator, "https://{s}.s3.{s}.amazonaws.com/", .{ bucket, self.region() });
            },
            .object => |object| {
                if (self.config.endpoint_url) |endpoint_url| {
                    return std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ endpoint_url, object.bucket, object.key orelse "" });
                }

                return std.fmt.allocPrint(allocator, "https://{s}.s3.{s}.amazonaws.com/{s}", .{ object.bucket, self.region(), object.key orelse "" });
            },
        }
    }

    /// Handle S3 error responses
    fn handleS3Error(self: Self, response: http.Response) S3Error!void {
        _ = self;

        return switch (response.status) {
            .not_found => S3Error.ObjectNotFound,
            .forbidden => S3Error.AccessDenied,
            .internal_server_error, .bad_gateway, .service_unavailable, .gateway_timeout => S3Error.InternalError,
            else => S3Error.InvalidResponse,
        };
    }
};

fn extractTagContent(xml_str: []const u8, tag: []const u8) ?[]const u8 {
    var open_tag_buf: [128]u8 = undefined;
    const open_tag = std.fmt.bufPrint(&open_tag_buf, "<{s}>", .{tag}) catch return null;
    var close_tag_buf: [128]u8 = undefined;
    const close_tag = std.fmt.bufPrint(&close_tag_buf, "</{s}>", .{tag}) catch return null;

    const start_pos = std.mem.indexOf(u8, xml_str, open_tag) orelse return null;
    const content_start = start_pos + open_tag.len;
    const end_pos = std.mem.indexOf(u8, xml_str[content_start..], close_tag) orelse return null;
    return xml_str[content_start .. content_start + end_pos];
}

fn parseListObjectsResponse(allocator: Allocator, buffer: []const u8) !ListObjectsResult {
    var objects: std.ArrayList(ObjectMetadata) = .empty;
    errdefer {
        for (objects.items) |*obj| obj.deinit(allocator);
        objects.deinit(allocator);
    }

    var is_truncated = false;
    if (extractTagContent(buffer, "IsTruncated")) |val| {
        const trimmed = std.mem.trim(u8, val, &std.ascii.whitespace);
        is_truncated = std.mem.eql(u8, trimmed, "true");
    }

    var next_continuation_token: ?[]const u8 = null;
    if (extractTagContent(buffer, "NextContinuationToken")) |val| {
        next_continuation_token = try allocator.dupe(u8, std.mem.trim(u8, val, &std.ascii.whitespace));
    }

    var search_slice = buffer;
    while (true) {
        const start_idx = std.mem.indexOf(u8, search_slice, "<Contents>") orelse break;
        const end_idx = std.mem.indexOf(u8, search_slice[start_idx..], "</Contents>") orelse break;
        const contents_chunk = search_slice[start_idx .. start_idx + end_idx];
        search_slice = search_slice[start_idx + end_idx + "</Contents>".len ..];

        const key = if (extractTagContent(contents_chunk, "Key")) |k| try allocator.dupe(u8, std.mem.trim(u8, k, &std.ascii.whitespace)) else try allocator.dupe(u8, "");
        const last_modified = if (extractTagContent(contents_chunk, "LastModified")) |lm| try allocator.dupe(u8, std.mem.trim(u8, lm, &std.ascii.whitespace)) else try allocator.dupe(u8, "");
        const etag = if (extractTagContent(contents_chunk, "ETag")) |et| try allocator.dupe(u8, std.mem.trim(u8, et, &std.ascii.whitespace)) else try allocator.dupe(u8, "");
        const storage_class = if (extractTagContent(contents_chunk, "StorageClass")) |sc| try allocator.dupe(u8, std.mem.trim(u8, sc, &std.ascii.whitespace)) else try allocator.dupe(u8, "");
        const size_str = if (extractTagContent(contents_chunk, "Size")) |s| std.mem.trim(u8, s, &std.ascii.whitespace) else "0";
        const size = std.fmt.parseInt(u64, size_str, 10) catch 0;

        try objects.append(allocator, ObjectMetadata{
            .key = key,
            .last_modified = last_modified,
            .etag = etag,
            .size = size,
            .storage_class = storage_class,
        });
    }

    return ListObjectsResult{
        .objects = try objects.toOwnedSlice(allocator),
        .is_truncated = is_truncated,
        .next_continuation_token = next_continuation_token,
    };
}

/// Validate S3 bucket name
fn isValidBucketName(name: []const u8) bool {
    if (name.len < 3 or name.len > 63) return false;
    if (name[0] == '.' or name[name.len - 1] == '.') return false;
    if (name[0] == '-' or name[name.len - 1] == '-') return false;

    for (name) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '-') {
            return false;
        }
    }

    return true;
}

/// Validate S3 object key
fn isValidObjectKey(key: []const u8) bool {
    if (key.len == 0 or key.len > 1024) return false;

    // Basic validation - real implementation would be more comprehensive
    for (key) |c| {
        if (c == 0) return false; // No null bytes
    }

    return true;
}

test "S3 bucket name validation" {
    const testing = std.testing;

    try testing.expect(isValidBucketName("my-bucket"));
    try testing.expect(isValidBucketName("bucket.with.dots"));
    try testing.expect(isValidBucketName("bucket123"));

    try testing.expect(!isValidBucketName("ab")); // Too short
    try testing.expect(!isValidBucketName(".bucket")); // Starts with dot
    try testing.expect(!isValidBucketName("bucket.")); // Ends with dot
    try testing.expect(!isValidBucketName("-bucket")); // Starts with dash
    try testing.expect(!isValidBucketName("bucket-")); // Ends with dash
    try testing.expect(!isValidBucketName("bucket_invalid")); // Contains underscore
}

test "S3 object key validation" {
    const testing = std.testing;

    try testing.expect(isValidObjectKey("my/object/key.txt"));
    try testing.expect(isValidObjectKey("simple-key"));
    try testing.expect(isValidObjectKey("key with spaces"));

    try testing.expect(!isValidObjectKey("")); // Empty key
    try testing.expect(!isValidObjectKey("key\x00with\x00nulls")); // Contains null bytes
}

test "S3 client initialization" {
    const testing = std.testing;

    const credentials = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    };

    const client = Client.init(.{
        .credentials = credentials,
        .region = "us-east-1",
    });

    try testing.expectEqualStrings("us-east-1", client.region());
    try testing.expectEqualStrings("AKIAIOSFODNN7EXAMPLE", client.credentials().access_key_id);
}

test "S3 URL building" {
    const testing = std.testing;

    const credentials = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    };

    var client = Client.init(.{
        .credentials = credentials,
        .region = "us-west-2",
    });

    // Test list buckets URL
    const list_url = try client.buildUrl(testing.allocator, .list_buckets);
    defer testing.allocator.free(list_url);
    try testing.expectEqualStrings("https://s3.us-west-2.amazonaws.com/", list_url);

    // Test bucket URL
    const bucket_url = try client.buildUrl(testing.allocator, .{ .bucket = "my-bucket" });
    defer testing.allocator.free(bucket_url);
    try testing.expectEqualStrings("https://my-bucket.s3.us-west-2.amazonaws.com/", bucket_url);

    // Test object URL
    const object_url = try client.buildUrl(testing.allocator, .{
        .object = .{
            .bucket = "my-bucket",
            .key = "path/to/object.txt",
        },
    });
    defer testing.allocator.free(object_url);
    try testing.expectEqualStrings("https://my-bucket.s3.us-west-2.amazonaws.com/path/to/object.txt", object_url);
}

test "S3 put object validation" {
    const testing = std.testing;

    const credentials = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    };

    var client = Client.init(.{
        .credentials = credentials,
        .region = "us-east-1",
    });

    const test_data = "Hello, S3!";

    // Test invalid bucket name
    try testing.expectError(S3Error.InvalidBucketName, client.putObject(testing.allocator, .{
        .bucket = "ab",
        .key = "key",
        .data = test_data,
    }));

    // Test invalid object key
    try testing.expectError(S3Error.InvalidObjectKey, client.putObject(testing.allocator, .{
        .bucket = "valid-bucket",
        .key = "",
        .data = test_data,
    }));
}

test "S3 get object validation" {
    const testing = std.testing;

    const credentials = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .session_token = null,
    };

    var client = Client.init(.{
        .credentials = credentials,
        .region = "us-east-1",
    });

    // Test invalid bucket name
    try testing.expectError(S3Error.InvalidBucketName, client.getObject(testing.allocator, .{
        .bucket = "ab",
        .key = "key",
    }));

    // Test invalid object key
    try testing.expectError(S3Error.InvalidObjectKey, client.getObject(testing.allocator, .{
        .bucket = "valid-bucket",
        .key = "",
    }));
}

test "S3 delete object validation" {
    const testing = std.testing;

    const credentials = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .session_token = null,
    };

    var client = Client.init(.{
        .credentials = credentials,
        .region = "us-east-1",
    });

    // Test invalid bucket name
    try testing.expectError(S3Error.InvalidBucketName, client.deleteObject(testing.allocator, .{
        .bucket = "ab",
        .key = "key",
    }));

    // Test invalid object key
    try testing.expectError(S3Error.InvalidObjectKey, client.deleteObject(testing.allocator, .{
        .bucket = "valid-bucket",
        .key = "",
    }));
}

test "S3 list objects options" {
    const testing = std.testing;

    const credentials = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .session_token = null,
    };

    var client = Client.init(.{
        .credentials = credentials,
        .region = "us-east-1",
    });

    var arena = ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Test invalid bucket name
    try testing.expectError(S3Error.InvalidBucketName, client.listObjects(allocator, .{
        .bucket = "ab",
    }));

    // Test with valid options
    const options = Client.ListObjectsOptions{
        .bucket = "valid-bucket",
        .prefix = "photos/",
        .max_keys = 100,
        .delimiter = "/",
    };
    _ = options; // autofix

    try testing.expectError(S3Error.InvalidBucketName, client.listObjects(allocator, .{
        .bucket = "ab",
        .prefix = "photos/",
        .max_keys = 100,
        .delimiter = "/",
    }));
}

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const client_lib = @import("client.zig");
const AwsClient = client_lib.Client;
const AwsConfig = client_lib.Config;
const Credentials = @import("Credentials.zig");
const RequestSigner = sigv4.RequestSigner;
const StringHashMap = std.StringHashMapUnmanaged;

const std = @import("std");
const http = @import("http.zig");
const sigv4 = @import("sigv4.zig");
