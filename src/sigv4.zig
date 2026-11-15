//! AWS Signature Version 4 (SigV4) implementation
//!
//! This module implements the complete AWS SigV4 signing process as specified
//! in the AWS documentation. It handles canonical request creation, string to sign
//! generation, and signature calculation.

const logger = std.log.scoped(.aws_sigv4);

/// AWS SigV4 algorithm identifier
const aws4_hmac_sha256 = "AWS4-HMAC-SHA256";

/// AWS SigV4 request terminator
const aws4_request = "aws4_request";

/// SigV4 signing errors
pub const SigV4Error = error{
    InvalidTimestamp,
    SigningFailed,
    UriParseError,
} || Allocator.Error || std.fmt.ParseIntError;

/// Optional parameters for SigV4 signing
pub const SignRequestOptions = struct {
    credentials: Credentials,
    region: []const u8,
    service: []const u8,
    method: HttpMethod,
    uri: []const u8,
    headers: StringHashMap([]const u8) = .empty,
    payload: ?[]const u8 = null,
    endpoint_url: ?[]const u8 = null,
    timestamp: ?i64 = null,
    include_content_hash: bool = false,
};

pub const SignRequestResult = struct {
    arena: ArenaAllocator,
    signature: []const u8,
    headers: ArrayList(Header) = .empty,
    endpoint: Uri,

    pub fn appendHeader(self: *SignRequestResult, key: []const u8, value: []const u8) !void {
        const allocator = self.arena.allocator();

        const header = Header{
            .name = try allocator.dupe(u8, key),
            .value = try allocator.dupe(u8, value),
        };

        try self.headers.append(allocator, header);
    }

    pub fn deinit(self: *SignRequestResult) void {
        self.arena.child_allocator.free(self.signature);
        self.arena.deinit();
    }
};

fn validateHeaders(headers: StringHashMap([]const u8)) !void {
    var header_key_it = headers.keyIterator();
    while (header_key_it.next()) |h| {
        inline for (forbidden_headers) |kvp| {
            if (std.ascii.eqlIgnoreCase(h.*, kvp.@"0")) {
                return kvp.@"1";
            }
        }
    }
}

const SignedRequestComponents = struct {
    arena: ArenaAllocator,
    method: HttpMethod,
    uri: std.Uri,
    headers: StringHashMap([]const u8),
    body: ?[]const u8,
    date_time: []const u8,
    date: []const u8,
    payload_hash: []const u8,

    pub fn deinit(self: SignedRequestComponents) void {
        self.arena.deinit();
    }
};

fn getTimestamp() i64 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(std.posix.system.CLOCK.REALTIME, &ts);
    return ts.sec;
}

fn cloneComponent(allocator: Allocator, comp: ?Uri.Component) !?Uri.Component {
    const c = comp orelse return null;
    return switch (c) {
        .raw => |s| .{ .raw = try allocator.dupe(u8, s) },
        .percent_encoded => |s| .{ .percent_encoded = try allocator.dupe(u8, s) },
    };
}

fn cloneUri(allocator: Allocator, uri: Uri) !Uri {
    return Uri{
        .scheme = try allocator.dupe(u8, uri.scheme),
        .user = try cloneComponent(allocator, uri.user),
        .password = try cloneComponent(allocator, uri.password),
        .host = try cloneComponent(allocator, uri.host),
        .port = uri.port,
        .path = (try cloneComponent(allocator, uri.path)).?,
        .query = try cloneComponent(allocator, uri.query),
        .fragment = try cloneComponent(allocator, uri.fragment),
    };
}

fn collectRequiredComponents(allocator: Allocator, options: SignRequestOptions) !SignedRequestComponents {
    // SAFETY: All fields will be set before returning
    var result: SignedRequestComponents = undefined;

    result.arena = ArenaAllocator.init(allocator);
    const alloc = result.arena.allocator();

    logger.debug("collectRequiredComponents: parsing uri {s}", .{options.uri});
    var parsed_uri = try Uri.parse(try alloc.dupe(u8, options.uri));

    logger.debug("collectRequiredComponents: parsing endpoint url", .{});
    if (options.endpoint_url) |url| {
        const parsed_endpoint = try std.Uri.parse(try alloc.dupe(u8, url));
        parsed_uri.scheme = parsed_endpoint.scheme;
        parsed_uri.host = parsed_endpoint.host;
        parsed_uri.port = parsed_endpoint.port;
    }

    logger.debug("collectRequiredComponents: formatting date", .{});
    const date_time = try formatDateTime(alloc, options.timestamp orelse getTimestamp());
    const date = date_time[0..8];

    logger.debug("collectRequiredComponents: collecting headers", .{});
    var headers = try options.headers.clone(alloc);
    try headers.putNoClobber(alloc, "Host", try extractHost(alloc, parsed_uri));
    try headers.putNoClobber(alloc, "X-Amz-Date", date_time);

    if (options.credentials.session_token) |token| {
        try headers.putNoClobber(alloc, "X-Amz-Security-Token", token);
    }

    logger.debug("collectRequiredComponents: calculating payload hash", .{});
    const payload_hash = try calculatePayloadHash(alloc, options.payload);

    if (options.include_content_hash) {
        try headers.putNoClobber(alloc, "X-Amz-Content-Sha256", payload_hash);
    }

    result.method = options.method;
    result.uri = parsed_uri;
    result.headers = headers;
    result.body = options.payload;
    result.date_time = date_time;
    result.date = date;
    result.payload_hash = payload_hash;

    return result;
}

/// Sign an AWS request using SigV4
pub fn signRequest(
    allocator: Allocator,
    options: SignRequestOptions,
) !SignRequestResult {
    logger.debug("signRequest: validating headers", .{});
    try validateHeaders(options.headers);

    logger.debug("signRequest: collecting required components", .{});
    const components = try collectRequiredComponents(allocator, options);
    defer components.deinit();

    logger.debug("signRequest: creating canonical request", .{});
    const canonical_request = try createCanonicalRequest(allocator, components);
    defer allocator.free(canonical_request);

    // Create string to sign
    logger.debug("signRequest: creating string to sign", .{});
    const credential_scope = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}/{s}/{s}",
        .{ components.date, options.region, options.service, aws4_request },
    );
    defer allocator.free(credential_scope);

    const string_to_sign = try createStringToSign(
        allocator,
        components.date_time,
        credential_scope,
        canonical_request,
    );
    defer allocator.free(string_to_sign);

    // Calculate signature
    logger.debug("signRequest: calculating signature", .{});
    const signature = try calculateSignature(
        allocator,
        options.credentials.secret_access_key,
        components.date,
        options.region,
        options.service,
        string_to_sign,
    );

    // Create authorization header
    logger.debug("signRequest: creating authorization header", .{});
    const signed_headers = try getSignedHeaders(allocator, components.headers);
    defer allocator.free(signed_headers);

    const authorization = try std.fmt.allocPrint(
        allocator,
        "{s} Credential={s}/{s}, SignedHeaders={s}, Signature={s}",
        .{ aws4_hmac_sha256, options.credentials.access_key_id, credential_scope, signed_headers, signature },
    );
    defer allocator.free(authorization);

    logger.debug("signRequest: creating result", .{});
    var result: SignRequestResult = .{
        .arena = ArenaAllocator.init(allocator),
        .signature = signature,
        // SAFETY: Endpoint is assigned below using the result's arena
        .endpoint = undefined,
    };
    result.endpoint = try cloneUri(result.arena.allocator(), components.uri);

    logger.debug("signRequest: appending headers", .{});
    var it = components.headers.iterator();
    while (it.next()) |header| {
        try result.appendHeader(header.key_ptr.*, header.value_ptr.*);
    }
    try result.appendHeader("Authorization", authorization);

    return result;
}

/// Create canonical request string
fn createCanonicalRequest(
    allocator: Allocator,
    components: SignedRequestComponents,
) ![]const u8 {
    // Extract path and query from URI
    const path = switch (components.uri.path) {
        .raw => |s| s,
        .percent_encoded => |s| s,
    };

    const canonical_uri = canonicalizeUri(path);

    const query_str = if (components.uri.query) |q| switch (q) {
        .raw => |s| s,
        .percent_encoded => |s| s,
    } else "";

    const canonical_query = try canonicalizeQuery(allocator, query_str);
    defer allocator.free(canonical_query);

    const canonical_headers = try canonicalizeHeaders(allocator, components.headers);
    defer allocator.free(canonical_headers);

    const signed_headers = try getSignedHeaders(allocator, components.headers);
    defer allocator.free(signed_headers);

    return std.fmt.allocPrint(
        allocator,
        \\{s}
        \\{s}
        \\{s}
        \\{s}
        \\{s}
        \\{s}
    ,
        .{
            @tagName(components.method),
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            components.payload_hash,
        },
    );
}

/// Create string to sign
fn createStringToSign(
    allocator: Allocator,
    date_time: []const u8,
    credential_scope: []const u8,
    canonical_request: []const u8,
) ![]u8 {
    const canonical_request_hash = try sha256Hash(allocator, canonical_request);
    defer allocator.free(canonical_request_hash);

    return std.fmt.allocPrint(
        allocator,
        "{s}\n{s}\n{s}\n{s}",
        .{ aws4_hmac_sha256, date_time, credential_scope, canonical_request_hash },
    );
}

/// Calculate the final signature
fn calculateSignature(
    allocator: Allocator,
    secret_key: []const u8,
    date: []const u8,
    region: []const u8,
    service: []const u8,
    string_to_sign: []const u8,
) ![]const u8 {
    const k_secret = try std.fmt.allocPrint(allocator, "AWS4{s}", .{secret_key});
    defer allocator.free(k_secret);

    const k_date = try hmacSha256Bytes(allocator, k_secret, date);
    defer allocator.free(k_date);

    const k_region = try hmacSha256Bytes(allocator, k_date, region);
    defer allocator.free(k_region);

    const k_service = try hmacSha256Bytes(allocator, k_region, service);
    defer allocator.free(k_service);

    const k_signing = try hmacSha256Bytes(allocator, k_service, aws4_request);
    defer allocator.free(k_signing);

    // Calculate final signature
    const signature_bytes = try hmacSha256Bytes(allocator, k_signing, string_to_sign);
    defer allocator.free(signature_bytes);

    return hexEncode(allocator, signature_bytes);
}

/// Calculate payload hash (SHA256 of body or empty string hash)
fn calculatePayloadHash(allocator: Allocator, payload: ?[]const u8) ![]u8 {
    return sha256Hash(allocator, payload orelse "");
}

/// Canonicalize headers
fn canonicalizeHeaders(allocator: Allocator, headers: StringHashMap([]const u8)) ![]const u8 {
    var list: ArrayList([]const u8) = .empty;
    defer {
        for (list.items) |item| {
            allocator.free(item);
        }
        list.deinit(allocator);
    }

    var iterator = headers.iterator();
    while (iterator.next()) |entry| {
        const lower_name = try toLowercase(allocator, entry.key_ptr.*);
        defer allocator.free(lower_name);

        const header = try std.fmt.allocPrint(
            allocator,
            "{s}:{s}\n",
            .{ lower_name, std.mem.trim(u8, entry.value_ptr.*, &std.ascii.whitespace) },
        );
        try list.append(allocator, header);
    }

    // Sort headers lexicographically
    std.mem.sort([]const u8, list.items, {}, struct {
        fn lessThan(context: void, lhs: []const u8, rhs: []const u8) bool {
            _ = context;
            return std.mem.lessThan(u8, lhs, rhs);
        }
    }.lessThan);

    return std.mem.join(allocator, "", list.items);
}

pub const SigningError = error{
    NotImplemented,
    S3NotImplemented,

    // There are a number of forbidden headers that the signing process
    // basically "owns". For clarity, and because zig does not have a way
    // to provide an error message
    //
    /// Used if the request headers already includes X-Amz-Date
    /// If a specific date is required, use a specific signing_time in config
    XAmzDateHeaderInRequest,
    /// Used if the request headers already includes Authorization
    AuthorizationHeaderInRequest,
    /// Used if the request headers already includes x-amz-content-sha256
    XAmzContentSha256HeaderInRequest,
    /// Used if the request headers already includes x-amz-signature
    XAmzSignatureHeaderInRequest,
    /// Used if the request headers already includes x-amz-algorithm
    XAmzAlgorithmHeaderInRequest,
    /// Used if the request headers already includes x-amz-credential
    XAmzCredentialHeaderInRequest,
    /// Used if the request headers already includes x-amz-signedheaders
    XAmzSignedHeadersHeaderInRequest,
    /// Used if the request headers already includes x-amz-security-token
    XAmzSecurityTokenHeaderInRequest,
    /// Used if the request headers already includes x-amz-expires
    XAmzExpiresHeaderInRequest,
    /// Used if the request headers already includes x-amz-region-set
    XAmzRegionSetHeaderInRequest,
    /// Used if the request headers already includes host
    HostHeaderInRequest,
};

const forbidden_headers = .{
    .{ "x-amz-content-sha256", SigningError.XAmzContentSha256HeaderInRequest },
    .{ "Authorization", SigningError.AuthorizationHeaderInRequest },
    .{ "X-Amz-Signature", SigningError.XAmzSignatureHeaderInRequest },
    .{ "X-Amz-Algorithm", SigningError.XAmzAlgorithmHeaderInRequest },
    .{ "X-Amz-Credential", SigningError.XAmzCredentialHeaderInRequest },
    .{ "X-Amz-Date", SigningError.XAmzDateHeaderInRequest },
    .{ "X-Amz-SignedHeaders", SigningError.XAmzSignedHeadersHeaderInRequest },
    .{ "X-Amz-Security-Token", SigningError.XAmzSecurityTokenHeaderInRequest },
    .{ "X-Amz-Expires", SigningError.XAmzExpiresHeaderInRequest },
    .{ "X-Amz-Region-Set", SigningError.XAmzRegionSetHeaderInRequest },
    .{ "host", SigningError.HostHeaderInRequest },
};

/// Get signed headers list
fn getSignedHeaders(allocator: Allocator, headers: StringHashMap([]const u8)) ![]const u8 {
    var list = ArrayList([]const u8).empty;
    defer {
        for (list.items) |item| {
            allocator.free(item);
        }
        list.deinit(allocator);
    }

    var buf: [4096]u8 = undefined;
    var iterator = headers.iterator();
    while (iterator.next()) |entry| {
        const header_name = std.mem.trim(
            u8,
            std.ascii.lowerString(&buf, entry.key_ptr.*),
            &std.ascii.whitespace,
        );
        try list.append(allocator, try allocator.dupe(u8, header_name));
    }

    // Sort headers lexicographically
    std.mem.sort([]const u8, list.items, {}, struct {
        fn lessThan(context: void, lhs: []const u8, rhs: []const u8) bool {
            _ = context;
            return std.mem.lessThan(u8, lhs, rhs);
        }
    }.lessThan);

    return std.mem.join(allocator, ";", list.items);
}

/// Extract host from URI
fn extractHost(allocator: Allocator, uri: Uri) ![]u8 {
    const host = uri.host.?.percent_encoded;

    if (uri.port) |port| {
        return std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port });
    }

    return allocator.dupe(u8, host);
}

/// Extract path and query from URI
fn extractPathAndQuery(uri: []const u8) struct { path: []const u8, query: []const u8 } {
    // Skip scheme if present
    var path_start: usize = 0;
    if (std.mem.startsWith(u8, uri, "https://")) {
        path_start = 8;
        if (std.mem.indexOf(u8, uri[path_start..], "/")) |slash_pos| {
            path_start += slash_pos;
        } else {
            return .{ .path = "/", .query = "" };
        }
    } else if (std.mem.startsWith(u8, uri, "http://")) {
        path_start = 7;
        if (std.mem.indexOf(u8, uri[path_start..], "/")) |slash_pos| {
            path_start += slash_pos;
        } else {
            return .{ .path = "/", .query = "" };
        }
    }

    const path_and_query = uri[path_start..];
    if (std.mem.indexOf(u8, path_and_query, "?")) |question_pos| {
        return .{ .path = path_and_query[0..question_pos], .query = path_and_query[question_pos + 1 ..] };
    } else {
        return .{ .path = path_and_query, .query = "" };
    }
}

/// Canonicalize URI path
fn canonicalizeUri(path: []const u8) []const u8 {
    if (path.len == 0) return "/";
    return path;
}

pub const QueryParam = struct {
    key: []const u8,
    value: []const u8,
};

fn compareQueryParams(context: void, lhs: QueryParam, rhs: QueryParam) bool {
    _ = context;
    const key_order = std.mem.order(u8, lhs.key, rhs.key);
    if (key_order != .eq) {
        return key_order == .lt;
    }
    return std.mem.order(u8, lhs.value, rhs.value) == .lt;
}

/// Canonicalize query string
fn canonicalizeQuery(allocator: Allocator, query_str: []const u8) ![]u8 {
    if (query_str.len == 0) return try allocator.dupe(u8, "");

    var params: ArrayList(QueryParam) = .empty;
    defer params.deinit(allocator);

    var it = std.mem.splitScalar(u8, query_str, '&');
    while (it.next()) |param| {
        if (param.len == 0) continue;
        if (std.mem.indexOfScalar(u8, param, '=')) |eq_pos| {
            try params.append(allocator, .{
                .key = param[0..eq_pos],
                .value = param[eq_pos + 1 ..],
            });
        } else {
            try params.append(allocator, .{
                .key = param,
                .value = "",
            });
        }
    }

    std.mem.sort(QueryParam, params.items, {}, compareQueryParams);

    var parts: ArrayList([]const u8) = .empty;
    defer {
        for (parts.items) |part| allocator.free(part);
        parts.deinit(allocator);
    }

    for (params.items) |p| {
        const item_str = try std.fmt.allocPrint(allocator, "{s}={s}", .{ p.key, p.value });
        try parts.append(allocator, item_str);
    }

    return try std.mem.join(allocator, "&", parts.items);
}

/// Calculate SHA256 hash and return as hex string
fn sha256Hash(allocator: Allocator, data: []const u8) ![]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    const hash = hasher.finalResult();
    return hexEncode(allocator, &hash);
}

/// Calculate HMAC-SHA256 and return as bytes
fn hmacSha256Bytes(allocator: Allocator, key: []const u8, data: []const u8) ![]u8 {
    var hmac: HmacSha256 = .init(key);
    hmac.update(data);
    var buf: [HmacSha256.mac_length]u8 = undefined;
    hmac.final(&buf);
    return allocator.dupe(u8, &buf);
}

/// Format timestamp as AWS date-time string (YYYYMMDDTHHMMSSZ)
fn formatDateTime(allocator: Allocator, timestamp: i64) ![]u8 {
    if (timestamp < 0) return error.InvalidTimestamp;
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(timestamp) };
    const epoch_day = epoch_seconds.getEpochDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    return try std.fmt.allocPrint(
        allocator,
        "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z",
        .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
        },
    );
}

/// Convert string to lowercase
fn toLowercase(allocator: Allocator, input: []const u8) ![]u8 {
    return std.ascii.allocLowerString(allocator, input);
}

/// Encode bytes as hexadecimal string
fn hexEncode(allocator: Allocator, bytes: []const u8) ![]u8 {
    const hex_chars = "0123456789abcdef";
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0x0F];
    }
    return out;
}

pub const RequestSigner = struct {
    const Self = @This();

    pub const Options = struct {
        service: []const u8,
        region: []const u8,
        credentials: Credentials,
        endpoint_url: ?[]const u8 = null,
        include_content_hash: bool = false,
    };

    options: Options,

    pub fn init(options: Options) Self {
        return Self{
            .options = options,
        };
    }

    pub const SignOptions = struct {
        method: HttpMethod,
        uri: []const u8,
        headers: StringHashMap([]const u8) = .empty,
        payload: ?[]const u8 = null,
    };

    pub fn sign(self: Self, allocator: Allocator, opt: SignOptions) !SignRequestResult {
        const sign_options: SignRequestOptions = .{
            .service = self.options.service,
            .region = self.options.region,
            .credentials = self.options.credentials,
            .endpoint_url = self.options.endpoint_url,
            .method = opt.method,
            .uri = opt.uri,
            .headers = opt.headers,
            .payload = opt.payload,
            .include_content_hash = self.options.include_content_hash,
        };
        return try signRequest(allocator, sign_options);
    }
};

test "SigV4 DateTime formatting" {
    const timestamp: i64 = 1640995200; // 2022-01-01T00:00:00Z
    const formatted = try formatDateTime(testing.allocator, timestamp);
    defer testing.allocator.free(formatted);

    try testing.expectEqualStrings("20220101T000000Z", formatted);
}

test "SigV4 payload hash calculation" {
    const hash_empty = try calculatePayloadHash(testing.allocator, null);
    defer testing.allocator.free(hash_empty);

    const hash_content = try calculatePayloadHash(testing.allocator, "hello");
    defer testing.allocator.free(hash_content);

    try testing.expect(hash_empty.len == 64); // SHA256 hex = 64 chars
    try testing.expect(hash_content.len == 64);
}

test "SigV4 host extraction" {
    const host1 = try extractHost(testing.allocator, try Uri.parse("https://s3.us-east-1.amazonaws.com/bucket/key"));
    defer testing.allocator.free(host1);
    try testing.expectEqualStrings("s3.us-east-1.amazonaws.com", host1);

    const host2 = try extractHost(testing.allocator, try Uri.parse("http://example.com"));
    defer testing.allocator.free(host2);
    try testing.expectEqualStrings("example.com", host2);
}

test "SigV4 path and query extraction" {
    const path_query1 = extractPathAndQuery("https://example.com/path?query=value");
    try testing.expectEqualStrings("/path", path_query1.path);
    try testing.expectEqualStrings("query=value", path_query1.query);

    const path_query2 = extractPathAndQuery("/simple/path");
    try testing.expectEqualStrings("/simple/path", path_query2.path);
    try testing.expectEqualStrings("", path_query2.query);
}

test "SigV4 canonical request creation" {
    var headers = StringHashMap([]const u8).empty;
    defer headers.deinit(testing.allocator);

    try headers.put(testing.allocator, "Host", "s3.amazonaws.com");
    try headers.put(testing.allocator, "X-Amz-Date", "20230101T120000Z");

    var arena = ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const canonical = try createCanonicalRequest(testing.allocator, .{
        .arena = arena,
        .method = .GET,
        .uri = try Uri.parse("https://s3.amazonaws.com/bucket/key"),
        .headers = headers,
        .body = "Hello, world!",
        .payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        .date_time = "20230101T120000Z",
        .date = "20230101",
    });
    defer testing.allocator.free(canonical);

    try testing.expect(std.mem.startsWith(u8, canonical, "GET\n"));
    try testing.expect(std.mem.indexOf(u8, canonical, "host:s3.amazonaws.com") != null);
}

test "SigV4 string to sign creation" {
    const string_to_sign = try createStringToSign(testing.allocator, "20230101T120000Z", "20230101/us-east-1/s3/aws4_request", "canonical_request_hash");
    defer testing.allocator.free(string_to_sign);

    try testing.expect(std.mem.startsWith(u8, string_to_sign, "AWS4-HMAC-SHA256\n"));
    try testing.expect(std.mem.indexOf(u8, string_to_sign, "20230101T120000Z") != null);
    try testing.expect(std.mem.indexOf(u8, string_to_sign, "20230101/us-east-1/s3/aws4_request") != null);
}

test "SigV4 signature calculation" {
    const signature = try calculateSignature(testing.allocator, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20230101", "us-east-1", "s3", "test_string_to_sign");
    defer testing.allocator.free(signature);

    try testing.expect(signature.len == 64); // SHA256 hex = 64 chars
    // Verify it's valid hex
    for (signature) |c| {
        try testing.expect(std.ascii.isHex(c));
    }
}

test "SigV4 header canonicalization" {
    var headers = StringHashMap([]const u8).empty;
    defer headers.deinit(testing.allocator);

    try headers.put(testing.allocator, "Host", "example.com");
    try headers.put(testing.allocator, "X-Amz-Date", "20230101T120000Z");
    try headers.put(testing.allocator, "Authorization", "AWS4-HMAC-SHA256 ...");

    const canonical = try canonicalizeHeaders(testing.allocator, headers);
    defer testing.allocator.free(canonical);

    // Should be sorted and lowercase
    try testing.expect(std.mem.indexOf(u8, canonical, "authorization:") != null);
    try testing.expect(std.mem.indexOf(u8, canonical, "host:") != null);
    try testing.expect(std.mem.indexOf(u8, canonical, "x-amz-date:") != null);
}

test "SigV4 signed headers list" {
    var headers = StringHashMap([]const u8).empty;
    defer headers.deinit(testing.allocator);

    try headers.put(testing.allocator, "Host", "example.com");
    try headers.put(testing.allocator, "X-Amz-Date", "20230101T120000Z");
    try headers.put(testing.allocator, "Content-Type", "application/json");

    const signed = try getSignedHeaders(testing.allocator, headers);
    defer testing.allocator.free(signed);

    // Should be lowercase and semicolon-separated
    try testing.expect(std.mem.indexOf(u8, signed, "content-type") != null);
    try testing.expect(std.mem.indexOf(u8, signed, "host") != null);
    try testing.expect(std.mem.indexOf(u8, signed, "x-amz-date") != null);
    try testing.expect(std.mem.indexOf(u8, signed, ";") != null);
}

test "SigV4 URI canonicalization" {
    const canonical1 = canonicalizeUri("/path/to/resource");
    try testing.expectEqualStrings("/path/to/resource", canonical1);

    const canonical2 = canonicalizeUri("");
    try testing.expectEqualStrings("/", canonical2);
}

test "SigV4 query canonicalization" {
    const canonical1 = try canonicalizeQuery(testing.allocator, "key1=value1&key2=value2");
    defer testing.allocator.free(canonical1);
    try testing.expectEqualStrings("key1=value1&key2=value2", canonical1);

    const canonical2 = try canonicalizeQuery(testing.allocator, "");
    defer testing.allocator.free(canonical2);
    try testing.expectEqualStrings("", canonical2);
}

test "SigV4 lowercase conversion" {
    const lower = try toLowercase(testing.allocator, "Content-Type");
    defer testing.allocator.free(lower);
    try testing.expectEqualStrings("content-type", lower);

    const already_lower = try toLowercase(testing.allocator, "host");
    defer testing.allocator.free(already_lower);
    try testing.expectEqualStrings("host", already_lower);
}

test "SigV4 hex encoding" {
    const bytes = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f }; // "Hello"
    const hex = try hexEncode(testing.allocator, &bytes);
    defer testing.allocator.free(hex);

    try testing.expectEqualStrings("48656c6c6f", hex);
}

test "SigV4 HMAC-SHA256 calculation" {
    const hmac_bytes = try hmacSha256Bytes(testing.allocator, "key", "data");
    defer testing.allocator.free(hmac_bytes);

    try testing.expect(hmac_bytes.len == 32); // SHA256 = 32 bytes
}

test "SigV4 complete signing workflow" {
    const credentials = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .session_token = null,
    };

    var arena: ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var headers = StringHashMap([]const u8).empty;

    const sign_result = try signRequest(allocator, .{
        .credentials = credentials,
        .region = "us-east-1",
        .service = "s3",
        .method = .GET,
        .uri = "https://s3.us-east-1.amazonaws.com/bucket/key",
        .headers = headers,
        .include_content_hash = true,
    });

    for (sign_result.headers.items) |header| {
        try headers.putNoClobber(allocator, header.name, header.value);
    }

    // Verify required headers were added
    try testing.expect(headers.get("Host") != null);
    try testing.expect(headers.get("X-Amz-Date") != null);
    try testing.expect(headers.get("X-Amz-Content-Sha256") != null);
    try testing.expect(headers.get("Authorization") != null);

    // Verify authorization header format
    const auth_header = headers.get("Authorization").?;
    try testing.expect(std.mem.startsWith(u8, auth_header, "AWS4-HMAC-SHA256"));
    try testing.expect(std.mem.indexOf(u8, auth_header, "Credential=") != null);
    try testing.expect(std.mem.indexOf(u8, auth_header, "SignedHeaders=") != null);
    try testing.expect(std.mem.indexOf(u8, auth_header, "Signature=") != null);
}

test "SigV4 signing with session token" {
    const credentials = Credentials{
        .access_key_id = "ASIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .session_token = "AQoDYXdzEJr...",
    };

    var arena = ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var headers = StringHashMap([]const u8).empty;

    const sign_result = try signRequest(allocator, .{
        .credentials = credentials,
        .region = "us-west-2",
        .service = "kms",
        .method = .POST,
        .uri = "https://kms.us-west-2.amazonaws.com/",
        .headers = headers,
        .payload = "{\"KeyId\":\"test\"}",
    });

    for (sign_result.headers.items) |header| {
        try headers.putNoClobber(allocator, header.name, header.value);
    }

    // Should include session token header
    try testing.expect(headers.get("X-Amz-Security-Token") != null);
    try testing.expectEqualStrings("AQoDYXdzEJr...", headers.get("X-Amz-Security-Token").?);
}

test "SigV4 signing with custom endpoint" {
    const credentials = Credentials{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .session_token = null,
    };

    var arena = ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var headers = StringHashMap([]const u8){};
    defer headers.deinit(allocator);

    // Test with LocalStack endpoint
    const sign_result = try signRequest(allocator, .{
        .credentials = credentials,
        .region = "us-east-1",
        .service = "s3",
        .method = .GET,
        .uri = "https://s3.us-east-1.amazonaws.com/bucket/key",
        .headers = headers,
        .endpoint_url = "http://localhost:4566",
        .include_content_hash = true,
    });

    for (sign_result.headers.items) |header| {
        try headers.putNoClobber(allocator, header.name, header.value);
    }

    // Verify the host header uses the custom endpoint
    try testing.expect(headers.get("Host") != null);
    try testing.expectEqualStrings("localhost:4566", headers.get("Host").?);

    // Verify other required headers are still present
    try testing.expect(headers.get("X-Amz-Date") != null);
    try testing.expect(headers.get("X-Amz-Content-Sha256") != null);
    try testing.expect(headers.get("Authorization") != null);
}

test "signRequest with LocalStack endpoint" {
    var arena = ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const credentials: Credentials = .{
        .access_key_id = "test",
        .secret_access_key = "test",
    };

    const timestamp: i64 = 1752645518;

    // Test with LocalStack endpoint
    const sign_result = try signRequest(allocator, .{
        .credentials = credentials,
        .region = "us-east-1",
        .service = "execute-api",
        .method = .GET,
        .uri = "https://execute-api.us-east-1.amazonaws.com/bucket/key",
        .endpoint_url = "http://localhost:4566",
        .timestamp = timestamp,
    });

    var headers: StringHashMap([]const u8) = .empty;
    for (sign_result.headers.items) |header| {
        try headers.putNoClobber(allocator, header.name, header.value);
    }

    // Verify the host header uses the custom endpoint
    try testing.expect(headers.get("Host") != null);
    try testing.expectEqualStrings("localhost:4566", headers.get("Host").?);

    // Verify other required headers are still present
    try testing.expect(headers.get("X-Amz-Date") != null);
    try testing.expectEqualStrings("20250716T055838Z", headers.get("X-Amz-Date").?);

    try testing.expect(headers.get("Authorization") != null);
}

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayList = std.ArrayListUnmanaged;
const Credentials = @import("Credentials.zig");
const Header = std.http.Header;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HttpMethod = std.http.Method;
const StringHashMap = std.StringHashMapUnmanaged;
const Uri = std.Uri;

const std = @import("std");
const testing = std.testing;
