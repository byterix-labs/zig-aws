//! Minimalist AWS client for S3 and KMS services
//!
//! This module provides a lightweight, memory-safe, and error-handling-focused
//! AWS client implementation following Zig's design principles. It includes:
//!
//! - Complete AWS Signature Version 4 (SigV4) implementation
//! - Core S3 operations: PutObject, GetObject, DeleteObject, ListBuckets
//! - Essential KMS operations: Encrypt, Decrypt, GenerateDataKey
//! - Explicit error handling and allocator-based memory management
//!
//! Example usage:
//!
//! ```zig
//! const aws = @import("aws.zig");
//!
//! // Initialize client
//! var client = try aws.Client.init(allocator, .{
//!     .access_key_id = "AKIAIOSFODNN7EXAMPLE",
//!     .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
//!     .region = "us-east-1",
//! });
//! defer client.deinit();
//!
//! // Use S3
//! try client.s3().putObject("my-bucket", "key.txt", "Hello, World!", .{});
//! var result = try client.s3().getObject("my-bucket", "key.txt");
//! defer result.deinit();
//!
//! // Use KMS
//! var encrypted = try client.kms().encrypt("key-id", "secret data", null);
//! defer encrypted.deinit();
//! ```

// Core modules
pub const client = @import("client.zig");
pub const Client = client.Client;
pub const Config = client.Config;
pub const Error = client.Error;

// Authentication
pub const Credentials = @import("Credentials.zig");

// S3 service
pub const s3 = @import("s3.zig");
pub const S3Client = s3.Client;
pub const S3Error = s3.S3Error;
pub const ObjectMetadata = s3.ObjectMetadata;
pub const Bucket = s3.Bucket;
pub const ListObjectsResult = s3.ListObjectsResult;
pub const PutObjectOptions = s3.PutObjectOptions;
pub const GetObjectResult = s3.GetObjectResult;
pub const ListObjectsOptions = s3.ListObjectsOptions;

// KMS service
pub const kms = @import("kms.zig");
pub const KmsClient = kms.Client;
pub const KMSError = kms.KmsError;
pub const KmsError = kms.KmsError;
pub const KeySpec = kms.KeySpec;
pub const EncryptResult = kms.EncryptResult;
pub const DecryptResult = kms.DecryptResult;
pub const EncryptionContext = kms.EncryptionContext;

// HTTP and signing
pub const http = @import("http.zig");
pub const sigv4 = @import("sigv4.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
