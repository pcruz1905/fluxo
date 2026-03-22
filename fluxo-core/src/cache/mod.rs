//! Disk-backed HTTP cache storage.
//!
//! Implements Pingora's `Storage` trait with filesystem persistence.
//! Cache entries survive restarts. LRU eviction keeps total size under budget.
//!
//! Directory layout:
//! ```text
//! {cache_dir}/{hex_hash[0..2]}/{hex_hash}/meta.bin
//! {cache_dir}/{hex_hash[0..2]}/{hex_hash}/body.bin
//! ```

mod disk;

pub use disk::DiskCache;
