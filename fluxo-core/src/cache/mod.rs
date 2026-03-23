//! HTTP cache storage backends.
//!
//! Provides two storage implementations:
//! - **`DiskCache`** — Filesystem-backed with LRU eviction. Entries survive restarts.
//! - **`TinyUfoCache`** — In-memory with TinyLFU + S3-FIFO eviction. Better hit rates
//!   for frequency-skewed workloads.
//!
//! Directory layout (disk):
//! ```text
//! {cache_dir}/{hex_hash[0..2]}/{hex_hash}/meta.bin
//! {cache_dir}/{hex_hash[0..2]}/{hex_hash}/body.bin
//! ```

mod disk;
pub mod lock;
pub mod tinyufo;

pub use disk::DiskCache;
pub use lock::CacheLockManager;
pub use tinyufo::TinyUfoCache;
