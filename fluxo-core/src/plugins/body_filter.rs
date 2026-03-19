//! Body filter chain — Nginx-inspired response body transformation pipeline.
//!
//! Nginx separates request/response header filters from body filters.
//! Body filters process streaming chunks without buffering the entire body.
//! This module provides the `BodyFilter` trait and `BodyFilterChain` for
//! composing multiple body transformations.

use crate::context::RequestContext;

/// A body filter that processes response body chunks.
///
/// Nginx-inspired: header filters (`on_response`) run once, body filters
/// run per-chunk. This enables streaming transformations without buffering.
pub trait BodyFilter: std::fmt::Debug + Send + Sync {
    /// Filter a body chunk. Modify `body` in-place.
    ///
    /// Called once per chunk. `end_of_stream` is true on the final chunk.
    /// The filter can:
    /// - Modify the bytes (compression, injection)
    /// - Set body to `None` to suppress the chunk
    /// - Buffer internally and emit on `end_of_stream`
    fn filter_body(
        &self,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut RequestContext,
    );
}

/// An ordered chain of body filters, executed per response chunk.
///
/// Nginx-inspired: body filters run in registration order on each chunk
/// of the response body. This is separate from the header-level plugin
/// pipeline (`on_request`/`on_response`).
#[derive(Debug, Default)]
pub struct BodyFilterChain {
    filters: Vec<Box<dyn BodyFilter>>,
}

impl BodyFilterChain {
    /// Create a new chain from a list of body filters.
    pub fn new(filters: Vec<Box<dyn BodyFilter>>) -> Self {
        Self { filters }
    }

    /// Create an empty chain (pass-through).
    pub fn empty() -> Self {
        Self {
            filters: Vec::new(),
        }
    }

    /// Add a body filter to the chain.
    pub fn push(&mut self, filter: Box<dyn BodyFilter>) {
        self.filters.push(filter);
    }

    /// Run all filters on a body chunk.
    pub fn run(
        &self,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut RequestContext,
    ) {
        for filter in &self.filters {
            filter.filter_body(body, end_of_stream, ctx);
        }
    }

    /// Whether the chain has any filters.
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    /// Number of filters in the chain.
    pub fn len(&self) -> usize {
        self.filters.len()
    }
}

/// Compression body filter — compresses response chunks using the encoding
/// chosen by the compression plugin's `on_response` phase.
///
/// This is a refactored version of the inline compression logic that was
/// previously in `proxy.rs::response_body_filter`.
#[derive(Debug)]
pub struct CompressionBodyFilter;

impl BodyFilter for CompressionBodyFilter {
    fn filter_body(
        &self,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut RequestContext,
    ) {
        use crate::context::StreamingCompressor;

        // Only compress if the compression plugin chose an encoding
        let encoding = match ctx.compression_encoding {
            Some(enc) => enc,
            None => return,
        };

        if let Some(b) = body.take() {
            // Lazily initialize the streaming compressor on first chunk
            if ctx.compressor.is_none() {
                ctx.compressor = StreamingCompressor::new(encoding);
            }
            if let Some(ref mut compressor) = ctx.compressor {
                match compressor.write_chunk(&b) {
                    Ok(compressed) if !compressed.is_empty() => {
                        *body = Some(bytes::Bytes::from(compressed));
                    }
                    Ok(_) => {} // Buffered internally, nothing to emit yet
                    Err(_) => {
                        *body = Some(b); // Compression failed — pass through
                    }
                }
            }
        }

        // On end-of-stream, finalize the compressor
        if end_of_stream {
            if let Some(compressor) = ctx.compressor.take() {
                match compressor.finish() {
                    Ok(final_bytes) if !final_bytes.is_empty() => match body {
                        Some(existing) => {
                            let mut combined = existing.to_vec();
                            combined.extend_from_slice(&final_bytes);
                            *body = Some(bytes::Bytes::from(combined));
                        }
                        None => {
                            *body = Some(bytes::Bytes::from(final_bytes));
                        }
                    },
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[derive(Debug)]
    struct UppercaseFilter;

    impl BodyFilter for UppercaseFilter {
        fn filter_body(
            &self,
            body: &mut Option<bytes::Bytes>,
            _end_of_stream: bool,
            _ctx: &mut RequestContext,
        ) {
            if let Some(b) = body.take() {
                let upper = String::from_utf8_lossy(&b).to_uppercase();
                *body = Some(bytes::Bytes::from(upper));
            }
        }
    }

    #[test]
    fn empty_chain_passes_through() {
        let chain = BodyFilterChain::empty();
        let mut body = Some(bytes::Bytes::from("hello"));
        let mut ctx = RequestContext::new();
        chain.run(&mut body, false, &mut ctx);
        assert_eq!(body.as_deref(), Some(b"hello".as_ref()));
    }

    #[test]
    fn single_filter_modifies_body() {
        let chain = BodyFilterChain::new(vec![Box::new(UppercaseFilter)]);
        let mut body = Some(bytes::Bytes::from("hello"));
        let mut ctx = RequestContext::new();
        chain.run(&mut body, false, &mut ctx);
        assert_eq!(body.as_deref(), Some(b"HELLO".as_ref()));
    }

    #[test]
    fn chain_runs_filters_in_order() {
        #[derive(Debug)]
        struct AppendFilter(&'static str);
        impl BodyFilter for AppendFilter {
            fn filter_body(
                &self,
                body: &mut Option<bytes::Bytes>,
                _end_of_stream: bool,
                _ctx: &mut RequestContext,
            ) {
                if let Some(b) = body.take() {
                    let mut s = b.to_vec();
                    s.extend_from_slice(self.0.as_bytes());
                    *body = Some(bytes::Bytes::from(s));
                }
            }
        }

        let chain = BodyFilterChain::new(vec![
            Box::new(AppendFilter("-a")),
            Box::new(AppendFilter("-b")),
        ]);
        let mut body = Some(bytes::Bytes::from("x"));
        let mut ctx = RequestContext::new();
        chain.run(&mut body, false, &mut ctx);
        assert_eq!(body.as_deref(), Some(b"x-a-b".as_ref()));
    }

    #[test]
    fn chain_length() {
        let mut chain = BodyFilterChain::empty();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        chain.push(Box::new(UppercaseFilter));
        assert!(!chain.is_empty());
        assert_eq!(chain.len(), 1);
    }
}
