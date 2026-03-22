//! Response body rewriting — Nginx `sub_filter` equivalent.
//!
//! Performs string substitution in response body chunks.
//! Only applies to responses with matching content types.

use bytes::Bytes;

use crate::config::SubFilterConfig;

/// Compiled `sub_filter` ready for use during request processing.
#[derive(Debug, Clone)]
pub struct CompiledSubFilter {
    /// Search/replace pairs.
    pub replacements: Vec<(String, String)>,
    /// Allowed content types (lowercase, prefix match).
    pub types: Vec<String>,
    /// Replace only first occurrence per pattern.
    pub once: bool,
}

impl CompiledSubFilter {
    /// Build from config.
    pub fn from_config(config: &SubFilterConfig) -> Self {
        Self {
            replacements: config
                .replacements
                .iter()
                .map(|r| (r.search.clone(), r.replace.clone()))
                .collect(),
            types: config.types.iter().map(|t| t.to_lowercase()).collect(),
            once: config.once,
        }
    }

    /// Check if the given content type should be filtered.
    pub fn should_filter(&self, content_type: Option<&str>) -> bool {
        let ct = match content_type {
            Some(ct) => ct.to_lowercase(),
            None => return false,
        };
        self.types.iter().any(|t| ct.starts_with(t.as_str()))
    }

    /// Apply all replacements to a body chunk.
    /// Returns the modified body.
    pub fn apply(&self, body: &[u8]) -> Bytes {
        // Only process valid UTF-8 text
        let Ok(text) = std::str::from_utf8(body) else {
            return Bytes::copy_from_slice(body);
        };

        let mut result = text.to_string();
        for (search, replace) in &self.replacements {
            if search.is_empty() {
                continue;
            }
            if self.once {
                // Replace only first occurrence
                if let Some(pos) = result.find(search.as_str()) {
                    result = format!(
                        "{}{}{}",
                        &result[..pos],
                        replace,
                        &result[pos + search.len()..]
                    );
                }
            } else {
                result = result.replace(search.as_str(), replace.as_str());
            }
        }

        Bytes::from(result)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::config::{SubFilterConfig, SubFilterReplacement};

    fn make_config(replacements: Vec<(&str, &str)>, once: bool) -> SubFilterConfig {
        SubFilterConfig {
            replacements: replacements
                .into_iter()
                .map(|(s, r)| SubFilterReplacement {
                    search: s.to_string(),
                    replace: r.to_string(),
                })
                .collect(),
            types: vec!["text/html".to_string()],
            once,
        }
    }

    #[test]
    fn simple_replacement() {
        let cfg = make_config(vec![("foo", "bar")], false);
        let filter = CompiledSubFilter::from_config(&cfg);
        let result = filter.apply(b"hello foo world foo");
        assert_eq!(&result[..], b"hello bar world bar");
    }

    #[test]
    fn once_mode_replaces_first_only() {
        let cfg = make_config(vec![("foo", "bar")], true);
        let filter = CompiledSubFilter::from_config(&cfg);
        let result = filter.apply(b"foo foo foo");
        assert_eq!(&result[..], b"bar foo foo");
    }

    #[test]
    fn multiple_patterns() {
        let cfg = make_config(vec![("old", "new"), ("bad", "good")], false);
        let filter = CompiledSubFilter::from_config(&cfg);
        let result = filter.apply(b"old and bad");
        assert_eq!(&result[..], b"new and good");
    }

    #[test]
    fn empty_search_skipped() {
        let cfg = make_config(vec![("", "bar")], false);
        let filter = CompiledSubFilter::from_config(&cfg);
        let result = filter.apply(b"hello");
        assert_eq!(&result[..], b"hello");
    }

    #[test]
    fn non_utf8_passthrough() {
        let cfg = make_config(vec![("foo", "bar")], false);
        let filter = CompiledSubFilter::from_config(&cfg);
        let binary = vec![0xFF, 0xFE, 0x00, 0x01];
        let result = filter.apply(&binary);
        assert_eq!(&result[..], &binary[..]);
    }

    #[test]
    fn content_type_matching() {
        let cfg = make_config(vec![("a", "b")], false);
        let filter = CompiledSubFilter::from_config(&cfg);
        assert!(filter.should_filter(Some("text/html; charset=utf-8")));
        assert!(filter.should_filter(Some("TEXT/HTML")));
        assert!(!filter.should_filter(Some("application/json")));
        assert!(!filter.should_filter(None));
    }

    #[test]
    fn replacement_with_longer_string() {
        let cfg = make_config(vec![("x", "xxx")], false);
        let filter = CompiledSubFilter::from_config(&cfg);
        let result = filter.apply(b"axbxc");
        assert_eq!(&result[..], b"axxxbxxxc");
    }

    #[test]
    fn replacement_with_empty_string() {
        let cfg = make_config(vec![("remove", "")], false);
        let filter = CompiledSubFilter::from_config(&cfg);
        let result = filter.apply(b"please remove this");
        assert_eq!(&result[..], b"please  this");
    }

    #[test]
    fn no_match_returns_unchanged() {
        let cfg = make_config(vec![("xyz", "abc")], false);
        let filter = CompiledSubFilter::from_config(&cfg);
        let result = filter.apply(b"hello world");
        assert_eq!(&result[..], b"hello world");
    }
}
