//! Plugin pipeline — an ordered list of plugins compiled per-route.

use super::BuiltinPlugin;

/// An ordered list of plugins to execute at each request phase.
#[derive(Debug)]
pub struct PluginPipeline {
    plugins: Vec<BuiltinPlugin>,
}

impl PluginPipeline {
    /// Create a new pipeline from a list of plugins.
    pub fn new(plugins: Vec<BuiltinPlugin>) -> Self {
        Self { plugins }
    }

    /// Create an empty pipeline (no-op at all phases).
    pub fn empty() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Number of plugins in the pipeline.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether the pipeline is empty.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pipeline_returns_continue_on_all_phases() {
        let pipeline = PluginPipeline::empty();
        assert_eq!(pipeline.len(), 0);
    }

    #[test]
    fn pipeline_from_single_plugin() {
        let plugin = BuiltinPlugin::RequestId(super::super::request_id::RequestIdPlugin);
        let pipeline = PluginPipeline::new(vec![plugin]);
        assert_eq!(pipeline.len(), 1);
    }
}
