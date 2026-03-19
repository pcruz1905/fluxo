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

    /// Execute all request-phase plugins. Returns Handled if any short-circuited.
    pub fn run_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut crate::context::RequestContext,
    ) -> super::PluginAction {
        for plugin in &self.plugins {
            match plugin.on_request(req, ctx) {
                super::PluginAction::Continue => {}
                action => return action,
            }
        }
        super::PluginAction::Continue
    }

    /// Execute all upstream-request-phase plugins.
    pub fn run_upstream_request(
        &self,
        upstream_req: &mut pingora_http::RequestHeader,
        ctx: &crate::context::RequestContext,
    ) {
        for plugin in &self.plugins {
            plugin.on_upstream_request(upstream_req, ctx);
        }
    }

    /// Execute all response-phase plugins.
    pub fn run_response(
        &self,
        resp: &mut pingora_http::ResponseHeader,
        ctx: &mut crate::context::RequestContext,
    ) {
        for plugin in &self.plugins {
            plugin.on_response(resp, ctx);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn empty_pipeline_returns_continue_on_all_phases() {
        let pipeline = PluginPipeline::empty();
        assert_eq!(pipeline.len(), 0);
    }

    #[test]
    fn pipeline_from_single_plugin() {
        let plugin = BuiltinPlugin::RequestId(super::super::request_id::RequestIdPlugin::default());
        let pipeline = PluginPipeline::new(vec![plugin]);
        assert_eq!(pipeline.len(), 1);
    }
}
