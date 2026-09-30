use async_trait::async_trait;
use ctor::ctor;
use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingap_plugin::{Error, get_plugin_factory, get_step_conf_in};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::sync::Arc;

const CATEGORY: &str = "intel";

/// The feed subsystem is normally selected by a WAF policy. This lightweight
/// category exists so a built artifact can resolve the subsystem explicitly and
/// so a hand-written Location can fail closed if its feed policy cannot build.
pub struct IntelPlugin {
    step: PluginStep,
    hash: String,
}

impl TryFrom<&PluginConf> for IntelPlugin {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self, Self::Error> {
        Ok(Self {
            step: get_step_conf_in(
                value,
                CATEGORY,
                PluginStep::Request,
                &[PluginStep::Request],
            )?,
            hash: pingap_plugin::get_hash_key(value),
        })
    }
}

#[async_trait]
impl Plugin for IntelPlugin {
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash)
    }

    async fn handle_request(
        &self,
        step: PluginStep,
        _session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step == self.step {
            Ok(RequestPluginResult::Continue)
        } else {
            Ok(RequestPluginResult::Skipped)
        }
    }
}

#[ctor(unsafe)]
fn register() {
    get_plugin_factory().register(CATEGORY, |params| {
        Ok(Arc::new(IntelPlugin::try_from(params)?))
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn category_is_registered_with_the_factory() {
        assert!(
            pingap_plugin::get_plugin_factory()
                .supported_plugins()
                .contains(&"intel".to_string())
        );
    }
}
