use async_trait::async_trait;
use pingap_core::{BackgroundTask, Error};
use std::sync::Arc;

use crate::set::refresh_all;

pub struct FeedRefreshTask;

#[async_trait]
impl BackgroundTask for FeedRefreshTask {
    async fn execute(&self, _count: u32) -> Result<bool, Error> {
        Ok(refresh_all().await)
    }
}

pub fn new_feed_refresh_task() -> Box<dyn BackgroundTask> {
    Box::new(FeedRefreshTask)
}

pub fn shared_registry() -> Option<Arc<crate::set::FeedRegistry>> {
    crate::global_registry()
}
