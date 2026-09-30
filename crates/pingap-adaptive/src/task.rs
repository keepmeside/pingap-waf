use async_trait::async_trait;
use pingap_core::{BackgroundTask, Error};

use crate::plugin::calibrate_global;

pub struct CalibrationTask;

#[async_trait]
impl BackgroundTask for CalibrationTask {
    async fn execute(&self, _count: u32) -> Result<bool, Error> {
        Ok(calibrate_global())
    }
}

pub fn new_calibration_task() -> Box<dyn BackgroundTask> {
    Box::new(CalibrationTask)
}
