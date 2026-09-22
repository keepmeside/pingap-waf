//! Alert evaluation, suppression, dispatch, and outbound channels.

pub mod channels;
pub mod dispatch;
pub mod evaluator;
pub mod scheduler;
pub mod suppression;

pub use scheduler::{dispatch_persisted_channels, evaluate_once};

pub use crate::repository::AlertRuleRecord;
pub use dispatch::{
    AttemptOutcome, Delivery, Dispatch, DispatchResult, DispatchSender,
};
pub use evaluator::{
    AlertRule, Comparison, Evaluation, MetricSample, evaluate,
};
pub use suppression::{Suppression, SuppressionDecision, SuppressionState};
