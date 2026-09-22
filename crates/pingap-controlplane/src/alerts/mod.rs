//! Alert evaluation, suppression, dispatch, and outbound channels.

pub mod channels;
pub mod dispatch;
pub mod evaluator;
pub mod suppression;

pub use dispatch::{AttemptOutcome, Delivery, Dispatch, DispatchResult};
pub use evaluator::{
    AlertRule, Comparison, Evaluation, MetricSample, evaluate,
};
pub use suppression::{Suppression, SuppressionDecision, SuppressionState};
