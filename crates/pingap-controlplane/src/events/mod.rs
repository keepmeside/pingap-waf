// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! WAF findings on their way to the store.
//!
//! Two halves that are deliberately separate. The queue decides what survives a burst; the
//! writer decides how it reaches the store. Keeping them apart is what lets the queue be
//! tested without a database and the writer be tested without a request path, and it is also
//! the reason the queue can promise never to block: it has no idea a store exists.

pub mod writer;

pub use pingap_events::{Admission, EventQueue, Verdict, WafEvent};
pub use writer::{DEFAULT_BATCH, EventWriter};
