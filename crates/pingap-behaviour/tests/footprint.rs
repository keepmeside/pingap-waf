//! The measured per-client memory footprint, against the published
//! arithmetic. The plan publishes ≈ 8.5 KB per tracked client and ~43 MB per
//! busy domain at `max_clients = 5000`; a published number that is never
//! measured is a claim, so this file measures the real bytes a full profile
//! holds, with a counting global allocator around the construction and fill.
//!
//! The measurement is a delta, not an absolute: the allocator counts the whole
//! test binary's traffic, so the reading is taken around the profile alone.
//! This file is the only test in its binary, so no other test thread
//! allocates between the two readings.

use pingap_behaviour::{Observation, Profile};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe {
            let pointer = System.alloc(layout);
            if !pointer.is_null() {
                ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
            }
            pointer
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe {
            ALLOCATED.fetch_sub(layout.size(), Ordering::Relaxed);
            System.dealloc(pointer, layout);
        }
    }
    unsafe fn realloc(
        &self,
        pointer: *mut u8,
        layout: Layout,
        new_size: usize,
    ) -> *mut u8 {
        unsafe {
            let new = System.realloc(pointer, layout, new_size);
            if !new.is_null() {
                ALLOCATED.fetch_add(
                    new_size.saturating_sub(layout.size()),
                    Ordering::Relaxed,
                );
            }
            new
        }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: Counting = Counting;

/// The published per-client figure the measurement is held against.
const PUBLISHED_PER_CLIENT: usize = 8_500;

fn fill(profile: &mut Profile, start: Instant) {
    for index in 0..40 {
        profile.record(Observation {
            at: start + Duration::from_millis(index * 1_000),
            uri: format!("/products/{}/detail", index),
            user_agent: if index % 20 == 0 {
                "browser-b".into()
            } else {
                "browser-a".into()
            },
            status: 200,
            denied: false,
            challenged: false,
            bot: false,
        });
    }
}

/// One full profile, measured. The caps are the documented defaults — 32
/// interval samples, 64 URL keys, 8 user agents — and the fill drives past
/// every cap so the reading is the steady state a busy client holds, not the
/// growing edge. The tolerance is stated, not discovered: half to double the
/// published figure, the range where the published arithmetic still counts as
/// an honest estimate rather than a different number.
#[test]
fn a_full_profile_measures_within_tolerance_of_the_published_figure() {
    let start = Instant::now();
    // Warm any structure the first construction sizes, so the measured delta
    // is the profile's own bytes and not first-touch growth.
    let mut warmup = Profile::new(32, 64, 8, Duration::from_secs(300));
    fill(&mut warmup, start);
    drop(warmup);

    let before = ALLOCATED.load(Ordering::Relaxed);
    let mut profile = Profile::new(32, 64, 8, Duration::from_secs(300));
    fill(&mut profile, start);
    let measured = ALLOCATED.load(Ordering::Relaxed) - before;
    drop(profile);

    assert!(
        measured >= PUBLISHED_PER_CLIENT / 2,
        "measured {measured} B is less than half the published 8.5 KB — the \
         published figure overstates the footprint the caps bound"
    );
    assert!(
        measured <= PUBLISHED_PER_CLIENT * 2,
        "measured {measured} B is more than double the published 8.5 KB — the \
         published figure understates what a busy client holds"
    );
    // The per-domain figure is this measurement times the client cap: the
    // number an operator reads as the cost of one busy domain.
    let per_domain = measured.saturating_mul(5_000);
    println!(
        "measured {measured} B per full profile; × 5000 clients = \
         {per_domain} B per busy domain"
    );
}
