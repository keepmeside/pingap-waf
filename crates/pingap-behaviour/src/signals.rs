use crate::profile::Profile;

pub fn timing_regularity(profile: &Profile, min: usize) -> Option<f64> {
    if profile.samples.len() < min {
        return None;
    }
    let intervals: Vec<f64> = profile
        .samples
        .iter()
        .zip(profile.samples.iter().skip(1))
        .map(|(previous, current)| {
            current.at.duration_since(previous.at).as_secs_f64()
        })
        .collect();
    if intervals.is_empty() {
        return None;
    }
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean == 0.0 {
        return Some(0.0);
    }
    let variance = intervals
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / intervals.len() as f64;
    Some((1.0 - variance.sqrt() / mean).clamp(0.0, 1.0) * 100.0)
}

pub fn url_entropy(profile: &Profile, min: usize) -> Option<f64> {
    if profile.samples.len() < min {
        return None;
    }
    let total = profile
        .url_counts
        .values()
        .map(|value| f64::from(*value))
        .sum::<f64>();
    if total == 0.0 {
        return None;
    }
    let entropy = profile
        .url_counts
        .values()
        .map(|value| {
            let p = f64::from(*value) / total;
            -p * p.log2()
        })
        .sum::<f64>();
    Some(
        (entropy / (profile.url_counts.len().max(1) as f64).log2().max(1.0)
            * 100.0)
            .clamp(0.0, 100.0),
    )
}

pub fn request_diversity(profile: &Profile, min: usize) -> Option<f64> {
    if profile.samples.len() < min {
        return None;
    }
    Some(
        (profile.url_counts.len() as f64 / profile.samples.len() as f64
            * 100.0)
            .clamp(0.0, 100.0),
    )
}

pub fn request_speed(profile: &Profile, min: usize) -> Option<f64> {
    if profile.samples.len() < min {
        return None;
    }
    let first = profile.samples.front()?;
    let last = profile.samples.back()?;
    let seconds = last.at.duration_since(first.at).as_secs_f64().max(1.0);
    let rps = profile.samples.len() as f64 / seconds;
    Some((100.0 / (1.0 + rps * 2.0)).clamp(0.0, 100.0))
}

pub fn error_pattern(profile: &Profile, min: usize) -> Option<f64> {
    if profile.samples.len() < min {
        return None;
    }
    let errors = profile
        .samples
        .iter()
        .filter(|sample| sample.status >= 400)
        .count() as f64;
    Some(
        (100.0 - errors / profile.samples.len() as f64 * 100.0)
            .clamp(0.0, 100.0),
    )
}

pub fn user_agent_consistency(profile: &Profile, min: usize) -> Option<f64> {
    if profile.samples.len() < min {
        return None;
    }
    Some((100.0 / profile.user_agents.len().max(1) as f64).clamp(0.0, 100.0))
}
