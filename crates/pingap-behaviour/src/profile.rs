use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Observation {
    pub at: Instant,
    pub uri: String,
    pub user_agent: String,
    pub status: u16,
    pub denied: bool,
    pub challenged: bool,
    pub bot: bool,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub samples: VecDeque<Observation>,
    pub url_counts: HashMap<String, u32>,
    pub user_agents: HashSet<String>,
    pub total: u64,
    pub errors: u64,
    pub overflow_urls: u64,
    pub overflow_user_agents: u64,
    pub observed: u64,
    pub last: Option<Instant>,
    max_samples: usize,
    max_urls: usize,
    max_user_agents: usize,
    window: Duration,
}

impl Profile {
    pub fn new(
        max_samples: usize,
        max_urls: usize,
        max_user_agents: usize,
        window: Duration,
    ) -> Self {
        Self {
            samples: VecDeque::with_capacity(max_samples),
            url_counts: HashMap::new(),
            user_agents: HashSet::new(),
            total: 0,
            errors: 0,
            overflow_urls: 0,
            overflow_user_agents: 0,
            observed: 0,
            last: None,
            max_samples: max_samples.max(1),
            max_urls: max_urls.max(1),
            max_user_agents: max_user_agents.max(1),
            window,
        }
    }

    pub fn record(&mut self, observation: Observation) {
        let now = observation.at;
        self.prune(now);
        if self.url_counts.contains_key(&observation.uri)
            || self.url_counts.len() < self.max_urls
        {
            *self.url_counts.entry(observation.uri.clone()).or_default() += 1;
        } else {
            self.overflow_urls = self.overflow_urls.saturating_add(1);
        }
        if self.user_agents.contains(&observation.user_agent)
            || self.user_agents.len() < self.max_user_agents
        {
            self.user_agents.insert(observation.user_agent.clone());
        } else {
            self.overflow_user_agents =
                self.overflow_user_agents.saturating_add(1);
        }
        if self.samples.len() == self.max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(observation);
        self.rebuild_aggregates();
        self.last = Some(now);
    }

    pub fn prune(&mut self, now: Instant) {
        let mut changed = false;
        while self
            .samples
            .front()
            .is_some_and(|sample| now.duration_since(sample.at) > self.window)
        {
            self.samples.pop_front();
            changed = true;
        }
        if changed {
            self.rebuild_aggregates();
        }
    }

    fn rebuild_aggregates(&mut self) {
        self.total = self.samples.len() as u64;
        self.observed = self.samples.len() as u64;
        self.errors = 0;
        self.url_counts.clear();
        self.user_agents.clear();
        for sample in &self.samples {
            if sample.status >= 400 {
                self.errors = self.errors.saturating_add(1);
            }
            if self.url_counts.contains_key(&sample.uri)
                || self.url_counts.len() < self.max_urls
            {
                *self.url_counts.entry(sample.uri.clone()).or_default() += 1;
            }
            if self.user_agents.contains(&sample.user_agent)
                || self.user_agents.len() < self.max_user_agents
            {
                self.user_agents.insert(sample.user_agent.clone());
            }
        }
        if self.samples.is_empty() {
            self.last = None;
        }
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
    pub fn capacity(&self) -> usize {
        self.max_samples
    }
}
