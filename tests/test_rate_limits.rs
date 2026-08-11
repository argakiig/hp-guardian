use hp_guard::{InMemoryRateLimitStore, PolicyCall, RateLimitedPolicyStore};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const POLICY: &str = "version: 2\nrules:\n  - action: allow\n    target:\n      tool: search\n    rate_limit:\n      max_calls: 1\n      window_seconds: 60\n";

fn search_call() -> PolicyCall {
    PolicyCall {
        tool: Some("search".into()),
        ..Default::default()
    }
}

#[test]
fn concurrent_calls_cannot_exceed_a_fixed_window_quota() {
    let store = Arc::new(
        RateLimitedPolicyStore::with_clock(
            POLICY,
            Arc::new(InMemoryRateLimitStore::new()),
            Arc::new(|| 10),
        )
        .expect("policy"),
    );
    let decisions = Arc::new(Mutex::new(Vec::new()));
    let threads = (0..16)
        .map(|_| {
            let store = Arc::clone(&store);
            let decisions = Arc::clone(&decisions);
            std::thread::spawn(move || {
                decisions
                    .lock()
                    .expect("decisions")
                    .push(store.resolve(&search_call()).expect("decision").action);
            })
        })
        .collect::<Vec<_>>();
    for thread in threads {
        thread.join().expect("thread");
    }
    let decisions = decisions.lock().expect("decisions");
    assert_eq!(
        decisions
            .iter()
            .filter(|action| action.as_str() == "allow")
            .count(),
        1
    );
    assert_eq!(
        decisions
            .iter()
            .filter(|action| action.as_str() == "throttle")
            .count(),
        15
    );
}

#[test]
fn monotonic_clock_regression_fails_closed() {
    let now = Arc::new(AtomicU64::new(10));
    let clock = {
        let now = Arc::clone(&now);
        Arc::new(move || now.load(Ordering::Relaxed))
    };
    let store =
        RateLimitedPolicyStore::with_clock(POLICY, Arc::new(InMemoryRateLimitStore::new()), clock)
            .expect("policy");
    assert_eq!(
        store
            .resolve(&search_call())
            .expect("decision")
            .action
            .as_str(),
        "allow"
    );
    now.store(9, Ordering::Relaxed);
    assert_eq!(
        store
            .resolve(&search_call())
            .expect_err("clock regression")
            .code(),
        "state_unavailable"
    );
}

#[test]
fn state_capacity_exhaustion_fails_closed() {
    let store = RateLimitedPolicyStore::with_clock(
        POLICY,
        Arc::new(InMemoryRateLimitStore::with_capacity(1).expect("capacity")),
        Arc::new(|| 10),
    )
    .expect("policy");
    assert_eq!(
        store
            .resolve(&PolicyCall {
                agent: Some("first".into()),
                ..search_call()
            })
            .expect("decision")
            .action
            .as_str(),
        "allow"
    );
    assert_eq!(
        store
            .resolve(&PolicyCall {
                agent: Some("second".into()),
                ..search_call()
            })
            .expect_err("capacity exhausted")
            .code(),
        "state_unavailable"
    );
}
