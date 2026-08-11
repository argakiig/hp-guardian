use hp_guard::{InMemoryRateLimitStore, PolicyCall, PolicyParser, RateLimitedPolicyStore};
use serde_json::Value;
use std::fs;
use std::sync::Arc;

fn fixture() -> Value {
    serde_json::from_str(
        &fs::read_to_string("conformance/cases/rate_limits_v2.json").expect("read fixture"),
    )
    .expect("valid fixture")
}

fn call(value: &Value) -> PolicyCall {
    PolicyCall {
        agent: value["agent"].as_str().map(str::to_owned),
        tool: value["tool"].as_str().map(str::to_owned),
        args: Vec::new(),
        user: value["user"].as_str().map(str::to_owned),
        context: value["context"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_owned()))
            .collect(),
    }
}

#[test]
fn v2_rate_limit_cases_match_shared_fixture() {
    for case in fixture()["cases"].as_array().expect("cases") {
        let now = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clock = {
            let now = Arc::clone(&now);
            Arc::new(move || now.load(std::sync::atomic::Ordering::Relaxed))
        };
        let store = RateLimitedPolicyStore::with_clock(
            case["policy"].as_str().expect("policy"),
            Arc::new(InMemoryRateLimitStore::new()),
            clock,
        )
        .expect("valid policy");
        for step in case["steps"].as_array().expect("steps") {
            now.store(
                step["now"].as_u64().expect("now"),
                std::sync::atomic::Ordering::Relaxed,
            );
            let decision = store.resolve(&call(&step["call"])).expect("decision");
            assert_eq!(
                decision.action.as_str(),
                step["expect"]["decision"].as_str().unwrap()
            );
            assert_eq!(
                decision.matched_rules,
                serde_json::from_value::<Vec<usize>>(step["expect"]["matched_rules"].clone())
                    .unwrap()
            );
        }
    }
}

#[test]
fn v2_rate_limit_errors_match_shared_fixture() {
    for case in fixture()["error_cases"].as_array().expect("error cases") {
        let error = if case["entry"].as_str() == Some("policy_parser") {
            PolicyParser::parse(case["policy"].as_str().expect("policy"))
                .expect_err("invalid policy")
        } else {
            match RateLimitedPolicyStore::with_policy(
                case["policy"].as_str().expect("policy"),
                Arc::new(InMemoryRateLimitStore::new()),
            ) {
                Ok(_) => panic!("invalid policy"),
                Err(error) => error,
            }
        };
        assert_eq!(error.code(), case["error"].as_str().unwrap());
    }
}
