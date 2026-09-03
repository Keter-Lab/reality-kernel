use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct GoldenCase {
    command: String,
    prime_intent: String,
    expected_verdict: String,
    expected_confidence_min: f64,
    expected_max_divergence_min: Option<f64>,
}

#[test]
fn rust_python_verdict_parity_gate() {
    let corpus_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("cases");
    let mut entries = fs::read_dir(&corpus_dir)
        .expect("missing parity cases directory")
        .flatten()
        .collect::<Vec<_>>();
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let body = fs::read_to_string(&path).expect("unable to read case file");
        let case: GoldenCase = serde_json::from_str(&body).expect("invalid golden json");
        let result = rk_engine_core::analyse(&case.command, &case.prime_intent, 5);
        assert_eq!(result.verdict, case.expected_verdict, "{}", path.display());
        assert!(
            result.confidence >= case.expected_confidence_min,
            "{} confidence {} < {}",
            path.display(),
            result.confidence,
            case.expected_confidence_min
        );
        if let Some(expected_div) = case.expected_max_divergence_min {
            assert!(
                result.max_divergence >= expected_div,
                "{} max_divergence {} < {}",
                path.display(),
                result.max_divergence,
                expected_div
            );
        }
    }
}
