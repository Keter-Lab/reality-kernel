use anyhow::Context;
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct GoldenCase {
    command: String,
    prime_intent: String,
    expected_verdict: String,
    expected_confidence_min: f64,
    #[serde(default)]
    expected_max_divergence_min: Option<f64>,
    #[serde(default)]
    notes: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_golden_cases_match_engine() {
        let cases_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("cases");
        let mut entries = fs::read_dir(&cases_dir)
            .expect("missing tests/parity/cases directory")
            .flatten()
            .collect::<Vec<_>>();
        entries.sort_by_key(|e| e.path());

        assert!(!entries.is_empty(), "no parity case files found");

        for entry in entries {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            let raw = fs::read_to_string(&path)
                .with_context(|| format!("failed reading {}", path.display()))
                .unwrap();
            let case: GoldenCase = serde_json::from_str(&raw)
                .with_context(|| format!("invalid JSON in {}", path.display()))
                .unwrap();

            let result = rk_engine_core::analyse(&case.command, &case.prime_intent, 5);

            assert_eq!(
                result.verdict,
                case.expected_verdict,
                "verdict mismatch for {} ({})",
                path.display(),
                case.notes
            );
            assert!(
                result.confidence >= case.expected_confidence_min,
                "confidence {} < {} for {} ({})",
                result.confidence,
                case.expected_confidence_min,
                path.display(),
                case.notes
            );
            if let Some(min_div) = case.expected_max_divergence_min {
                assert!(
                    result.max_divergence >= min_div,
                    "max_divergence {} < {} for {} ({})",
                    result.max_divergence,
                    min_div,
                    path.display(),
                    case.notes
                );
            }
        }
    }
}
