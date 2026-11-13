//! Time utilities for `rk-cli`: duration parsing for `--since`.

use anyhow::{anyhow, Result};

/// `30s`, `15m`, `2h`, `1d` in milliseconds. The number is one or more
/// decimal digits with no sign, and must be positive: a negative or zero
/// window would put the cutoff at or after now and silently match nothing.
/// A window too long to represent is an error rather than an overflow.
pub fn parse_since(text: &str) -> Result<i64> {
    let text = text.trim();
    let malformed = || anyhow!("--since {text}: expected a positive number and s, m, h or d");
    if !text.is_ascii() || text.len() < 2 {
        return Err(malformed());
    }
    let (num, unit) = text.split_at(text.len() - 1);
    if !num.bytes().all(|b| b.is_ascii_digit()) {
        return Err(malformed());
    }
    let unit_ms: i64 = match unit {
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return Err(malformed()),
    };
    let too_long = || anyhow!("--since {text}: too long a window");
    let n: i64 = num.parse().map_err(|_| too_long())?;
    if n == 0 {
        return Err(malformed());
    }
    n.checked_mul(unit_ms).ok_or_else(too_long)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_since() {
        assert_eq!(parse_since("30s").unwrap(), 30_000);
        assert_eq!(parse_since("15m").unwrap(), 900_000);
        assert_eq!(parse_since("2h").unwrap(), 7_200_000);
        assert_eq!(parse_since("1d").unwrap(), 86_400_000);
        assert_eq!(parse_since(" 5m ").unwrap(), 300_000);
        assert!(parse_since("2w").is_err());
        assert!(parse_since("").is_err());
        assert!(parse_since("m").is_err());
        assert!(parse_since("10").is_err());
    }

    #[test]
    fn rejects_signed_zero_and_malformed_numbers() {
        for text in ["-5m", "+5m", "0s", "00d", "5.5m", "5 m", "1e3s", "-0s", "--5m"] {
            assert!(parse_since(text).is_err(), "{text:?} was accepted");
        }
    }

    #[test]
    fn rejects_windows_too_long_to_represent() {
        // The largest day count that fits in i64 milliseconds is accepted.
        let max_days = i64::MAX / 86_400_000;
        assert_eq!(parse_since(&format!("{max_days}d")).unwrap(), max_days * 86_400_000);
        for text in [
            format!("{}d", max_days + 1),
            "99999999999999d".to_string(),
            "106751991168d".to_string(),
            format!("{}s", i64::MAX),
            "99999999999999999999s".to_string(), // does not fit in i64 at all
        ] {
            let err = parse_since(&text).unwrap_err().to_string();
            assert!(err.contains("too long"), "{text}: {err}");
        }
    }
}
