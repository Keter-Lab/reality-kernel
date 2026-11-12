//! Time utilities for `rk-cli`: duration parsing for `--since`.

use anyhow::{bail, Context, Result};

/// `30s`, `15m`, `2h`, `1d` in milliseconds.
pub fn parse_since(text: &str) -> Result<i64> {
    let text = text.trim();
    if !text.is_ascii() || text.len() < 2 {
        bail!("--since {text}: expected a number and s, m, h or d");
    }
    let (num, unit) = text.split_at(text.len() - 1);
    let n: i64 = num
        .parse()
        .with_context(|| format!("--since {text}: expected a number and s, m, h or d"))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => bail!("--since {text}: expected a number and s, m, h or d"),
    };
    Ok(secs * 1000)
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
        assert!(parse_since("2w").is_err());
        assert!(parse_since("").is_err());
        assert!(parse_since("m").is_err());
        assert!(parse_since("10").is_err());
    }
}
