//! Multi-strategy encoding chains and aggressiveness scoring.

use super::strategy::{Strategy, all_strategies, encode};
use crate::error::EncodeError;

/// Maximum accumulated output size for layered encoding.
pub const MAX_LAYERED_OUTPUT_SIZE: usize = 8 * 1024 * 1024;

/// Apply multiple encoding strategies in sequence (layered encoding).
///
/// # Errors
/// Returns `EncodeError::PayloadTooLarge` if the input exceeds [`super::strategy::MAX_PAYLOAD_SIZE`].
/// Returns `EncodeError::LayeredOutputTooLarge` if any intermediate output
/// exceeds [`MAX_LAYERED_OUTPUT_SIZE`].
pub fn encode_layered(
    payload: impl AsRef<[u8]>,
    strategies: &[Strategy],
) -> Result<String, EncodeError> {
    let payload = payload.as_ref();
    let mut result = encode(
        payload,
        strategies.first().copied().unwrap_or(Strategy::UrlEncode),
    )?;
    // Check size IMMEDIATELY after the first encoding too — the
    // pre-fix guard only ran before the SECOND layer, so a single
    // strategy that expands dramatically (HexEncode 2×,
    // TripleUrlEncode up to 3×, GzipEncode + base64 ~1.33×) could
    // produce up to expansion_factor × MAX_PAYLOAD_SIZE bytes
    // (potentially 24 MiB from an 8 MiB input) before any guard
    // fired.
    if result.len() > MAX_LAYERED_OUTPUT_SIZE {
        return Err(EncodeError::LayeredOutputTooLarge {
            max: MAX_LAYERED_OUTPUT_SIZE,
            actual: result.len(),
        });
    }

    for strategy in strategies.iter().skip(1) {
        result = encode(&result, *strategy)?;
        if result.len() > MAX_LAYERED_OUTPUT_SIZE {
            return Err(EncodeError::LayeredOutputTooLarge {
                max: MAX_LAYERED_OUTPUT_SIZE,
                actual: result.len(),
            });
        }
    }

    Ok(result)
}

/// Generate programmatic combinations up to a depth limit.
///
/// Filters out redundant pairings (same strategy twice, or pairings that
/// produce semantically equivalent outputs).
pub fn layered_combinations(depth: usize) -> Vec<Vec<Strategy>> {
    let base = all_strategies();
    let mut results: Vec<Vec<Strategy>> = Vec::new();

    fn backtrack(
        base: &[Strategy],
        current: &mut Vec<Strategy>,
        results: &mut Vec<Vec<Strategy>>,
        depth: usize,
    ) {
        if current.len() >= 2 && current.len() <= depth {
            results.push(current.clone());
        }
        if current.len() >= depth {
            return;
        }
        for s in base {
            // Skip redundant consecutive duplicates
            if current.last() == Some(s) {
                continue;
            }
            // Skip some known-redundant pairings
            if let Some(last) = current.last()
                && redundant_pair(*last, *s)
            {
                continue;
            }
            current.push(*s);
            backtrack(base, current, results, depth);
            current.pop();
        }
    }

    let mut current = Vec::new();
    backtrack(base, &mut current, &mut results, depth);
    results
}

fn redundant_pair(a: Strategy, b: Strategy) -> bool {
    // URL + URL variants are redundant with existing single strategies
    matches!(
        (a, b),
        (
            Strategy::UrlEncode
                | Strategy::UrlEncodeLower
                | Strategy::DoubleUrlEncode
                | Strategy::TripleUrlEncode,
            Strategy::UrlEncode
        ) | (
            Strategy::UrlEncode | Strategy::UrlEncodeLower,
            Strategy::UrlEncodeLower
        ) | (Strategy::CaseAlternation, Strategy::RandomCase)
            | (Strategy::RandomCase, Strategy::CaseAlternation)
    )
}

/// Estimate how aggressive an encoding strategy is (0.0 = mild, 1.0 = extreme).
///
/// Used by the strategy engine to decide escalation order.
#[must_use]
pub fn aggressiveness(strategy: Strategy) -> f64 {
    match strategy {
        Strategy::CaseAlternation => 0.05,
        Strategy::RandomCase => 0.08,
        Strategy::UrlEncode => 0.1,
        Strategy::UrlEncodeLower => 0.1,
        Strategy::WhitespaceInsertion => 0.12,
        Strategy::SqlCommentInsertion => 0.12,
        Strategy::SpaceToPlus => 0.13,
        Strategy::SpaceToRandomBlank => 0.14,
        Strategy::SpaceToComment => 0.15,
        Strategy::SpaceToDash => 0.15,
        Strategy::SpaceToHash => 0.15,
        Strategy::HtmlEntityEncode => 0.2,
        Strategy::HtmlEntityDecimalEncode => 0.2,
        Strategy::DoubleUrlEncode => 0.25,
        Strategy::UnicodeEncode => 0.3,
        Strategy::IisUnicodeEncode => 0.3,
        Strategy::JsonEncode => 0.3,
        Strategy::NullByte => 0.35,
        Strategy::FullwidthEncode => 0.36,
        Strategy::HomoglyphEncode => 0.37,
        Strategy::PercentagePrefix => 0.4,
        Strategy::ParameterPollution => 0.45,
        Strategy::TripleUrlEncode => 0.5,
        Strategy::MysqlVersionedComment => 0.55,
        Strategy::Base64Encode => 0.6,
        Strategy::Base64UrlEncode => 0.6,
        Strategy::OverlongUtf8 => 0.7,
        Strategy::OverlongUtf8More => 0.75,
        Strategy::HexEncode => 0.8,
        Strategy::Utf7Encode => 0.85,
        Strategy::BetweenObfuscation => 0.88,
        Strategy::UnmagicQuotes => 0.9,
        Strategy::ChunkedSplit => 0.92,
        Strategy::GzipEncode => 0.95,
        Strategy::DeflateEncode => 0.95,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::strategy::all_strategies;

    #[test]
    fn encode_layered_basic() {
        let result =
            encode_layered("A", &[Strategy::UrlEncode, Strategy::DoubleUrlEncode]).unwrap();
        assert!(result.contains('%'));
    }

    #[test]
    fn encode_layered_size_limit() {
        // Use a non-unreserved char so URL encoding multiplies size by ~3x each pass
        let big = "!".repeat(5 * 1024 * 1024);
        let result = encode_layered(
            &big,
            &[
                Strategy::UrlEncode,
                Strategy::UrlEncode,
                Strategy::UrlEncode,
            ],
        );
        assert!(matches!(
            result,
            Err(EncodeError::LayeredOutputTooLarge { .. })
        ));
    }

    #[test]
    fn layered_combinations_depth_2() {
        let combos = layered_combinations(2);
        assert!(!combos.is_empty());
        // All combos should have length 2
        assert!(combos.iter().all(|c| c.len() == 2));
    }

    #[test]
    fn layered_combinations_no_consecutive_duplicates() {
        let combos = layered_combinations(3);
        for combo in combos {
            for window in combo.windows(2) {
                assert_ne!(window[0], window[1], "no consecutive duplicates: {combo:?}");
            }
        }
    }

    #[test]
    fn aggressiveness_ordering() {
        let strategies = all_strategies();
        for i in 1..strategies.len() {
            assert!(
                aggressiveness(strategies[i - 1]) <= aggressiveness(strategies[i]),
                "aggressiveness should be non-decreasing"
            );
        }
    }

    #[test]
    fn encode_layered_empty_strategies() {
        let result = encode_layered("hello", &[]).unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn encode_layered_single_strategy() {
        let result = encode_layered("A<", &[Strategy::UrlEncode]).unwrap();
        assert_eq!(result, "A%3C");
    }

    #[test]
    fn layered_combinations_depth_1_returns_empty() {
        let combos = layered_combinations(1);
        assert!(combos.is_empty());
    }

    #[test]
    fn aggressiveness_in_valid_range() {
        for &s in all_strategies() {
            let a = aggressiveness(s);
            assert!(
                (0.0..=1.0).contains(&a),
                "aggressiveness for {s:?} out of range: {a}"
            );
        }
    }
}
