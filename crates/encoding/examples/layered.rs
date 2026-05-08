//! Layered encoding example — chaining multiple encodings for hardened WAFs.

use wafrift_encoding::{
    Strategy, aggressiveness, all_strategies, encode, encode_layered, layered_combinations,
};

fn main() {
    let payload = "SELECT * FROM users WHERE id=1";

    println!("Original payload:");
    println!("  {}", payload);
    println!();

    // Layered encoding: apply multiple strategies in sequence
    // This bypasses WAFs that decode once or twice before matching
    let layered = encode_layered(
        payload,
        &[Strategy::SqlCommentInsertion, Strategy::UrlEncode],
    )
    .unwrap();

    println!("Layered (SQL comments + URL encoding):");
    println!("  {}", layered);
    println!();

    // More aggressive example: triple-layer for paranoid WAFs
    let aggressive = encode_layered(
        payload,
        &[
            Strategy::CaseAlternation,
            Strategy::WhitespaceInsertion,
            Strategy::DoubleUrlEncode,
        ],
    )
    .unwrap();

    println!("Aggressive 3-layer (case + whitespace + double URL):");
    println!(
        "  {}",
        aggressive[..aggressive.len().min(80)].to_string() + "..."
    );
    println!();

    // Show pre-defined useful combinations
    println!("Pre-defined useful combinations:");
    for (i, combo) in layered_combinations(2).iter().enumerate() {
        println!("  {}. {:?}", i + 1, combo);
    }
    println!();

    // Demo: escalation ladder
    println!("Escalation ladder (least to most aggressive):");
    let strategies = all_strategies();
    for (i, strategy) in strategies.iter().take(5).enumerate() {
        let score = aggressiveness(*strategy);
        let result = encode(payload, *strategy).unwrap();
        println!(
            "  {}. {:?} (score: {:.1}): {}...",
            i + 1,
            strategy,
            score,
            &result[..result.len().min(40)]
        );
    }
    println!("     ... ({} more strategies)", strategies.len() - 5);
}
