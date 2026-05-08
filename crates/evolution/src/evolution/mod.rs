//! Feedback-driven evolutionary evasion engine.

pub mod crossover;
pub mod engine;
pub mod fitness;
pub mod population;

pub use crossover::*;
pub use engine::*;
pub use fitness::*;
pub use population::*;
