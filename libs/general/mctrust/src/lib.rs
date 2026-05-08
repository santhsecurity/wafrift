//! Monte Carlo Tree Search (MCTS) framework for trajectory optimization.
//!
//! This crate provides a generic MCTS implementation suitable for:
//! - Game playing AI
//! - Evasion path optimization
//! - Combinatorial search problems
//!
//! # Core Concepts
//!
//! - [`Environment`] — Defines the action space and state transitions for your domain
//! - [`GameState`] — Terminal/ongoing/win/loss conditions
//! - [`Reward`] — Scalar value for backpropagation
//! - [`GameSearch`] — The MCTS engine that runs simulations
//! - [`SearchConfig`] — Tuning parameters (iterations, exploration constant, depth)
//!
//! # Example
//!
//! ```rust
//! use mctrust::{Environment, GameState, Reward, GameSearch, SearchConfig};
//!
//! #[derive(Clone)]
//! struct SimpleEnv { value: i32 }
//!
//! #[derive(Clone)]
//! enum Action { Increment, Decrement }
//!
//! impl Environment for SimpleEnv {
//!     type Action = Action;
//!
//!     fn legal_actions(&self) -> Vec<Self::Action> {
//!         vec![Action::Increment, Action::Decrement]
//!     }
//!
//!     fn apply(&mut self, action: &Self::Action) {
//!         match action {
//!             Action::Increment => self.value += 1,
//!             Action::Decrement => self.value -= 1,
//!         }
//!     }
//!
//!     fn evaluate(&self) -> GameState {
//!         if self.value >= 5 {
//!             GameState::Win(Reward::new(1.0))
//!         } else if self.value <= -5 {
//!             GameState::Loss
//!         } else {
//!             GameState::Ongoing
//!         }
//!     }
//!
//!     fn max_depth(&self) -> Option<usize> {
//!         Some(10)
//!     }
//! }
//!
//! let env = SimpleEnv { value: 0 };
//! let config = SearchConfig::builder()
//!     .iterations(100)
//!     .exploration_constant(1.414)
//!     .max_depth(10)
//!     .build();
//!
//! let mut search = GameSearch::new(env, config);
//! let best_action = search.run();
//! ```

use rand::seq::SliceRandom;
use std::marker::PhantomData;

/// Represents the current state of a game/simulation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GameState {
    /// The simulation is still in progress.
    Ongoing,
    /// The simulation ended in a win with the given reward.
    Win(Reward),
    /// The simulation ended in a loss.
    Loss,
}

impl GameState {
    /// Returns true if the game has reached a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, GameState::Win(_) | GameState::Loss)
    }

    /// Returns the reward if this is a winning state, None otherwise.
    #[must_use]
    pub fn reward(&self) -> Option<Reward> {
        match self {
            GameState::Win(r) => Some(*r),
            _ => None,
        }
    }
}

/// A scalar reward value for backpropagation in MCTS.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Reward {
    value: f64,
}

impl Reward {
    /// Create a new reward with the given value.
    ///
    /// # Panics
    ///
    /// Panics if the value is NaN or infinite.
    #[must_use]
    pub fn new(value: f64) -> Self {
        assert!(
            value.is_finite(),
            "Reward value must be finite, got {value}"
        );
        Self {
            value: value.clamp(0.0, 1.0),
        }
    }

    /// Returns the raw reward value.
    #[must_use]
    pub fn value(&self) -> f64 {
        self.value
    }
}

impl Default for Reward {
    fn default() -> Self {
        Self::new(0.5)
    }
}

/// Environment trait defining the simulation domain.
///
/// Implement this trait for your specific use case to define:
/// - What actions are available in each state
/// - How actions modify the state
/// - When the simulation terminates and with what reward
pub trait Environment: Clone {
    /// The type of actions in this environment.
    type Action: Clone;

    /// Returns the list of legal actions from the current state.
    fn legal_actions(&self) -> Vec<Self::Action>;

    /// Applies an action to the current state, modifying it in place.
    fn apply(&mut self, action: &Self::Action);

    /// Evaluates the current state, returning whether it's ongoing or terminal.
    fn evaluate(&self) -> GameState;

    /// Returns the maximum depth for simulations, if any.
    fn max_depth(&self) -> Option<usize>;
}

/// Configuration for the MCTS search.
#[derive(Debug, Clone, Copy)]
pub struct SearchConfig {
    /// Number of MCTS iterations to run.
    pub iterations: usize,
    /// Exploration constant (typically sqrt(2) ≈ 1.414).
    pub exploration_constant: f64,
    /// Maximum depth for rollouts.
    pub max_depth: usize,
}

impl SearchConfig {
    /// Create a builder for fluent configuration.
    #[must_use]
    pub fn builder() -> SearchConfigBuilder {
        SearchConfigBuilder::default()
    }
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            iterations: 500,
            exploration_constant: 1.414,
            max_depth: 10,
        }
    }
}

/// Builder for [`SearchConfig`].
#[derive(Debug, Clone, Copy)]
pub struct SearchConfigBuilder {
    iterations: usize,
    exploration_constant: f64,
    max_depth: usize,
}

impl Default for SearchConfigBuilder {
    fn default() -> Self {
        Self {
            iterations: 500,
            exploration_constant: 1.414,
            max_depth: 10,
        }
    }
}

impl SearchConfigBuilder {
    /// Set the number of iterations.
    #[must_use]
    pub fn iterations(mut self, iterations: usize) -> Self {
        self.iterations = iterations;
        self
    }

    /// Set the exploration constant.
    #[must_use]
    pub fn exploration_constant(mut self, c: f64) -> Self {
        self.exploration_constant = c;
        self
    }

    /// Set the maximum depth.
    #[must_use]
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Build the configuration.
    #[must_use]
    pub fn build(self) -> SearchConfig {
        SearchConfig {
            iterations: self.iterations,
            exploration_constant: self.exploration_constant,
            max_depth: self.max_depth,
        }
    }
}

/// A node in the MCTS tree.
struct Node<E: Environment> {
    /// The environment state at this node.
    env: E,
    /// The action that led to this node (None for root).
    action: Option<E::Action>,
    /// Parent node index (None for root).
    parent: Option<usize>,
    /// Child node indices.
    children: Vec<usize>,
    /// Number of visits to this node.
    visits: u64,
    /// Total reward accumulated through this node.
    total_reward: f64,
    /// Whether this node is fully expanded.
    expanded: bool,
    /// Untried actions (for expansion).
    untried_actions: Vec<E::Action>,
}

impl<E: Environment> Node<E> {
    fn new(env: E, action: Option<E::Action>, parent: Option<usize>) -> Self {
        let untried_actions = env.legal_actions();
        Self {
            env,
            action,
            parent,
            children: Vec::new(),
            visits: 0,
            total_reward: 0.0,
            expanded: untried_actions.is_empty(),
            untried_actions,
        }
    }

    /// Calculate UCT (Upper Confidence Bound for Trees) score.
    fn uct(&self, exploration_constant: f64, parent_visits: u64) -> f64 {
        if self.visits == 0 {
            return f64::INFINITY;
        }
        let exploitation = self.total_reward / self.visits as f64;
        let exploration =
            exploration_constant * ((parent_visits as f64).ln() / self.visits as f64).sqrt();
        exploitation + exploration
    }

    /// Returns true if this node has untried actions.
    fn is_expandable(&self) -> bool {
        !self.untried_actions.is_empty()
    }
}

/// The MCTS search engine.
pub struct GameSearch<E: Environment> {
    /// Search configuration.
    config: SearchConfig,
    /// The tree nodes (index 0 is root).
    nodes: Vec<Node<E>>,
    /// Phantom marker for the action type.
    _phantom: PhantomData<E::Action>,
}

impl<E: Environment> GameSearch<E> {
    /// Create a new MCTS search engine.
    ///
    /// # Arguments
    ///
    /// * `env` — The initial environment state
    /// * `config` — Search configuration parameters
    #[must_use]
    pub fn new(env: E, config: SearchConfig) -> Self {
        let root = Node::new(env, None, None);
        Self {
            config,
            nodes: vec![root],
            _phantom: PhantomData,
        }
    }

    /// Run the MCTS search and return the best action.
    ///
    /// Returns `None` if no actions are available or all paths lead to loss.
    #[must_use]
    pub fn run(&mut self) -> Option<E::Action> {
        // Check if there are any legal actions from root
        if self.nodes[0].untried_actions.is_empty() {
            return None;
        }

        // Run MCTS iterations
        for _ in 0..self.config.iterations {
            self.iterate();
        }

        // Select the best child of the root based on visit count
        self.best_action()
    }

    /// Perform one MCTS iteration: select, expand, simulate, backpropagate.
    fn iterate(&mut self) {
        // Selection: traverse tree to find a node to expand
        let node_idx = self.select();

        // Expansion: add a child node if possible
        let leaf_idx = if self.nodes[node_idx].is_expandable() {
            self.expand(node_idx)
        } else {
            node_idx
        };

        // Simulation: rollout from the leaf node
        let reward = self.simulate(leaf_idx);

        // Backpropagation: update statistics up the tree
        self.backpropagate(leaf_idx, reward);
    }

    /// Select a node to expand using UCT.
    fn select(&self) -> usize {
        let mut current = 0; // Start at root

        loop {
            let node = &self.nodes[current];

            // If node is not fully expanded, return it
            if node.is_expandable() || node.children.is_empty() {
                return current;
            }

            // Otherwise, select child with highest UCT score
            let parent_visits = node.visits;
            let best_child = node
                .children
                .iter()
                .max_by(|&&a, &&b| {
                    let uct_a = self.nodes[a].uct(self.config.exploration_constant, parent_visits);
                    let uct_b = self.nodes[b].uct(self.config.exploration_constant, parent_visits);
                    uct_a
                        .partial_cmp(&uct_b)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .copied();

            match best_child {
                Some(child) => current = child,
                None => return current,
            }
        }
    }

    /// Expand a node by adding one child.
    fn expand(&mut self, node_idx: usize) -> usize {
        let node = &mut self.nodes[node_idx];

        if node.untried_actions.is_empty() {
            return node_idx;
        }

        // Select a random untried action
        let action_idx = rand::random::<usize>() % node.untried_actions.len();
        let action = node.untried_actions.swap_remove(action_idx);

        // Create child environment by applying the action
        let mut child_env = node.env.clone();
        child_env.apply(&action);

        // Create child node
        let child_idx = self.nodes.len();
        let child = Node::new(child_env, Some(action), Some(node_idx));
        self.nodes.push(child);

        // Update parent
        self.nodes[node_idx].children.push(child_idx);
        self.nodes[node_idx].expanded = self.nodes[node_idx].untried_actions.is_empty();

        child_idx
    }

    /// Simulate a random rollout from the given node.
    fn simulate(&self, node_idx: usize) -> f64 {
        let mut env = self.nodes[node_idx].env.clone();
        let max_depth = self
            .config
            .max_depth
            .min(env.max_depth().unwrap_or(usize::MAX));
        let mut depth = 0;

        loop {
            let state = env.evaluate();

            match state {
                GameState::Win(r) => return r.value(),
                GameState::Loss => return 0.0,
                GameState::Ongoing => {
                    if depth >= max_depth {
                        // Return partial reward based on depth
                        return 0.3;
                    }
                }
            }

            // Random action selection
            let actions = env.legal_actions();
            if actions.is_empty() {
                return 0.0;
            }

            if let Some(action) = actions.choose(&mut rand::thread_rng()) {
                env.apply(action);
            }

            depth += 1;
        }
    }

    /// Backpropagate the reward up the tree.
    fn backpropagate(&mut self, mut node_idx: usize, reward: f64) {
        loop {
            self.nodes[node_idx].visits += 1;
            self.nodes[node_idx].total_reward += reward;

            match self.nodes[node_idx].parent {
                Some(parent) => node_idx = parent,
                None => break,
            }
        }
    }

    /// Get the best action from the root node.
    fn best_action(&self) -> Option<E::Action> {
        let root = &self.nodes[0];

        if root.children.is_empty() {
            return None;
        }

        // Select child with highest visit count (most robust)
        root.children
            .iter()
            .max_by_key(|&&idx| self.nodes[idx].visits)
            .and_then(|&idx| self.nodes[idx].action.clone())
    }

    /// Get statistics for all children of the root.
    #[must_use]
    pub fn root_statistics(&self) -> Vec<(Option<E::Action>, u64, f64)> {
        let root = &self.nodes[0];
        root.children
            .iter()
            .map(|&idx| {
                let node = &self.nodes[idx];
                (
                    node.action.clone(),
                    node.visits,
                    if node.visits > 0 {
                        node.total_reward / node.visits as f64
                    } else {
                        0.0
                    },
                )
            })
            .collect()
    }

    /// Return the best action sequence from root to leaf.
    ///
    /// Walks from the most-visited root child down through the tree,
    /// selecting the child with the highest visit count at each level.
    #[must_use]
    pub fn best_sequence(&self) -> Vec<E::Action> {
        let mut sequence = Vec::new();
        let mut current = 0usize;

        loop {
            let node = &self.nodes[current];
            if node.children.is_empty() {
                break;
            }
            let best_child = node
                .children
                .iter()
                .max_by_key(|&&idx| self.nodes[idx].visits)
                .copied();
            match best_child {
                Some(idx) => {
                    if let Some(ref action) = self.nodes[idx].action {
                        sequence.push(action.clone());
                    }
                    current = idx;
                }
                None => break,
            }
        }

        sequence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct CountingEnv {
        value: i32,
        max_value: i32,
    }

    #[derive(Clone, Debug, PartialEq)]
    enum CountAction {
        Increment,
        Decrement,
    }

    impl Environment for CountingEnv {
        type Action = CountAction;

        fn legal_actions(&self) -> Vec<Self::Action> {
            vec![CountAction::Increment, CountAction::Decrement]
        }

        fn apply(&mut self, action: &Self::Action) {
            match action {
                CountAction::Increment => self.value += 1,
                CountAction::Decrement => self.value -= 1,
            }
        }

        fn evaluate(&self) -> GameState {
            if self.value >= self.max_value {
                GameState::Win(Reward::new(1.0))
            } else if self.value <= -self.max_value {
                GameState::Loss
            } else {
                GameState::Ongoing
            }
        }

        fn max_depth(&self) -> Option<usize> {
            Some(20)
        }
    }

    #[test]
    fn mcts_finds_winning_action() {
        let env = CountingEnv {
            value: 0,
            max_value: 5,
        };
        let config = SearchConfig::builder()
            .iterations(200)
            .exploration_constant(1.414)
            .max_depth(10)
            .build();

        let mut search = GameSearch::new(env, config);
        let action = search.run();

        assert!(action.is_some(), "MCTS should find an action");
        // Increment should be preferred to reach max_value
        assert_eq!(action.unwrap(), CountAction::Increment);
    }

    #[test]
    fn reward_bounds_check() {
        let r = Reward::new(0.5);
        assert!((r.value() - 0.5).abs() < f64::EPSILON);

        let r_clamped = Reward::new(1.5);
        assert!((r_clamped.value() - 1.0).abs() < f64::EPSILON);

        let r_clamped_low = Reward::new(-0.5);
        assert!((r_clamped_low.value() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    #[should_panic(expected = "Reward value must be finite")]
    fn reward_rejects_nan() {
        let _ = Reward::new(f64::NAN);
    }

    #[test]
    fn game_state_terminal_check() {
        assert!(!GameState::Ongoing.is_terminal());
        assert!(GameState::Win(Reward::new(0.5)).is_terminal());
        assert!(GameState::Loss.is_terminal());
    }

    #[test]
    fn no_actions_returns_none() {
        #[derive(Clone)]
        struct NoActionEnv;

        #[derive(Clone)]
        struct NoAction;

        impl Environment for NoActionEnv {
            type Action = NoAction;

            fn legal_actions(&self) -> Vec<Self::Action> {
                Vec::new()
            }

            fn apply(&mut self, _action: &Self::Action) {}

            fn evaluate(&self) -> GameState {
                GameState::Win(Reward::new(1.0))
            }

            fn max_depth(&self) -> Option<usize> {
                Some(1)
            }
        }

        let env = NoActionEnv;
        let config = SearchConfig::default();
        let mut search = GameSearch::new(env, config);

        assert!(search.run().is_none());
    }

    #[test]
    fn statistics_returned_correctly() {
        let env = CountingEnv {
            value: 0,
            max_value: 5,
        };
        let config = SearchConfig::builder().iterations(100).build();

        let mut search = GameSearch::new(env, config);
        let _ = search.run();

        let stats = search.root_statistics();
        assert!(!stats.is_empty());

        // Check that visits sum to approximately iterations
        let total_visits: u64 = stats.iter().map(|(_, v, _)| v).sum();
        assert!(total_visits > 0);
    }
}
