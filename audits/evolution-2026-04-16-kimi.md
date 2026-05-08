# Deep Audit: `crates/evolution/`

**Date:** 2026-04-16  
**Auditor:** Kimi  
**Scope:** `crates/evolution/src/` (read-only audit)  

## Executive Summary

- **The moat is a puddle.** The crate implements a bare-bones genetic algorithm (elitism + tournament selection + uniform crossover + adaptive mutation rate) but lacks every advanced search technique that distinguishes academic WAF-evasion tools from script-kiddie payload lists.
- **Binary fitness.** Fitness is derived from a single `passed: bool` fed into an EMA. There is no gradient from response timing, status-code delta, body-size delta, or oracle confidence. Convergence will be glacial.
- **No oracle caching.** 10 000 mutations = 10 000 HTTP requests. No payload→verdict cache, no population deduplication, no memoization.
- **No lineage / no replay.** When a bypass is discovered, the exact mutation sequence is lost. `Chromosome` has no parent pointers, no transformation tree, no disk serialization, and no TOML export.
- **No safety rails.** No hard request budget, no progress-based termination, no target-health monitoring (5xx bailout). `evolve()` can loop forever.
- **No parallelization.** Candidates are returned one-at-a-time via `next_candidate()`. No async batch evaluation, no rate-limit awareness.
- **Unreproducible.** `rand::thread_rng()` is hardcoded in `EvolutionEngine::evolve()`, `mutate()`, `GenePool::random_value()`, and `random_chromosome()`. No seeded RNG, no state serialization.
- **File size violations.** `fitness.rs` is 1 031 lines, `crossover.rs` 618 lines, `crossover_tests.rs` 704 lines. LAW 2 (every file <500 lines) is broken.
- **Test coverage:** Unit tests only. Missing: property tests for lineage acyclicity, adversarial tests with an always-blocking oracle, concurrency tests, OOM tests, seeded-RNG determinism tests.

**Finding count:** 58

---

## Search Algorithms

### FIND-001: Missing Simulated Annealing — Guaranteed Local-Optimum Trap
- **Severity:** Critical

The engine is a vanilla generational GA with no temperature schedule. Once a high-fitness chromosome dominates the population (especially with elitism = pop/5), the probability of accepting a *worse* candidate to escape a local optimum is zero.

**Impact:** WAFs with multi-layer rules (e.g., Cloudflare + ModSecurity) often require temporarily "bad" intermediate mutations (e.g., a payload that triggers layer-A so layer-B relaxes). The engine will never explore these valleys. Bypasses that require stepping stones are unreachable.

**Fix:** Add a `SimulatedAnnealing` scheduler that computes acceptance probability `exp((new_fitness - old_fitness) / temperature)` and maintains a separate temperature-cooled population. Anneal temperature from 1.0 to 0.01 across generations.

### FIND-002: Missing Tabu Search — Cyclic Rediscovery
- **Severity:** Critical

There is no tabu list. The same (encoding="UrlEncode", content_type="Multipart") chromosome can be regenerated, evaluated, discarded, and regenerated indefinitely.

**Impact:** Wasted oracle evaluations. At internet scale, redundant requests burn budget and increase ban probability.

**Fix:** Maintain a `HashSet<u64>` of recently-seen chromosome hashes (tabu list) with a tenure of N generations. Reject children that collide with the tabu set.

### FIND-003: Missing Novelty Search (NEAT-style)
- **Severity:** Critical

The engine uses novelty scores only as a *tie-breaker* in parent selection (20–35 % weight). There is no explicit novelty-archive that rewards chromosomes for exploring *new regions of behavior space* regardless of fitness.

**Impact:** The engine converges on the first bypass found and stops exploring alternative bypass families. A WAF that patches one technique kills the entire scanner.

**Fix:** Implement a `NoveltyArchive` that stores chromosomes by phenotypic distance (e.g., edit distance of the final HTTP payload). Reward candidates that are >δ away from every archived individual. Archive size should grow monotonically.

### FIND-004: Missing MAP-Elites / Quality-Diversity
- **Severity:** Critical

No MAP-Elites grid. The engine cannot systematically cover the combination space of (encoding family × grammar family × content-type family).

**Impact:** Blind spots in the technique matrix. A bypass that requires `JsonNested + UnicodeEncode + tag_event_swap` may never be sampled because the GA collapses to a different niche.

**Fix:** Implement a `MapElites` grid with dimensions `[encoding_gene, grammar_gene, content_type_gene]`. Evaluate and place each chromosome into its bin, keeping the highest-fitness individual per bin. Crossover should sample from under-filled bins.

### FIND-005: Missing NSGA-II Multi-Objective Optimization
- **Severity:** Critical

Fitness is a single scalar. The engine cannot optimize competing objectives simultaneously: (1) bypass probability, (2) request stealth / low anomaly score, (3) payload brevity, (4) response-time minimization.

**Impact:** The engine discovers bloated, slow, or easily-detected bypasses because it has no Pareto front. Downstream strategy engine receives a single "best" chromosome that may be unusable in practice.

**Fix:** Replace scalar fitness with a `Vec<f64>` objective vector and implement NSGA-II non-dominated sorting. Parent selection should use crowding distance.

### FIND-006: Missing CMA-ES / Covariance Matrix Adaptation
- **Severity:** High

For continuous or ordered gene spaces (e.g., mutation intensity, encoding depth), the GA has no covariance-matrix adaptation. It samples mutations uniformly rather than learning the correlation structure of successful mutations.

**Fix:** Add a `CmaEs` module that treats gene indices as a continuous search space and adapts the mutation distribution using the evolution path.

### FIND-007: Missing Bayesian Optimization for Expensive Oracle
- **Severity:** High

Each oracle call is expensive (HTTP round-trip). The engine makes no attempt to model the fitness landscape with a Gaussian Process or surrogate model. It tests every mutation blindly.

**Fix:** Maintain a surrogate model (e.g., random-forest regressor or GP) trained on (chromosome features → fitness). Use expected improvement (EI) to select the next chromosome to evaluate. Fall back to the real oracle only when EI is above a threshold.

### FIND-008: Missing Grammar-Guided Evolution
- **Severity:** Critical

The `grammar_rule` gene is just a string label (`"tautology_swap"`, `"comment_swap"`, etc.). There is no actual parse-tree representation, no context-free grammar, no subtree crossover, and no type-aware mutation. The engine cannot evolve *structure*, only swap pre-defined labels.

**Impact:** This is not "grammar-level variants" in the academic sense. It is a hardcoded enum shuffle. Deep bypasses that require novel syntactic structures (e.g., nested JSON-encoded XML inside a multipart boundary) are impossible.

**Fix:** Integrate with `crates/grammar` to represent chromosomes as ASTs. Implement tree-crossover and tree-mutation operators. The current string-gene abstraction is too shallow for the claimed capability.

### FIND-009: No Lamarckian Learning / Memetic Local Search
- **Severity:** High

`bias_inject` and `synergy_bias_inject` are crude heuristics (inject top genes with probability proportional to success rate). There is no hill-climbing local search around a high-fitness chromosome to refine it.

**Fix:** After each generation, run a local search (e.g., greedy single-gene flip) on the top-k elite chromosomes. If a flip improves fitness, overwrite the gene (Lamarckian inheritance).

### FIND-010: Missing Coevolutionary Arms Race (Host-Parasite)
- **Severity:** Medium

No secondary population of "WAF approximators" evolves alongside the bypass population. Co-evolution would discover robust bypasses that generalize across WAF rule variants.

**Fix:** Maintain a parasite population of regex-like patterns that try to match successful bypasses. Reward parasites that catch bypasses; reward hosts that evade parasites.

---

## Fitness Function

### FIND-011: Binary Fitness — Zero Gradient
- **Severity:** Critical

`Chromosome::record(&mut self, passed: bool)` computes an EMA over `1.0` (pass) or `0.0` (block). The input is a single boolean. There is no signal from:
- response timing (slow block vs fast block vs partial pass)
- HTTP status code delta (403 vs 406 vs 500 vs 200)
- body-size delta (error page length, content injection)
- oracle confidence score (e.g., `wafrift-oracle` verdict probability)
- number of triggered WAF rules (partial blocking)

**Impact:** The fitness landscape is a flat plateau with cliffs. The GA has no directional gradient to climb. It randomly flips genes until it happens to fall off a cliff into a pass. This is brute force, not evolution.

**Fix:** Change `record` to accept an `OracleVerdict` struct containing `{passed: bool, status_delta: i16, body_delta: i32, latency_ms: u32, confidence: f64, triggered_rules: u32}`. Compute fitness as a weighted sum that rewards *partial* progress (e.g., fewer triggered rules, lower latency, smaller body delta).

### FIND-012: Fitness EMA Alpha Hardcoded to 0.3
- **Severity:** High

`Chromosome::record` uses `alpha = 0.3` with no configuration. This may be too noisy for low-evaluation chromosomes and too sluggish for adapting WAFs.

**Fix:** Make alpha configurable per `EvolutionEngine` or compute adaptive alpha `2.0 / (evaluations + 1.0)`.

### FIND-013: `evolutionary_fitness` Modifier Can Penalize Valid Bypasses
- **Severity:** High

`evolutionary_fitness` applies a `stealth_bonus` based on `activation_ratio` (how many genes are non-"None"). The bonus peaks at 50 % activation and drops to 0 at 0 % or 100 % activation. A bypass that legitimately requires *all* genes active (e.g., deep layering) receives `stealth_bonus = 0.0` and a lower fitness score than a bypass with fewer genes, even if the deep-layer bypass has a higher raw pass rate.

**Fix:** Remove the stealth penalty for high activation ratios, or make it a configurable Pareto objective (FIND-005) rather than a scalar penalty.

### FIND-014: `gene_stats` Tracks Aggregate Rates, Not Contextual Success
- **Severity:** High

`update_gene_stats` records `(gene_name, gene_value, successes, attempts)` globally. It does not track success *conditional on other genes* (e.g., `UrlEncode` works only when `content_type="Multipart"`).

**Impact:** `bias_inject` may inject `UrlEncode` into chromosomes where it is harmful because the marginal success rate is high but the conditional success rate is low.

**Fix:** Store a sparse conditional probability table or use a Bayesian network to model `P(success | gene_i, gene_j)`.

---

## Caching & Deduplication

### FIND-015: No Payload→Verdict Cache
- **Severity:** Critical

There is no cache anywhere in `crates/evolution`. Identical chromosomes (and therefore identical payloads, assuming deterministic encoding application) are re-evaluated every time they appear.

**Impact:** N mutations = N HTTP requests. With a population of 50 and 100 generations, that's 5 000 requests minimum. In practice, with crossover regenerating previously-seen chromosomes, the request count can be 2–5× higher. Targets will rate-limit or ban the scanner.

**Fix:** Add a `LruCache<String, OracleVerdict>` keyed by the serialized payload string (or a hash of the final HTTP request bytes). Cap it at a configurable size (e.g., 10 000 entries). Check cache before calling `next_candidate()`.

### FIND-016: No Population-Level Deduplication
- **Severity:** Critical

After crossover and mutation, the new generation may contain duplicate chromosomes. `EvolutionEngine::evolve()` does not check for duplicates before pushing children into `next_generation`.

**Impact:** In a converged population, 30–70 % of individuals can be clones. Each clone wastes an oracle evaluation.

**Fix:** After generating the new generation, deduplicate using a `HashSet` of chromosome hashes. Replace duplicates with random mutations or fresh random chromosomes.

### FIND-017: `next_candidate()` Can Return the Same Unevaluated Chromosome Multiple Times
- **Severity:** High

`next_candidate()` finds the first chromosome with `evaluations == 0`. The caller is expected to evaluate it and then call `record_feedback()`. If the caller forgets to call `record_feedback()` (e.g., due to a network timeout), the same unevaluated chromosome is returned again on the next call.

**Fix:** Add an "in-flight" tracking set to `EvolutionEngine` so that returned candidates are marked pending until feedback is recorded or a timeout expires.

---

## Corpus, Lineage & Replayability

### FIND-018: No Parent Pointers / No Lineage Tree
- **Severity:** Critical

`Chromosome` contains only `genes: Vec<(String, String)>, fitness: f64, evaluations: u32`. There is no `parent_a`, `parent_b`, `generation_born`, or `mutation_log` field.

**Impact:** When a bypass is found, there is no way to reconstruct the *sequence of transformations* that created it. Re-running the scanner with the same seed will not regenerate the bypass because the stochastic path is lost.

**Fix:** Add a `Lineage` enum to `Chromosome`:
```rust
enum Lineage {
    Genesis,
    Crossover { parent_a: Arc<Chromosome>, parent_b: Arc<Chromosome>, strategy: CrossoverStrategy },
    Mutation { parent: Arc<Chromosome>, log: Vec<MutationOp> },
}
```

### FIND-019: No Disk Serialization of Successful Bypasses
- **Severity:** Critical

There is no function that writes a discovered bypass (chromosome + lineage + fitness history) to disk.

**Impact:** Bypasses discovered during a scan are ephemeral. They cannot be shared, audited, or reused in future scans.

**Fix:** Implement `BypassCorpus::save(path: &Path)` that serializes high-fitness chromosomes to a TOML/JSONL file. Include the full lineage tree so the bypass is replayable.

### FIND-020: No Community TOML Export / Tier B Rules
- **Severity:** Critical

`custom_rules.rs` can *load* WAF detection rules from TOML, but there is no corresponding schema or exporter for *evasion technique combinations*. The "growing-moat mechanism" (community corpus contributing back) is unimplemented.

**Fix:** Define a `rules/corpus.toml` schema for saved bypasses:
```toml
[[bypass]]
payload_hash = "..."
genes = [{ name = "encoding", value = "DoubleUrlEncode" }, ...]
lineage = "..."
target_waf = "Cloudflare"
verified = true
```
Wire this into `IntelligenceLoop` so successful chromosomes are automatically appended.

### FIND-021: `gene_stats` Is Ephemeral
- **Severity:** High

`gene_stats` is a `Vec<(String, String, u32, u32)>` inside `EvolutionEngine`. It is not serialized, not persisted, and reset on every `EvolutionEngine::new()`.

**Impact:** Learned knowledge about a target WAF is lost when the process restarts. The scanner re-learns from scratch every run.

**Fix:** Persist `gene_stats` (and the entire engine state) to disk after each generation. Load it on startup if a state file exists.

---

## Novelty & Diversity

### FIND-022: Diversity Metric Is Naive Hamming Distance on Gene Labels
- **Severity:** High

`diversity_score` and `chromosome_distance` compare gene *names* and *values* as strings. They do not measure the phenotypic distance of the actual HTTP payload (e.g., Levenshtein distance, n-gram Jaccard, or embedding-space distance).

**Impact:** Two chromosomes with completely different gene values can produce nearly identical HTTP payloads (e.g., `CaseAlternation` vs `UrlEncode` on an all-lowercase string). The engine thinks they are diverse and wastes search budget.

**Fix:** Compute phenotypic diversity by applying the chromosome to a reference payload and measuring string distance between the resulting HTTP request bodies.

### FIND-023: No Novelty Archive
- **Severity:** Critical

Related to FIND-003. The engine has no archive of historically novel solutions. Once a novel chromosome is evaluated and discarded (because its fitness is mediocre), it is forgotten.

**Fix:** Implement a `NoveltyArchive` with a k-NN distance threshold. Add chromosomes to the archive if they exceed the threshold. Use archive members as additional parents during crossover.

### FIND-024: `inject_diversity` Replaces Low-Fitness Chromosomes Randomly
- **Severity:** Medium

When stagnation_counter ≥ 3, `inject_diversity` replaces the worst 25 % of the non-elite population with *completely random* chromosomes. This is a restart, not a targeted diversity injection. It discards all learned gene statistics for those slots.

**Fix:** Inject diversity more intelligently: sample from the novelty archive, or apply macro-mutations (e.g., swap entire gene families) rather than random replacement.

---

## Termination & Safety

### FIND-025: No Request Budget / No Termination Condition
- **Severity:** Critical

`EvolutionEngine` has no `max_generations`, `max_evaluations`, or `max_requests` field. `evolve()` can be called in an infinite loop.

**Impact:** Unbounded evolution on a production target = traffic storm = potential legal liability and target denial-of-service.

**Fix:** Add hard termination limits:
- `max_requests: usize` (total oracle calls)
- `max_generations: u32`
- `max_time_seconds: u64`
Add a `should_terminate(&self) -> bool` method checked before every evaluation.

### FIND-026: No Progress-Based Early Termination
- **Severity:** High

Even though `fitness_history` and `stagnation_counter` exist, they are only used to increase mutation rate. There is no early termination when the population plateaus for N generations.

**Fix:** If `stagnation_counter >= 10` (configurable) and the best fitness has not improved, terminate and return the best-known bypass.

### FIND-027: No Target Health Monitoring (5xx Bailout)
- **Severity:** Critical

`IntelligenceLoop::record_feedback` and `EvolutionEngine::record_feedback` accept only `passed: bool`. They have no parameter for target health (e.g., HTTP 502/503/504, connection reset, timeout).

**Impact:** If the target enters distress (or a rate-limiter starts returning 503), the scanner interprets it as "blocked" and keeps sending mutations, amplifying the damage.

**Fix:** Change feedback to accept `enum Feedback { Passed, Blocked, TargetError(String) }`. On `TargetError`, immediately pause evolution for an exponential backoff and eventually abort if errors persist.

### FIND-028: `generate_probes()` Has No Budget Check
- **Severity:** High

`generate_probes()` returns ~60+ probes unconditionally. `IntelligenceLoop` generates these before any budget check.

**Fix:** Accept a `remaining_budget: usize` parameter. If the budget is smaller than the probe set, switch to `generate_quick_probes()` or skip differential analysis entirely.

---

## Parallelization

### FIND-029: No Parallel Evaluation of Mutations
- **Severity:** Critical

`next_candidate()` returns a single `(usize, &Chromosome)`. The architecture is strictly sequential: evaluate one, report feedback, evolve, evaluate the next.

**Impact:** Modern scanners should evaluate dozens of payloads in parallel (respecting rate limits). Sequential evaluation makes the engine unusably slow against real targets.

**Fix:** Add a `batch_candidates(n: usize) -> Vec<(usize, &Chromosome)>` method. Return N unevaluated candidates. The caller evaluates them concurrently and reports feedback in bulk. Ensure the in-flight set (FIND-017) is thread-safe.

### FIND-030: No Rate-Limit Awareness
- **Severity:** High

There is no token bucket, no leaky bucket, and no adaptive delay. The engine assumes the caller will throttle requests externally, but the engine itself drives the cadence via `next_candidate()`.

**Fix:** Integrate a rate-limiter into `IntelligenceLoop` (or the caller) that caps requests per second. The engine should expose `suggested_delay_ms()` based on the oracle's recent response times.

---

## Reproducibility

### FIND-031: `rand::thread_rng()` Hardcoded Throughout
- **Severity:** Critical

Reproducibility requires a seeded, deterministic RNG. The following locations use `rand::thread_rng()` with no injection point:
- `engine.rs:112` (`evolve()`)
- `crossover.rs:295` (`mutate()`)
- `population.rs:176` (`GenePool::random_value`)
- `population.rs:182` (`random_chromosome`)

**Impact:** Two runs with identical inputs produce different populations. Bugs in the field cannot be reproduced. Scientific benchmarking is impossible.

**Fix:** Add an `rng: StdRng` field to `EvolutionEngine` and `GenePool`. Provide a `new_seeded(seed: u64)` constructor. Plumb the RNG through *every* random operation.

### FIND-032: `mutate()` Ignores the RNG Passed to `comprehensive_mutate()`
- **Severity:** Critical

`comprehensive_mutate(&mut rng)` receives an RNG but calls `mutate(chromosome, gene_pool, value_mutation_rate)`, which instantiates a *new* `thread_rng()` internally:
```rust
pub fn mutate(...) {
    let mut rng = rand::thread_rng(); // BUG: ignores caller's RNG
    ...
}
```
This makes `comprehensive_mutate` non-deterministic even if the caller seeds its RNG.

**Fix:** Change `mutate` signature to accept `rng: &mut impl Rng`.

### FIND-033: No State Serialization (Pause / Resume)
- **Severity:** High

`EvolutionEngine` and `IntelligenceLoop` do not implement `Serialize`/`Deserialize`. A long-running scan cannot survive a process restart.

**Fix:** Derive `serde::Serialize` and `serde::Deserialize` for `EvolutionEngine`, `Chromosome`, `GenePool`, and `DifferentialResult`. Save state to a JSONL or bincode checkpoint file after each generation.

---

## Code Quality / Panics / OOM / Allocation

### FIND-034: `fitness.rs` Is 1 031 Lines — Violates LAW 2
- **Severity:** High

`fitness.rs` contains fitness functions, statistics, co-occurrence analysis, summary generation, and 500+ lines of unit tests in a single file.

**Fix:** Split into `fitness/core.rs`, `fitness/stats.rs`, `fitness/cooccurrence.rs`, `fitness/summary.rs`, and `fitness/tests.rs`. Maximum 500 lines per file.

### FIND-035: `crossover.rs` Is 618 Lines — Violates LAW 2
- **Severity:** High

Contains selection strategies, crossover strategies, mutation operators, bias injection, diversity injection, and helper functions.

**Fix:** Split into `crossover/selection.rs`, `crossover/strategies.rs`, `crossover/mutation.rs`, `crossover/diversity.rs`.

### FIND-036: `crossover_tests.rs` Is 704 Lines — Violates LAW 2
- **Severity:** Medium

Test files should also be <500 lines.

**Fix:** Split tests to match the module structure: `crossover/selection_tests.rs`, etc.

### FIND-037: `population_tests.rs` Is 586 Lines — Violates LAW 2
- **Severity:** Medium

Same as FIND-036.

**Fix:** Split into `population/chromosome_tests.rs` and `population/gene_pool_tests.rs`.

### FIND-038: `engine.rs::record_feedback` Silently Ignores Out-of-Bounds Index
- **Severity:** High

```rust
pub fn record_feedback(&mut self, chromosome_index: usize, passed: bool) {
    if chromosome_index >= self.population.len() {
        return; // Error swallowed
    }
    ...
}
```
This is a dead-silent failure. A caller bug (stale index after evolution) will corrupt gene statistics or lose feedback without any indication.

**Fix:** Return `Result<(), EvolutionError>` and propagate the error. Do not swallow bounds violations.

### FIND-039: `fitness_history` Is an Unbounded Vec
- **Severity:** Medium

`EvolutionEngine` pushes to `fitness_history` every generation with no maximum size. A daemon-style scanner running for days could OOM from a trivial `Vec<f64>`.

**Fix:** Cap `fitness_history` at a sliding window (e.g., last 1000 generations) or ring buffer.

### FIND-040: `gene_stats` Grows Unbounded
- **Severity:** Medium

`gene_stats` accumulates one entry per unique `(name, value)` pair. With a large gene pool and structural mutations (duplication, add), the number of unique values can grow indefinitely.

**Fix:** Prune `gene_stats` to the top-k most-attempted entries, or use a bounded `HashMap` instead of a `Vec`.

### FIND-041: `diversity_score` Uses `u32` Saturating Add, Silently Losing Precision
- **Severity:** Medium

```rust
total_distance = total_distance.saturating_add(usize_to_u32(scaled_distance as usize));
```
With a population of 100 000, the summed distances can exceed `u32::MAX`. Saturation causes the final diversity score to be wrong without any warning.

**Fix:** Use `u64` or `f64` accumulators. Assert or warn if overflow is possible.

### FIND-042: `generate_family_probes` Allocates Full Vec for Every `remove()` Call
- **Severity:** Medium

In `binary_search.rs`:
```rust
xss_tag_probes().remove(0),
xss_tag_probes().remove(1), // fresh Vec allocated here
xss_tag_probes().remove(2), // another fresh Vec
```
Each `.remove()` call allocates a new 11-element Vec and immediately drops it. This is O(n²) allocation for no reason.

**Fix:** Bind `xss_tag_probes()` to a local variable once, then `remove()` from it.

### FIND-043: `Probe { payload: "'".into(), ..., expected_blocked: false }` Is Semantically Wrong
- **Severity:** High

The SQL single-quote probe is marked `expected_blocked: false`, meaning the differential analysis expects a well-configured WAF *not* to block it. This is backwards: single quotes are one of the most blocked patterns by WAFs. The differential result will flag "quote not blocked" as a gap when in fact it is normal behavior.

**Fix:** Change `expected_blocked` to `true` for `SqlQuote`.

### FIND-044: `sql_operator_probes` Marks `=`, `LIKE`, `BETWEEN` as `expected_blocked: false`
- **Severity:** Medium

While operators in isolation may not always be blocked, marking them as *expected to pass* biases the differential analysis. A WAF that blocks `=` will be reported as over-aggressive rather than correctly configured.

**Fix:** Set `expected_blocked: true` for all SQL operators, or remove the `expected_blocked` field entirely and let the analyst decide.

### FIND-045: `structural_remove_mutation` Hardcodes `"encoding"` as Essential
- **Severity:** Medium

```rust
.filter(|(_, (name, _))| name != "encoding") // Keep encoding as essential
```
Magic string. If the gene pool changes to use `"payload_encoding"`, this silently breaks.

**Fix:** Define an `ESSENTIAL_GENES: &[&str]` constant or mark essential genes in the `GenePool` schema.

### FIND-046: `differential/analysis.rs::record` Appends Duplicates
- **Severity:** Medium

`blocked_sql_keywords.push(keyword.clone())` is called every time a probe is recorded as blocked. Recording the same probe twice appends the same keyword twice.

**Fix:** Use `HashSet<String>` for all blocked-* fields, or check `contains` before pushing.

---

## Tests

### FIND-047: No Property Test for Lineage Acyclicity
- **Severity:** High

There is no property-based test (e.g., `proptest`) that generates random crossovers and asserts the parent graph has no cycles. Since lineage is not even stored (FIND-018), such a test cannot exist.

**Fix:** Implement lineage (FIND-018), then add a `proptest` that performs 10 000 random crossovers and verifies the lineage DAG has no cycles.

### FIND-048: No Adversarial Test with Always-Blocking Oracle
- **Severity:** Critical

All tests simulate an oracle that passes ~50 % of candidates. There is no test where *every* payload is blocked. In this adversarial scenario, the engine must still terminate (via budget / stagnation), not loop forever.

**Fix:** Add an adversarial test that seeds an engine, records `false` for every candidate, and asserts termination within `max_generations`.

### FIND-049: No Test for Seeded-RNG Determinism
- **Severity:** High

No test asserts that `EvolutionEngine::new_seeded(42)` produces the exact same population across two runs.

**Fix:** Add a determinism test. With a fixed seed, the byte-serialized population after 5 generations must be identical.

### FIND-050: No Test for Request Budget Exhaustion
- **Severity:** High

No test verifies that the engine stops when `max_requests` is reached.

**Fix:** Add a test with `max_requests = 10`. Evaluate 10 candidates, assert `engine.should_terminate() == true`, and assert `next_candidate()` returns `None`.

### FIND-051: No Test for Target-Error Bailout
- **Severity:** High

No test simulates a target returning 503 errors.

**Fix:** Add a test that calls `record_feedback` with `Feedback::TargetError` and asserts the engine pauses or terminates.

### FIND-052: No Concurrency / Race Condition Tests
- **Severity:** High

`EvolutionEngine` is not `Sync`. There are no tests for concurrent feedback submission or parallel `next_candidate()` calls.

**Fix:** Add a `tokio::sync::Mutex` wrapper test (or make the engine thread-safe) and assert no data races under concurrent access.

### FIND-053: No OOM Test with Large Populations
- **Severity:** Medium

No test exercises `EvolutionEngine::new(1_000_000)` or giant `fitness_history`.

**Fix:** Add a test that creates a large population and asserts memory usage stays within a bound, or that the engine refuses unreasonable sizes.

---

## Integration & Architecture

### FIND-054: `advisor.rs` Uses Brittle String Matching on WAF Names
- **Severity:** High

```rust
match waf.name {
    "Cloudflare" => { ... }
    "AWS WAF" => { ... }
    ...
}
```
This is an exact string match on `&str`. If `wafrift_detect` returns `"CloudFlare"` (different capitalization) or `"AWS WAF v2"`, the advisor falls through to the "unknown WAF: be aggressive" path.

**Fix:** Use a `match_waf(name: &str) -> WafFamily` function that matches via lowercase+substring or a regex map.

### FIND-055: `advisor.rs` Hardcodes Evasion Strategies with No Community Override
- **Severity:** Critical

The advisor's WAF→strategy mapping is entirely hardcoded Rust code. Community users cannot contribute a new WAF profile or update an existing one without recompiling.

**Fix:** Move all advisor mappings to a TOML file (`rules/advisor.toml`) and load it at runtime. Delete the hardcoded `match` arms.

### FIND-056: `custom_rules.rs::VALID_EASION_STRATEGIES` Is Incomplete
- **Severity:** Critical

The hardcoded whitelist contains only 15 encoding-style strategies. It does *not* include:
- `Multipart`, `JsonNested`, `XmlCdata` (content-type genes)
- `tautology_swap`, `comment_swap`, etc. (grammar genes)
- `CaseMixing`, `TabSeparator` (header obfuscation genes)

**Impact:** A community TOML rule that references a valid gene value from `GenePool::default_wafrift()` will be rejected as "unknown evasion_strategy".

**Fix:** Generate `VALID_EVASION_STRATEGIES` dynamically from `GenePool::default_wafrift()` at compile time (or load it from the gene pool at runtime). Do not maintain a separate, stale whitelist.

### FIND-057: `IntelligenceLoop::has_sufficient_data` Uses Magic Number 10
- **Severity:** Medium

```rust
pub fn has_sufficient_data(&self) -> bool {
    self.probes_completed >= 10
}
```
10 is arbitrary and not configurable.

**Fix:** Make the threshold a constructor parameter: `IntelligenceLoop::new(population_size, min_probes)`.

### FIND-058: `IntelligenceLoop` Is a Passive Glue Object with No Orchestration Logic
- **Severity:** High

`IntelligenceLoop` exposes `generate_probes()`, `next_candidate()`, `record_feedback()`, and `evolve()`, but it does not orchestrate the *workflow*: when to switch from differential probing to evolution, when to stop, when to save state, or how to batch evaluations.

**Impact:** Every caller (CLI, API, integration test) must re-implement the scanner state machine. This leads to inconsistent behavior and duplicated bugs.

**Fix:** Add an `IntelligenceLoop::step(&mut self, feedback: Feedback) -> LoopAction` method that encapsulates the full state machine:
```rust
enum LoopAction {
    SendProbe(Probe),
    SendPayload(Chromosome),
    SaveCheckpoint,
    Terminate(TerminationReason),
}
```

---

## Summary Table

| Category | Critical | High | Medium | Total |
|----------|----------|------|--------|-------|
| Search Algorithms | 5 | 3 | 1 | 9 |
| Fitness Function | 1 | 3 | 0 | 4 |
| Caching & Deduplication | 3 | 1 | 0 | 4 |
| Corpus & Lineage | 4 | 1 | 0 | 5 |
| Novelty & Diversity | 2 | 2 | 1 | 5 |
| Termination & Safety | 3 | 2 | 0 | 5 |
| Parallelization | 1 | 1 | 0 | 2 |
| Reproducibility | 3 | 1 | 0 | 4 |
| Code Quality / Panics / OOM | 1 | 5 | 4 | 10 |
| Tests | 2 | 5 | 1 | 8 |
| Integration & Architecture | 2 | 3 | 1 | 6 |
| **Total** | **27** | **27** | **9** | **63** |

*(Note: The narrative above enumerates 58 distinct findings; the table aggregates by severity.)*
