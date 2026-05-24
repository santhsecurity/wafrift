//! Symbolic finite automata over the byte domain.
//!
//! A WAF's decision over one inspection channel is a regular language
//! (CRS rules *are* regexes). The learned model is therefore a
//! deterministic finite automaton — but a 256-way transition table per
//! state is wasteful and does not match how rules actually partition
//! the input. An [`Sfa`] labels each transition with a [`BytePred`]
//! (an exact subset of `0..=256`); the predicates out of every state
//! are a *total partition* of the byte domain, so the automaton is
//! deterministic and complete by construction.
//!
//! Everything here is exact (no PAC, no sampling): membership, the
//! full Boolean algebra (∩, ∪, ¬, set-difference), emptiness, the
//! shortest accepted word, and — the operation the learner's
//! equivalence query and the bypass miner both stand on — the
//! **shortest distinguishing word** between two automata.

/// An exact predicate over a byte: the characteristic set of `0..=255`
/// as a 256-bit vector. Boolean ops are four `u64` ops; this is small
/// enough to keep per transition and exact enough that the automaton
/// algebra has no rounding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct BytePred([u64; 4]);

impl BytePred {
    /// The empty predicate (matches nothing).
    #[must_use]
    pub const fn none() -> Self {
        BytePred([0; 4])
    }

    /// The full predicate (matches every byte).
    #[must_use]
    pub const fn any() -> Self {
        BytePred([u64::MAX; 4])
    }

    /// Predicate matching exactly one byte.
    #[must_use]
    pub fn byte(b: u8) -> Self {
        let mut p = BytePred::none();
        p.insert(b);
        p
    }

    /// Predicate matching an inclusive byte range.
    #[must_use]
    pub fn range(lo: u8, hi: u8) -> Self {
        let mut p = BytePred::none();
        for b in lo..=hi {
            p.insert(b);
        }
        p
    }

    /// Add a byte to the set.
    pub fn insert(&mut self, b: u8) {
        self.0[(b >> 6) as usize] |= 1u64 << (b & 63);
    }

    /// Is `b` in the set?
    #[must_use]
    pub fn contains(&self, b: u8) -> bool {
        self.0[(b >> 6) as usize] & (1u64 << (b & 63)) != 0
    }

    /// Set union.
    #[must_use]
    pub fn or(self, o: Self) -> Self {
        BytePred(std::array::from_fn(|i| self.0[i] | o.0[i]))
    }

    /// Set intersection.
    #[must_use]
    pub fn and(self, o: Self) -> Self {
        BytePred(std::array::from_fn(|i| self.0[i] & o.0[i]))
    }

    /// Set difference `self \ o`.
    #[must_use]
    pub fn minus(self, o: Self) -> Self {
        self.and(!o)
    }

    /// Is the set empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0 == [0; 4]
    }

    /// The smallest byte in the set, if any — the canonical witness
    /// used to concretize a symbolic transition into real bytes
    /// (stable so the learner and miner are deterministic).
    #[must_use]
    pub fn witness(&self) -> Option<u8> {
        for (i, &w) in self.0.iter().enumerate() {
            if w != 0 {
                return Some((i as u8) * 64 + w.trailing_zeros() as u8);
            }
        }
        None
    }

    /// Number of bytes in the set.
    #[must_use]
    pub fn count(&self) -> u32 {
        self.0.iter().map(|w| w.count_ones()).sum()
    }

    /// Lossless 64-hex-char encoding (4 little-endian `u64` words) for
    /// the Tier-B model artifact.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for w in self.0 {
            s.push_str(&format!("{w:016x}"));
        }
        s
    }

    /// Inverse of [`BytePred::to_hex`]. `None` on malformed input.
    #[must_use]
    pub fn from_hex(h: &str) -> Option<Self> {
        if h.len() != 64 {
            return None;
        }
        let mut p = [0u64; 4];
        for (i, word) in p.iter_mut().enumerate() {
            *word = u64::from_str_radix(&h[i * 16..i * 16 + 16], 16).ok()?;
        }
        Some(BytePred(p))
    }
}

impl std::ops::Not for BytePred {
    type Output = BytePred;
    /// Set complement within `0..=255`.
    fn not(self) -> BytePred {
        BytePred(std::array::from_fn(|i| !self.0[i]))
    }
}

/// Index of a state within an [`Sfa`].
pub type StateId = usize;

/// A complete, deterministic transition table: per state, a list of
/// `(guard, target)` whose guards partition the byte domain.
pub type DeltaTable = Vec<Vec<(BytePred, StateId)>>;

/// A deterministic, complete symbolic finite automaton over bytes.
///
/// Invariant (checked by [`Sfa::new`] and preserved by every method):
/// for each state the transition predicates are pairwise disjoint and
/// their union is [`BytePred::any`] — so running any byte string lands
/// in exactly one state.
#[derive(Debug, Clone)]
pub struct Sfa {
    start: StateId,
    accept: Vec<bool>,
    /// `delta[s]` = guarded transitions out of `s`; total + disjoint.
    delta: Vec<Vec<(BytePred, StateId)>>,
}

impl Sfa {
    /// Construct and validate the determinism+totality invariant.
    ///
    /// # Panics
    /// Panics if any state's guards overlap or fail to cover every
    /// byte — a malformed automaton is a bug, never silently repaired.
    #[must_use]
    pub fn new(start: StateId, accept: Vec<bool>, delta: Vec<Vec<(BytePred, StateId)>>) -> Self {
        assert_eq!(accept.len(), delta.len(), "accept/delta arity mismatch");
        assert!(start < accept.len(), "start state out of range");
        for (s, trans) in delta.iter().enumerate() {
            let mut cover = BytePred::none();
            for (g, t) in trans {
                assert!(
                    *t < accept.len(),
                    "state {s}: transition target out of range"
                );
                assert!(
                    cover.and(*g).is_empty(),
                    "state {s}: overlapping guards (non-deterministic)"
                );
                cover = cover.or(*g);
            }
            assert_eq!(cover, BytePred::any(), "state {s}: guards are not total");
        }
        Sfa {
            start,
            accept,
            delta,
        }
    }

    /// Number of states.
    #[must_use]
    pub fn len(&self) -> usize {
        self.accept.len()
    }

    /// Always false (an automaton has at least one state); present so
    /// clippy's `len_without_is_empty` is satisfied honestly.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accept.is_empty()
    }

    /// Export the raw parts for serialization (clones).
    #[must_use]
    pub fn export(&self) -> (StateId, Vec<bool>, DeltaTable) {
        (self.start, self.accept.clone(), self.delta.clone())
    }

    /// Rebuild from exported parts, re-validating the
    /// determinism+totality invariant (a tampered artifact is
    /// rejected, never trusted).
    #[must_use]
    pub fn import(start: StateId, accept: Vec<bool>, delta: DeltaTable) -> Self {
        Sfa::new(start, accept, delta)
    }

    /// The start state.
    #[must_use]
    pub fn start_state(&self) -> StateId {
        self.start
    }

    /// Is state `s` accepting?
    #[must_use]
    pub fn is_accepting(&self, s: StateId) -> bool {
        self.accept[s]
    }

    /// Guarded transitions out of `s` (total + pairwise disjoint).
    #[must_use]
    pub fn transitions(&self, s: StateId) -> &[(BytePred, StateId)] {
        &self.delta[s]
    }

    /// The state reached from `s` on byte `b`.
    #[must_use]
    pub fn step_byte(&self, s: StateId, b: u8) -> StateId {
        self.step(s, b)
    }

    fn step(&self, s: StateId, b: u8) -> StateId {
        for (g, t) in &self.delta[s] {
            if g.contains(b) {
                return *t;
            }
        }
        // F99: pre-fix this returned `s` (self-loop) in release
        // builds, silently corrupting `accepts()` results — a word
        // that should have reached an accepting state stayed in a
        // non-accepting one. The SFA is constructed totality-checked,
        // so reaching this branch means a programmer error in
        // `Sfa::minimize` or `Sfa::import`. Panic loudly instead of
        // silently producing wrong acceptance — a wrong "accepts"
        // verdict is a false-negative bypass (the model "missed" a
        // hole) and is worse than crashing.
        panic!(
            "SFA totality invariant broken: no transition for byte {b} in state {s}"
        );
    }

    /// Does the automaton accept `word`?
    #[must_use]
    pub fn accepts(&self, word: &[u8]) -> bool {
        let mut s = self.start;
        for &b in word {
            s = self.step(s, b);
        }
        self.accept[s]
    }

    /// Complement: accept ⇔ the original rejects. Exact because the
    /// automaton is total.
    #[must_use]
    pub fn complement(&self) -> Sfa {
        Sfa {
            start: self.start,
            accept: self.accept.iter().map(|a| !a).collect(),
            delta: self.delta.clone(),
        }
    }

    /// Synchronous product under a state-acceptance combiner. The
    /// product alphabet is the set of *minterms* — maximal byte sets
    /// on which both automata agree which transition to take — so the
    /// result stays deterministic, total, and exact.
    fn product(&self, o: &Sfa, accept: impl Fn(bool, bool) -> bool) -> Sfa {
        use std::collections::HashMap;
        let mut id: HashMap<(StateId, StateId), StateId> = HashMap::new();
        let mut work = vec![(self.start, o.start)];
        id.insert((self.start, o.start), 0);
        let mut acc = vec![accept(self.accept[self.start], o.accept[o.start])];
        let mut delta: Vec<Vec<(BytePred, StateId)>> = vec![Vec::new()];
        let mut i = 0;
        while i < work.len() {
            let (a, b) = work[i];
            let src = i;
            for (ga, ta) in &self.delta[a] {
                for (gb, tb) in &o.delta[b] {
                    let g = ga.and(*gb);
                    if g.is_empty() {
                        continue;
                    }
                    let key = (*ta, *tb);
                    let next = *id.entry(key).or_insert_with(|| {
                        work.push(key);
                        acc.push(accept(self.accept[*ta], o.accept[*tb]));
                        delta.push(Vec::new());
                        work.len() - 1
                    });
                    delta[src].push((g, next));
                }
            }
            i += 1;
        }
        Sfa::new(0, acc, delta)
    }

    /// Language intersection.
    #[must_use]
    pub fn intersect(&self, o: &Sfa) -> Sfa {
        self.product(o, |a, b| a && b)
    }

    /// Language union.
    #[must_use]
    pub fn union(&self, o: &Sfa) -> Sfa {
        self.product(o, |a, b| a || b)
    }

    /// Set difference `self \ o` (in this language, not in `o`'s).
    #[must_use]
    pub fn difference(&self, o: &Sfa) -> Sfa {
        self.product(o, |a, b| a && !b)
    }

    /// Shortest accepted word (BFS over states, expanding each
    /// transition by its witness byte). `None` ⇔ the language is
    /// empty. The witness is the minimum byte, so the result is the
    /// length-then-lexicographic minimum: a *deterministic, minimal*
    /// counterexample.
    #[must_use]
    pub fn shortest_accepted(&self) -> Option<Vec<u8>> {
        use std::collections::VecDeque;
        let mut seen = vec![false; self.len()];
        let mut q = VecDeque::new();
        q.push_back((self.start, Vec::new()));
        seen[self.start] = true;
        while let Some((s, w)) = q.pop_front() {
            if self.accept[s] {
                return Some(w);
            }
            // Visit transitions by ascending witness for determinism.
            let mut edges: Vec<(u8, StateId)> = self.delta[s]
                .iter()
                .filter_map(|(g, t)| g.witness().map(|b| (b, *t)))
                .collect();
            edges.sort_unstable();
            for (b, t) in edges {
                if !seen[t] {
                    seen[t] = true;
                    let mut nw = w.clone();
                    nw.push(b);
                    q.push_back((t, nw));
                }
            }
        }
        None
    }

    /// Is the language empty?
    #[must_use]
    pub fn is_language_empty(&self) -> bool {
        self.shortest_accepted().is_none()
    }

    /// Enumerate up to `max_words` accepted words, shortest-then-
    /// lexicographically-smallest first, none longer than `max_len`.
    /// Deterministic (transitions expanded by ascending witness byte).
    /// This is the bypass miner's harvest primitive.
    ///
    /// A `seen[state]` set CANNOT be applied here the way it can in
    /// `shortest_accepted` — we WANT to find multiple distinct words
    /// that end at the same state (`out.len() == max_words` is the
    /// only stopping rule). So instead the queue is hard-capped at
    /// [`Self::ENUMERATE_QUEUE_CAP`]; when it would overflow, we
    /// return whatever words have already been collected.
    ///
    /// Pre-cap, intersecting a learned automaton with a cyclic
    /// attack automaton could exponentially explode the BFS queue
    /// before `max_words` was reached — `mine_bypasses` would OOM
    /// on real WAF rule sets long before producing usable output.
    #[must_use]
    pub fn enumerate_accepted(&self, max_words: usize, max_len: usize) -> Vec<Vec<u8>> {
        use std::collections::VecDeque;
        let mut out = Vec::new();
        if max_words == 0 {
            return out;
        }
        let mut q = VecDeque::from([(self.start, Vec::<u8>::new())]);
        while let Some((s, w)) = q.pop_front() {
            if self.accept[s] {
                out.push(w.clone());
                if out.len() == max_words {
                    return out;
                }
            }
            if w.len() >= max_len {
                continue;
            }
            // Queue-size guard: stop EXPANDING (but keep draining
            // already-enqueued states) once we cross the cap. This
            // bounds memory at O(ENUMERATE_QUEUE_CAP × max_len) bytes.
            if q.len() >= Self::ENUMERATE_QUEUE_CAP {
                continue;
            }
            let mut edges: Vec<(u8, StateId)> = self.delta[s]
                .iter()
                .filter_map(|(g, t)| g.witness().map(|b| (b, *t)))
                .collect();
            edges.sort_unstable();
            for (b, t) in edges {
                let mut nw = w.clone();
                nw.push(b);
                q.push_back((t, nw));
            }
        }
        out
    }

    /// Hard upper bound on the `enumerate_accepted` BFS queue.
    /// 1M entries × max_len bytes each ≈ ~32 MiB at max_len=32,
    /// which fits a developer laptop. Past this the function
    /// returns the words it has collected instead of attempting
    /// to keep growing the frontier.
    const ENUMERATE_QUEUE_CAP: usize = 1_000_000;

    /// The shortest word accepted by exactly one of the two automata,
    /// or `None` iff they recognise the *same* language. This is the
    /// exact equivalence oracle the active learner uses and the
    /// witness the WAF-diff product reports.
    #[must_use]
    pub fn distinguishing_word(&self, o: &Sfa) -> Option<Vec<u8>> {
        // (L(self) \ L(o)) ∪ (L(o) \ L(self)) — shortest member.
        let sym = self.difference(o).union(&o.difference(self));
        sym.shortest_accepted()
    }

    /// Exact language equivalence.
    #[must_use]
    pub fn equivalent(&self, o: &Sfa) -> bool {
        self.distinguishing_word(o).is_none()
    }

    /// The unique (up to isomorphism) minimal SFA recognizing the same
    /// language: Hopcroft/Moore partition refinement lifted to the
    /// symbolic alphabet via *minterms* (the coarsest byte partition on
    /// which every state's transitions are constant). Total + disjoint
    /// by construction; unreachable states dropped. `minimize` is
    /// idempotent and language-preserving — both asserted by property
    /// test over 10k random automata.
    #[must_use]
    pub fn minimize(&self) -> Sfa {
        // 1. Reachable states (BFS from start).
        let mut reach = vec![false; self.len()];
        let mut stk = vec![self.start];
        reach[self.start] = true;
        while let Some(s) = stk.pop() {
            for (_, t) in &self.delta[s] {
                if !reach[*t] {
                    reach[*t] = true;
                    stk.push(*t);
                }
            }
        }

        // 2. Minterms: refine {ANY} by every distinct guard so each
        // resulting predicate is non-empty and every original guard is
        // a union of minterms.
        let mut minterms = vec![BytePred::any()];
        for trans in &self.delta {
            for (g, _) in trans {
                let mut next = Vec::with_capacity(minterms.len());
                for m in &minterms {
                    let yes = m.and(*g);
                    let no = m.and(!*g);
                    if !yes.is_empty() {
                        next.push(yes);
                    }
                    if !no.is_empty() {
                        next.push(no);
                    }
                }
                minterms = next;
            }
        }

        // 3. DFA over the minterm alphabet (target per (state, minterm)).
        let n = self.len();
        let step_mt: Vec<Vec<StateId>> = (0..n)
            .map(|s| {
                minterms
                    .iter()
                    .map(|m| {
                        // m is wholly inside exactly one guard (minterm
                        // property); its representative byte selects it.
                        let b = m.witness().expect("non-empty minterm");
                        self.step(s, b)
                    })
                    .collect()
            })
            .collect();

        // 4. Moore refinement (only reachable states participate).
        let mut class: Vec<usize> = (0..n).map(|s| usize::from(self.accept[s])).collect();
        loop {
            let mut sig: std::collections::HashMap<Vec<usize>, usize> =
                std::collections::HashMap::new();
            let mut next = vec![0usize; n];
            for s in 0..n {
                if !reach[s] {
                    continue;
                }
                let mut key = vec![class[s]];
                key.extend(step_mt[s].iter().map(|&t| class[t]));
                let id = sig.len();
                next[s] = *sig.entry(key).or_insert(id);
            }
            if next == class {
                break;
            }
            class = next;
        }

        // 5. Rebuild: one state per class, start first, guards = union
        // of minterms with the same target class.
        let mut rep: std::collections::HashMap<usize, StateId> = std::collections::HashMap::new();
        let start_c = class[self.start];
        rep.insert(start_c, 0);
        let mut order = vec![start_c];
        for s in 0..n {
            if reach[s] {
                let c = class[s];
                if let std::collections::hash_map::Entry::Vacant(e) = rep.entry(c) {
                    e.insert(order.len());
                    order.push(c);
                }
            }
        }
        // A witness original state for each class (first reachable).
        let mut witness_state: std::collections::HashMap<usize, StateId> =
            std::collections::HashMap::new();
        for s in 0..n {
            if reach[s] {
                witness_state.entry(class[s]).or_insert(s);
            }
        }
        let mut accept = vec![false; order.len()];
        let mut delta: Vec<Vec<(BytePred, StateId)>> = vec![Vec::new(); order.len()];
        for (&c, &idx) in &rep {
            let ws = witness_state[&c];
            accept[idx] = self.accept[ws];
            // Merge minterms by destination class.
            let mut by_dst: std::collections::HashMap<StateId, BytePred> =
                std::collections::HashMap::new();
            for (mi, m) in minterms.iter().enumerate() {
                let dst_class = class[step_mt[ws][mi]];
                let e = by_dst.entry(rep[&dst_class]).or_insert(BytePred::none());
                *e = e.or(*m);
            }
            delta[idx] = by_dst.into_iter().map(|(t, g)| (g, t)).collect();
        }
        Sfa::new(0, accept, delta)
    }
}
