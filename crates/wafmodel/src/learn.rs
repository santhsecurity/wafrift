//! Active automaton learning over the WAF oracle.
//!
//! The learned language is exactly **the set of requests the WAF lets
//! through** (accept ⇔ [`Outcome::Pass`]). Two independent learners are
//! provided and a differential test forces them to agree:
//!
//! - [`l_star`] — Angluin's L\* with all-suffixes counterexample
//!   handling. The simplest *provably convergent* learner; the
//!   correctness baseline.
//! - [`kv_learn`] — a Kearns–Vazirani discrimination-tree learner with
//!   Rivest–Schapire counterexample decomposition: the
//!   query-economical learner, which is what matters when every
//!   membership query is a live request.
//!
//! Both reduce learning to a membership function (a word over the
//! abstract [`Alphabet`] → does the WAF pass it?) and an
//! [`EquivalenceOracle`]. Membership results are memoized so a live
//! WAF is never asked the same question twice.

use crate::error::Result;
use crate::oracle::WafOracle;
use crate::outcome::Outcome;
use crate::sfa::{BytePred, Sfa, StateId};
use std::collections::HashMap;
use wafrift_types::Request;

/// The abstract alphabet the learner reasons over: a set of
/// distinguished concrete bytes plus one **catch-all class** whose
/// representative byte stands for every byte not otherwise listed.
///
/// This is the byte-domain abstraction that makes learning a *symbolic*
/// automaton tractable: a WAF rule cares about a handful of bytes
/// (`<`, `'`, `(`, …); the rest are interchangeable. The catch-all
/// keeps the learned [`Sfa`] total without a 256-way table. When the
/// distinguished set covers every byte any rule branches on, learning
/// is *exact* (not PAC) — the property the truth-suite asserts.
#[derive(Debug, Clone)]
pub struct Alphabet {
    /// Distinguished bytes, in stable order. The last entry is the
    /// catch-all class representative.
    symbols: Vec<u8>,
}

impl Alphabet {
    /// Build from distinguished bytes; `catch_all` is a byte that no
    /// rule of interest treats specially (its class absorbs every
    /// non-distinguished byte). It must not collide with a
    /// distinguished byte.
    ///
    /// # Panics
    /// If `catch_all` is also in `distinguished` (the classes would
    /// overlap and the lifted automaton would be non-deterministic).
    #[must_use]
    pub fn new(mut distinguished: Vec<u8>, catch_all: u8) -> Self {
        distinguished.sort_unstable();
        distinguished.dedup();
        assert!(
            !distinguished.contains(&catch_all),
            "catch-all byte {catch_all} must not be a distinguished symbol"
        );
        distinguished.push(catch_all);
        Alphabet {
            symbols: distinguished,
        }
    }

    /// Number of alphabet classes (distinguished + 1 catch-all).
    #[must_use]
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Always false (an alphabet always has the catch-all class).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Index of the catch-all class.
    #[must_use]
    pub fn catch_all(&self) -> usize {
        self.symbols.len() - 1
    }

    /// Concretize an abstract word into the bytes a request carries.
    #[must_use]
    pub fn concretize(&self, word: &[usize]) -> Vec<u8> {
        word.iter().map(|&i| self.symbols[i]).collect()
    }

    /// Representative byte of alphabet class `i`.
    #[must_use]
    pub fn byte_of(&self, i: usize) -> u8 {
        self.symbols[i]
    }

    /// The raw symbol table (distinguished bytes followed by the
    /// catch-all representative) — for artifact serialization.
    #[must_use]
    pub fn raw_symbols(&self) -> &[u8] {
        &self.symbols
    }

    /// Reconstruct from a raw symbol table (last entry = catch-all).
    ///
    /// # Panics
    /// If `symbols` is empty or has duplicates (a corrupt artifact;
    /// never silently repaired).
    #[must_use]
    pub fn from_raw_symbols(symbols: Vec<u8>) -> Self {
        assert!(!symbols.is_empty(), "alphabet must have ≥1 class");
        let mut seen = symbols.clone();
        seen.sort_unstable();
        let len_before = seen.len();
        seen.dedup();
        assert_eq!(len_before, seen.len(), "duplicate alphabet symbols");
        Alphabet { symbols }
    }

    /// The [`BytePred`] guard for alphabet class `i` when lifting a
    /// learned DFA to an [`Sfa`]: a distinguished symbol guards exactly
    /// its byte; the catch-all guards every byte not distinguished.
    /// Public so callers can build their own automata (attack
    /// grammars, hardening rules) over the same abstraction.
    #[must_use]
    pub fn guard(&self, i: usize) -> BytePred {
        if i == self.catch_all() {
            let mut explicit = BytePred::none();
            for &b in &self.symbols[..self.catch_all()] {
                explicit.insert(b);
            }
            !explicit
        } else {
            BytePred::byte(self.symbols[i])
        }
    }
}

/// Cached membership over abstract words: concretize → build a real
/// request → ask the WAF → accept ⇔ it passed. Never queries the same
/// abstract word twice.
struct Mq<'a, B> {
    oracle: &'a mut dyn WafOracle,
    build: &'a B,
    cache: HashMap<Vec<usize>, bool>,
    alpha: &'a Alphabet,
}

impl<'a, B> Mq<'a, B>
where
    B: Fn(&[u8]) -> Request,
{
    fn ask(&mut self, word: &[usize]) -> Result<bool> {
        if let Some(&b) = self.cache.get(word) {
            return Ok(b);
        }
        let req = (self.build)(&self.alpha.concretize(word));
        let pass = matches!(self.oracle.classify(&req)?, Outcome::Pass);
        self.cache.insert(word.to_vec(), pass);
        Ok(pass)
    }
}

/// Finds a word the hypothesis classifies differently from the WAF, or
/// `None` if the hypothesis is correct (within the oracle's power).
pub trait EquivalenceOracle {
    /// Return an abstract counterexample word, or `None` if equivalent.
    fn find_counterexample(
        &mut self,
        hyp: &Sfa,
        alpha: &Alphabet,
        mq: &mut dyn FnMut(&[usize]) -> Result<bool>,
    ) -> Result<Option<Vec<usize>>>;
}

/// Exhaustively enumerate every abstract word up to `max_len` and
/// return the first the hypothesis gets wrong. Exact for any language
/// whose shortest distinguishing word is ≤ `max_len`; this is the
/// equivalence oracle the exact-correctness truth-suite uses (no
/// sampling, no PAC). The query-economical sampling/W-method oracles
/// live in `equiv_query` (P1 #18).
#[derive(Debug, Clone, Copy)]
pub struct BoundedExhaustiveEq {
    /// Maximum word length to certify.
    pub max_len: usize,
}

impl EquivalenceOracle for BoundedExhaustiveEq {
    fn find_counterexample(
        &mut self,
        hyp: &Sfa,
        alpha: &Alphabet,
        mq: &mut dyn FnMut(&[usize]) -> Result<bool>,
    ) -> Result<Option<Vec<usize>>> {
        let k = alpha.len();
        let mut frontier: Vec<Vec<usize>> = vec![Vec::new()];
        for _len in 0..=self.max_len {
            let mut next = Vec::new();
            for w in &frontier {
                let truth = mq(w)?;
                if hyp.accepts(&alpha.concretize(w)) != truth {
                    return Ok(Some(w.clone()));
                }
                for sym in 0..k {
                    let mut e = w.clone();
                    e.push(sym);
                    next.push(e);
                }
            }
            frontier = next;
        }
        Ok(None)
    }
}

/// What a learning run produced and what it cost.
#[derive(Debug)]
pub struct LearnReport {
    /// The decompiled WAF as a symbolic automaton (accept ⇔ pass).
    pub sfa: Sfa,
    /// Distinct membership queries put to the oracle.
    pub membership_queries: u64,
    /// Equivalence rounds (counterexamples consumed).
    pub equivalence_rounds: u64,
}

// ── L* ─────────────────────────────────────────────────────────────

struct Table {
    s: Vec<Vec<usize>>,
    e: Vec<Vec<usize>>,
    rows: HashMap<Vec<usize>, Vec<bool>>,
}

impl Table {
    fn row<F: FnMut(&[usize]) -> Result<bool>>(
        &mut self,
        u: &[usize],
        mq: &mut F,
    ) -> Result<Vec<bool>> {
        if let Some(r) = self.rows.get(u) {
            return Ok(r.clone());
        }
        let mut r = Vec::with_capacity(self.e.len());
        for e in &self.e.clone() {
            let mut w = u.to_vec();
            w.extend_from_slice(e);
            r.push(mq(&w)?);
        }
        self.rows.insert(u.to_vec(), r.clone());
        Ok(r)
    }
}

fn build_hypothesis<F: FnMut(&[usize]) -> Result<bool>>(
    t: &mut Table,
    alpha: &Alphabet,
    mq: &mut F,
) -> Result<Sfa> {
    // Distinct S-rows in insertion order ⇒ states.
    let mut access: Vec<Vec<usize>> = Vec::new();
    let mut row_of: HashMap<Vec<bool>, StateId> = HashMap::new();
    for s in t.s.clone() {
        let r = t.row(&s, mq)?;
        row_of.entry(r).or_insert_with(|| {
            access.push(s.clone());
            access.len() - 1
        });
    }
    let n = access.len();
    let mut accept = vec![false; n];
    let mut delta: Vec<Vec<(BytePred, StateId)>> = vec![Vec::new(); n];
    let eps_idx = t.e.iter().position(|e| e.is_empty()).expect("ε ∈ E");
    for (st, acc) in access.iter().zip(accept.iter_mut()) {
        *acc = t.row(st, mq)?[eps_idx];
    }
    for st in 0..n {
        for a in 0..alpha.len() {
            let mut sa = access[st].clone();
            sa.push(a);
            let tgt_row = t.row(&sa, mq)?;
            let tgt = *row_of
                .get(&tgt_row)
                .expect("table closed ⇒ every S·a row is an S row");
            delta[st].push((alpha.guard(a), tgt));
        }
    }
    let start = *row_of.get(&t.row(&[], mq)?).expect("ε row is a state");
    Ok(Sfa::new(start, accept, delta))
}

/// Angluin L\* with all-suffixes counterexample handling.
pub fn l_star<B>(
    oracle: &mut dyn WafOracle,
    build: &B,
    alpha: &Alphabet,
    eq: &mut dyn EquivalenceOracle,
) -> Result<LearnReport>
where
    B: Fn(&[u8]) -> Request,
{
    let mut mqx = Mq {
        oracle,
        build,
        cache: HashMap::new(),
        alpha,
    };
    // Borrow the cache through a closure so the table and EQ share it.
    let mut t = Table {
        s: vec![vec![]],
        e: vec![vec![]],
        rows: HashMap::new(),
    };
    let mut rounds = 0u64;
    loop {
        // Close + make consistent.
        loop {
            // Closedness.
            let s_rows: std::collections::HashSet<Vec<bool>> = {
                let mut set = std::collections::HashSet::new();
                for s in t.s.clone() {
                    let r = {
                        let mut ask = |w: &[usize]| mqx.ask(w);
                        t.row(&s, &mut ask)?
                    };
                    set.insert(r);
                }
                set
            };
            let mut added = false;
            'close: for s in t.s.clone() {
                for a in 0..alpha.len() {
                    let mut sa = s.clone();
                    sa.push(a);
                    let r = {
                        let mut ask = |w: &[usize]| mqx.ask(w);
                        t.row(&sa, &mut ask)?
                    };
                    if !s_rows.contains(&r) {
                        t.s.push(sa);
                        added = true;
                        break 'close;
                    }
                }
            }
            if added {
                continue;
            }
            // Consistency.
            let mut fix: Option<Vec<usize>> = None;
            'cons: for i in 0..t.s.len() {
                for j in (i + 1)..t.s.len() {
                    let (si, sj) = (t.s[i].clone(), t.s[j].clone());
                    let (ri, rj) = {
                        let mut ask = |w: &[usize]| mqx.ask(w);
                        (t.row(&si, &mut ask)?, t.row(&sj, &mut ask)?)
                    };
                    if ri != rj {
                        continue;
                    }
                    for a in 0..alpha.len() {
                        for ei in 0..t.e.len() {
                            let e = t.e[ei].clone();
                            let mut wia = si.clone();
                            wia.push(a);
                            wia.extend_from_slice(&e);
                            let mut wja = sj.clone();
                            wja.push(a);
                            wja.extend_from_slice(&e);
                            let (a1, a2) = {
                                let mut ask = |w: &[usize]| mqx.ask(w);
                                (ask(&wia)?, ask(&wja)?)
                            };
                            if a1 != a2 {
                                let mut suffix = vec![a];
                                suffix.extend_from_slice(&e);
                                fix = Some(suffix);
                                break 'cons;
                            }
                        }
                    }
                }
            }
            if let Some(suffix) = fix {
                if !t.e.contains(&suffix) {
                    t.e.push(suffix);
                    t.rows.clear();
                }
                continue;
            }
            break;
        }

        let hyp = {
            let mut ask = |w: &[usize]| mqx.ask(w);
            build_hypothesis(&mut t, alpha, &mut ask)?
        };
        let ce = {
            let mut ask = |w: &[usize]| mqx.ask(w);
            eq.find_counterexample(&hyp, alpha, &mut ask)?
        };
        match ce {
            None => {
                return Ok(LearnReport {
                    sfa: hyp,
                    membership_queries: mqx.cache.len() as u64,
                    equivalence_rounds: rounds,
                });
            }
            Some(c) => {
                rounds += 1;
                // All-suffixes: add c[i..] for every i. Provably
                // increases Myhill–Nerode resolution ⇒ terminates.
                for i in 0..=c.len() {
                    let suf = c[i..].to_vec();
                    if !t.e.contains(&suf) {
                        t.e.push(suf);
                    }
                }
                t.rows.clear();
            }
        }
    }
}

// ── Kearns–Vazirani discrimination-tree learner ────────────────────

enum Node {
    Leaf(usize),
    Inner {
        suffix: Vec<usize>,
        accept_child: Box<Node>,
        reject_child: Box<Node>,
    },
}

struct Kv<'a, B> {
    mqx: Mq<'a, B>,
    access: Vec<Vec<usize>>,
    tree: Node,
}

impl<'a, B> Kv<'a, B>
where
    B: Fn(&[u8]) -> Request,
{
    fn sift(&mut self, word: &[usize]) -> Result<usize> {
        // Walk the discrimination tree by membership of word·suffix.
        let mut node = &self.tree;
        loop {
            match node {
                Node::Leaf(id) => return Ok(*id),
                Node::Inner {
                    suffix,
                    accept_child,
                    reject_child,
                } => {
                    let mut w = word.to_vec();
                    w.extend_from_slice(suffix);
                    node = if self.mqx.ask(&w)? {
                        accept_child
                    } else {
                        reject_child
                    };
                }
            }
        }
    }

    fn hypothesis(&mut self, alpha: &Alphabet) -> Result<Sfa> {
        let n = self.access.len();
        let mut accept = vec![false; n];
        for (i, a) in self.access.clone().iter().enumerate() {
            accept[i] = self.mqx.ask(a)?;
        }
        let words = self.access.clone();
        let mut delta: Vec<Vec<(BytePred, StateId)>> = Vec::with_capacity(n);
        for w in &words {
            let mut row = Vec::with_capacity(alpha.len());
            for sym in 0..alpha.len() {
                let mut sa = w.clone();
                sa.push(sym);
                let tgt = self.sift(&sa)?;
                row.push((alpha.guard(sym), tgt));
            }
            delta.push(row);
        }
        let start = self.sift(&[])?;
        Ok(Sfa::new(start, accept, delta))
    }
}

fn replace_leaf(node: &mut Node, target: usize, replacement: Node) {
    match node {
        Node::Leaf(id) if *id == target => *node = replacement,
        Node::Leaf(_) => {}
        Node::Inner {
            accept_child,
            reject_child,
            ..
        } => {
            replace_leaf(accept_child, target, replacement_clone(&replacement));
            replace_leaf(reject_child, target, replacement);
        }
    }
}

// `Node` is a tree of owned data; we only ever replace exactly one
// leaf, but the recursion needs an owned value on each branch. The
// replacement is constructed fresh per split (two leaves + a suffix),
// so cloning it is cheap and only the matching leaf is ever rewritten.
fn replacement_clone(n: &Node) -> Node {
    match n {
        Node::Leaf(id) => Node::Leaf(*id),
        Node::Inner {
            suffix,
            accept_child,
            reject_child,
        } => Node::Inner {
            suffix: suffix.clone(),
            accept_child: Box::new(replacement_clone(accept_child)),
            reject_child: Box::new(replacement_clone(reject_child)),
        },
    }
}

/// Kearns–Vazirani learner with Rivest–Schapire counterexample
/// decomposition. Tree-structured hypotheses keep the membership-query
/// count low — the property that matters against a live WAF.
pub fn kv_learn<B>(
    oracle: &mut dyn WafOracle,
    build: &B,
    alpha: &Alphabet,
    eq: &mut dyn EquivalenceOracle,
) -> Result<LearnReport>
where
    B: Fn(&[u8]) -> Request,
{
    let mut kv = Kv {
        mqx: Mq {
            oracle,
            build,
            cache: HashMap::new(),
            alpha,
        },
        access: vec![vec![]],
        // Root splits on ε: the empty word's membership separates the
        // initial accept/reject states. Start single-leaf; the first
        // counterexample grows the tree.
        tree: Node::Leaf(0),
    };
    let mut rounds = 0u64;

    loop {
        let hyp = kv.hypothesis(alpha)?;
        let ce = {
            let cache_ref = &mut kv.mqx;
            let mut ask = |w: &[usize]| cache_ref.ask(w);
            eq.find_counterexample(&hyp, alpha, &mut ask)?
        };
        let Some(c) = ce else {
            return Ok(LearnReport {
                sfa: hyp,
                membership_queries: kv.mqx.cache.len() as u64,
                equivalence_rounds: rounds,
            });
        };
        rounds += 1;

        // Rivest–Schapire: binary-search the breakpoint i where the
        // hypothesis' state after c[..i] stops agreeing with the WAF
        // on the residual c[i..]. That yields a new state and a
        // distinguishing suffix that splits an existing leaf.
        let n = c.len();
        let state_word = |k: usize, kv: &mut Kv<B>| -> Result<Vec<usize>> {
            // Access string of the hypothesis state reached on c[..k].
            let id = {
                let pref = c[..k].to_vec();
                kv.sift(&pref)?
            };
            Ok(kv.access[id].clone())
        };
        let alpha_at = |k: usize, kv: &mut Kv<B>| -> Result<bool> {
            // mq( access(state after c[..k]) · c[k..] )
            let mut w = state_word(k, kv)?;
            w.extend_from_slice(&c[k..]);
            kv.mqx.ask(&w)
        };

        let g0 = alpha_at(0, &mut kv)?;
        let gn = alpha_at(n, &mut kv)?;
        debug_assert_ne!(g0, gn, "Rivest–Schapire precondition: γ0 ≠ γn");
        // Find i with γ(i) != γ(i+1) by binary search on the prefix.
        let (mut lo, mut hi) = (0usize, n);
        while hi - lo > 1 {
            let mid = (lo + hi) / 2;
            if alpha_at(mid, &mut kv)? == g0 {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        let i = lo;
        // New distinguishing suffix and the new state's access string.
        let new_suffix = c[i + 1..].to_vec();
        let new_access = {
            let mut w = state_word(i, &mut kv)?;
            w.push(c[i]);
            w
        };
        let split_leaf = {
            let pref = c[..i + 1].to_vec();
            kv.sift(&pref)?
        };
        let new_id = kv.access.len();
        kv.access.push(new_access.clone());

        // Which branch (accept/reject of new_suffix) does each of the
        // old vs new access string fall on?
        let old_access = kv.access[split_leaf].clone();
        let mut old_probe = old_access;
        old_probe.extend_from_slice(&new_suffix);
        let old_goes_accept = kv.mqx.ask(&old_probe)?;

        let (accept_child, reject_child) = if old_goes_accept {
            (
                Box::new(Node::Leaf(split_leaf)),
                Box::new(Node::Leaf(new_id)),
            )
        } else {
            (
                Box::new(Node::Leaf(new_id)),
                Box::new(Node::Leaf(split_leaf)),
            )
        };
        let replacement = Node::Inner {
            suffix: new_suffix,
            accept_child,
            reject_child,
        };
        replace_leaf(&mut kv.tree, split_leaf, replacement);
    }
}
