//! Concrete multi-segment reassembly scenarios beyond the two-segment cases the
//! unit tests cover — triple overlaps, mid-chain overlaps, and extending
//! segments, each asserted byte-for-byte under the relevant policy.

use wafrift_tcpoverlap::policy::ReassemblyPolicy::{Bsd, First, Last, Linux};
use wafrift_tcpoverlap::reassemble::{Segment, reassemble};

fn seg(seq: u32, s: &str) -> Segment {
    Segment::new(seq, s.as_bytes().to_vec())
}

#[test]
fn triple_full_overlap_first_keeps_the_earliest_arrival() {
    let segs = [seg(0, "AAAA"), seg(0, "BBBB"), seg(0, "CCCC")];
    assert_eq!(reassemble(&segs, First), b"AAAA");
}

#[test]
fn triple_full_overlap_last_keeps_the_latest_arrival() {
    let segs = [seg(0, "AAAA"), seg(0, "BBBB"), seg(0, "CCCC")];
    assert_eq!(reassemble(&segs, Last), b"CCCC");
}

#[test]
fn triple_full_overlap_bsd_keeps_the_first_filled_on_equal_edges() {
    // All share seq 0, so no incoming ever has a strictly-lower edge → first wins.
    let segs = [seg(0, "AAAA"), seg(0, "BBBB"), seg(0, "CCCC")];
    assert_eq!(reassemble(&segs, Bsd), b"AAAA");
}

#[test]
fn triple_full_overlap_linux_takes_the_last_on_equal_edges() {
    // Equal edges → Linux takes newer on every overwrite → final arrival wins.
    let segs = [seg(0, "AAAA"), seg(0, "BBBB"), seg(0, "CCCC")];
    assert_eq!(reassemble(&segs, Linux), b"CCCC");
}

#[test]
fn mid_chain_overlap_first_preserves_the_original_middle() {
    // base "GET /admin", an attack chunk overlapping the middle.
    let segs = [seg(0, "GET /admin"), seg(4, "XXXX")]; // pos 4..8 = "admi"
    // First keeps "admi"; pos 8,9 "n" plus... seg2 covers 4..8 only.
    assert_eq!(reassemble(&segs, First), b"GET /admin");
}

#[test]
fn mid_chain_overlap_last_rewrites_the_middle() {
    let segs = [seg(0, "GET /admin"), seg(4, "XXXX")];
    assert_eq!(reassemble(&segs, Last), b"GET XXXXin");
}

#[test]
fn an_extending_overlap_appends_its_non_overlapping_tail() {
    // seg2 overlaps the end of seg1 AND extends past it.
    let segs = [seg(0, "GET /"), seg(3, "Xevil")]; // seg2 pos 3..8: overlaps 3,4; extends 5..8
    // First: pos3,4 keep "/ "? "GET /" = G E T _ / at 0..5 → pos3='_'? indices: G0 E1 T2 space3 /4.
    // seg2 at pos3='X',4='e',5='v',6='i',7='l'. First keeps pos3=' ',4='/'; appends pos5..8 "vil".
    assert_eq!(reassemble(&segs, First), b"GET /vil");
    // Last: pos3,4 overwritten → "GETXevil".
    assert_eq!(reassemble(&segs, Last), b"GETXevil");
}

#[test]
fn bsd_lower_seq_wins_regardless_of_arrival_in_a_three_segment_set() {
    // High-seq segment arrives first; a lower-seq overlapping segment later.
    let segs = [seg(4, "YYYY"), seg(2, "ZZZZ"), seg(0, "WWWWWW")];
    // base 0, span 8. Lowest seq (0) covers 0..6; seq 2 covers 2..6; seq 4 covers 4..8.
    // BSD: at each position the lowest covering seq wins.
    //   pos0,1: only seq0 → W
    //   pos2..6: seq0 (0) beats seq2 (2) → W
    //   pos6,7: only seq4 → Y
    assert_eq!(reassemble(&segs, Bsd), b"WWWWWWYY");
}

#[test]
fn identical_bytes_overlap_is_policy_invariant() {
    // When overlapping bytes are equal, every policy yields the same stream.
    let segs = [seg(0, "HELLO"), seg(2, "LLO")];
    for p in [First, Last, Bsd, Linux] {
        assert_eq!(reassemble(&segs, p), b"HELLO", "policy must not matter when bytes agree");
    }
}

#[test]
fn a_single_segment_is_delivered_verbatim_under_every_policy() {
    for p in [First, Last, Bsd, Linux] {
        assert_eq!(reassemble(&[seg(7, "payload")], p), b"payload");
    }
}

#[test]
fn a_later_segment_filling_an_earlier_hole_is_delivered() {
    // seg at 0 ("AB"), hole at 2,3, seg at 4 ("EF"); then a seg fills 2,3 ("CD").
    let segs = [seg(0, "AB"), seg(4, "EF"), seg(2, "CD")];
    assert_eq!(reassemble(&segs, First), b"ABCDEF", "the gap-filler completes the stream");
}
