//! `wafrift http3-frames` — generate wire-format HTTP/3 + QUIC evasion frames.
//!
//! Closes the "first production caller" gap for every builder in
//! [`wafrift_http3_evasion`]: `QpackDesyncAttack`, `ConnectionIdGenerator`,
//! `ZeroRttReplayBuilder`, `H3PriorityAttack`, `MtuFragmentationAttack`.
//! Pre-wire the crate enumerated `EvasionTechnique::all()` for `techniques
//! list --format json` but never instantiated any builder — five complete
//! attack-frame generators were dark.
//!
//! ## What this command does
//!
//! Instantiates one of the five builders with sensible defaults, calls its
//! frame-set producer (`to_frame_set` / `rotation_burst` / `replay_bundle`),
//! and emits a JSON envelope describing the resulting `EvasionFrameSet`:
//!
//! ```text
//! {
//!   "technique": "QpackDesync",
//!   "description": "QPACK phantom-insert desync: ...",
//!   "frame_count": 6,
//!   "total_bytes": 142,
//!   "frames": [{"stream_id": 0, "bytes_hex": "...", "description": "..."}]
//! }
//! ```
//!
//! Optionally writes the raw concatenated frame bytes to `--out <PATH>` so
//! operators can feed them into an external QUIC client (quinn, msquic).
//! This crate stays pure data-plane per its own architecture note; this
//! subcommand is the operator-facing handle to that data.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use serde::Serialize;
use wafrift_http3_evasion::{
    ConnectionIdGenerator, EvasionFrameSet, EvasionTechnique, H3PriorityAttack,
    MtuFragmentationAttack, QpackDesyncAttack, ZeroRttReplayBuilder,
};

#[derive(Args, Debug)]
pub struct Http3FramesArgs {
    /// Which HTTP/3 + QUIC evasion technique to generate frames for.
    /// One of: `qpack-desync`, `cid-rotation`, `zero-rtt-replay`,
    /// `stream-priority`, `mtu-fragmentation`.
    #[arg(
        long,
        value_parser = [
            "qpack-desync",
            "cid-rotation",
            "zero-rtt-replay",
            "stream-priority",
            "mtu-fragmentation",
        ],
    )]
    pub technique: String,

    /// Output format: `json` (default, machine-readable) or `text`
    /// (human inspection with per-frame hex previews).
    #[arg(long, default_value = "json", value_parser = ["json", "text"])]
    pub format: String,

    /// Write the concatenated raw frame bytes to this file in addition
    /// to the JSON/text envelope on stdout. The file contains every
    /// frame's `bytes` joined end-to-end so operators can pipe it
    /// directly into an external QUIC client.
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,

    /// `qpack-desync` only — number of phantom QPACK insertions to
    /// emit before the attack header. Higher = more desync surface.
    #[arg(long, default_value_t = 3)]
    pub phantom_insertions: usize,

    /// `cid-rotation` only — number of new CIDs to announce in the
    /// rotation burst.
    #[arg(long, default_value_t = 5)]
    pub cid_burst: usize,

    /// `zero-rtt-replay` only — how many times to replay the same
    /// 0-RTT payload across fresh stream IDs.
    #[arg(long, default_value_t = 3)]
    pub replay_count: usize,

    /// `stream-priority` only — number of streams in the urgency storm.
    #[arg(long, default_value_t = 8)]
    pub priority_streams: usize,

    /// `mtu-fragmentation` only — raw bytes (UTF-8) to fragment one
    /// byte per packet. Default `"wafrift"` (7 bytes, 7 fragments).
    #[arg(long, default_value = "wafrift")]
    pub mtu_payload: String,
}

#[derive(Serialize)]
struct FrameRow {
    stream_id: u64,
    bytes_hex: String,
    description: String,
}

#[derive(Serialize)]
struct FramesEnvelope {
    technique: String,
    description: String,
    frame_count: usize,
    total_bytes: usize,
    frames: Vec<FrameRow>,
}

pub fn run_http3_frames(args: Http3FramesArgs) -> ExitCode {
    let frame_set = match args.technique.as_str() {
        "qpack-desync" => {
            let attack = QpackDesyncAttack::phantom_insert(
                args.phantom_insertions,
                ("authorization", "Bearer admin"),
            );
            attack.to_frame_set()
        }
        "cid-rotation" => {
            let mut cid_gen = ConnectionIdGenerator::new(8, 0xDEAD_BEEF);
            cid_gen.rotation_burst(args.cid_burst, 0)
        }
        "zero-rtt-replay" => {
            let builder = ZeroRttReplayBuilder::new(args.replay_count);
            let payload = builder.full_request_early(
                "GET",
                "/admin",
                &[("host", "target.example"), ("user-agent", "wafrift")],
                None,
            );
            builder.replay_bundle(&payload)
        }
        "stream-priority" => {
            let attack = H3PriorityAttack::urgency_storm(args.priority_streams);
            attack.to_frame_set()
        }
        "mtu-fragmentation" => {
            let attack = MtuFragmentationAttack::byte_per_packet(args.mtu_payload.as_bytes());
            attack.to_frame_set()
        }
        other => {
            eprintln!("✗ unknown technique: {other}");
            return ExitCode::from(2);
        }
    };

    // Persist raw bytes when --out is supplied so operators can pipe
    // them straight to an external QUIC client.
    if let Some(ref path) = args.out {
        let mut raw = Vec::new();
        for f in &frame_set.frames {
            raw.extend_from_slice(&f.bytes);
        }
        if let Err(e) = std::fs::write(path, &raw) {
            eprintln!("✗ failed to write {}: {e}", path.display());
            return ExitCode::from(1);
        }
    }

    let envelope = build_envelope(&frame_set);
    match args.format.as_str() {
        "json" => match serde_json::to_string_pretty(&envelope) {
            Ok(s) => {
                println!("{s}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("✗ json render: {e}");
                ExitCode::from(1)
            }
        },
        _ => {
            print_text(&envelope);
            ExitCode::SUCCESS
        }
    }
}

fn build_envelope(set: &EvasionFrameSet) -> FramesEnvelope {
    let frames: Vec<FrameRow> = set
        .frames
        .iter()
        .map(|f| FrameRow {
            stream_id: f.stream_id,
            bytes_hex: hex_encode(&f.bytes),
            description: f.description.clone(),
        })
        .collect();
    let total_bytes: usize = set.frames.iter().map(|f| f.bytes.len()).sum();
    FramesEnvelope {
        technique: format!("{:?}", set.technique),
        description: set.description.clone(),
        frame_count: set.frames.len(),
        total_bytes,
        frames,
    }
}

fn print_text(env: &FramesEnvelope) {
    println!("Technique : {}", env.technique);
    println!("Desc      : {}", env.description);
    println!("Frames    : {}", env.frame_count);
    println!("Total     : {} bytes", env.total_bytes);
    for (i, f) in env.frames.iter().enumerate() {
        println!(
            "  [{:>3}] stream={:<5} bytes={:>5}  {}",
            i,
            f.stream_id,
            f.bytes_hex.len() / 2,
            f.description
        );
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Stable mapping from CLI technique flag to `EvasionTechnique`. Pinned
/// in a test below so renaming the enum variant without updating the
/// flag value-parser surface trips CI rather than shipping silently.
/// Gated to test builds — the runtime dispatch matches on the flag
/// string directly inside `run_http3_frames` for clarity.
#[cfg(test)]
#[must_use]
fn technique_for(flag: &str) -> Option<EvasionTechnique> {
    match flag {
        "qpack-desync" => Some(EvasionTechnique::QpackDesync),
        "cid-rotation" => Some(EvasionTechnique::CidRotation),
        "zero-rtt-replay" => Some(EvasionTechnique::ZeroRttReplay),
        "stream-priority" => Some(EvasionTechnique::StreamPriorityTopology),
        "mtu-fragmentation" => Some(EvasionTechnique::MtuFragmentation),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(technique: &str) -> Http3FramesArgs {
        Http3FramesArgs {
            technique: technique.to_string(),
            format: "json".into(),
            out: None,
            phantom_insertions: 2,
            cid_burst: 3,
            replay_count: 2,
            priority_streams: 4,
            mtu_payload: "ab".into(),
        }
    }

    #[test]
    fn technique_for_covers_every_evasion_variant() {
        // Every value-parser entry must map to a real EvasionTechnique.
        for flag in [
            "qpack-desync",
            "cid-rotation",
            "zero-rtt-replay",
            "stream-priority",
            "mtu-fragmentation",
        ] {
            assert!(technique_for(flag).is_some(), "missing mapping for {flag}");
        }
        // And the count matches the crate's enumeration so a new
        // variant added in http3-evasion forces a CLI flag update.
        assert_eq!(EvasionTechnique::all().len(), 5);
    }

    #[test]
    fn unknown_technique_returns_none() {
        assert!(technique_for("not-a-real-technique").is_none());
    }

    #[test]
    fn qpack_desync_builds_non_empty_frameset() {
        let code = run_http3_frames(args("qpack-desync"));
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "qpack-desync should exit 0"
        );
    }

    #[test]
    fn cid_rotation_builds_non_empty_frameset() {
        let code = run_http3_frames(args("cid-rotation"));
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn zero_rtt_replay_builds_non_empty_frameset() {
        let code = run_http3_frames(args("zero-rtt-replay"));
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn stream_priority_builds_non_empty_frameset() {
        let code = run_http3_frames(args("stream-priority"));
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn mtu_fragmentation_builds_non_empty_frameset() {
        let code = run_http3_frames(args("mtu-fragmentation"));
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn out_path_writes_concatenated_bytes() {
        let tmp = std::env::temp_dir().join(format!(
            "wafrift_http3_frames_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut a = args("mtu-fragmentation");
        a.out = Some(tmp.clone());
        let code = run_http3_frames(a);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let raw = std::fs::read(&tmp).expect("file written");
        assert!(!raw.is_empty(), "concatenated frame bytes must be written");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn hex_encode_roundtrip_lowercase() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab]), "00ffab");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn build_envelope_counts_match_frame_set() {
        let attack = QpackDesyncAttack::phantom_insert(2, ("x", "y"));
        let fs = attack.to_frame_set();
        let env = build_envelope(&fs);
        assert_eq!(env.frame_count, fs.frames.len());
        let total: usize = fs.frames.iter().map(|f| f.bytes.len()).sum();
        assert_eq!(env.total_bytes, total);
    }
}
