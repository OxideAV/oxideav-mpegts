//! # oxideav-mpegts
//!
//! Pure-Rust, clean-room **MPEG-TS** (Transport Stream) demuxer per
//! ISO/IEC 13818-1, scoped at the bytes Blu-ray Disc ships inside a
//! `.m2ts` file once the BDAV TP_extra_header has been stripped (see
//! `oxideav_bluray::iter_source_packets`).
//!
//! ## Surface (Phase 1)
//!
//! - 188-byte TS packet parser ([`packet::TsPacket`]) — sync byte,
//!   `transport_error_indicator`, `payload_unit_start_indicator`,
//!   `transport_priority`, 13-bit PID, scrambling / adaptation /
//!   payload flags, continuity counter, optional adaptation field,
//!   payload slice.
//! - PAT (Program Association Table) parser
//!   ([`psi::ProgramAssociationTable`]) — discovers the PMT PID for
//!   each program.
//! - PMT (Program Map Table) parser ([`psi::ProgramMapTable`]) —
//!   discovers each elementary stream's PID + `stream_type` +
//!   per-stream `descriptor` payloads.
//! - PES packet reassembler ([`pes::PesReassembler`]) — joins TS
//!   payloads across packets per-PID, yields complete PES packets
//!   once the next start-indicator arrives or the stream ends.
//! - Stream-type → ESID helpers in [`stream_type`] mapping the BD-
//!   relevant constants (`0x1B AVC`, `0x24 HEVC`, `0x81 AC-3`,
//!   `0x82 DTS`, `0x90 PGS`, etc.) to a richer enum.
//! - PCR jitter and discontinuity tracking
//!   ([`clock::PcrTracker`], [`clock::ContinuityTracker`]) —
//!   per-PCR-PID 27 MHz clock recovery, instantaneous bitrate
//!   estimate, time-base discontinuity classification (signalled vs.
//!   tolerance-exceeded), plus per-PID continuity-counter
//!   classification (continuous / duplicate / no-payload /
//!   dropped / discontinuity).
//!
//! The crate ships **no decoders** — every payload byte stays as a
//! `&[u8]` slice. A downstream pipeline (e.g. `oxideav-cli`'s
//! `remux bluray:// …` path) iterates packets, drives a reassembler
//! per PID, and hands the resulting PES payloads to a muxer.
//!
//! ## What's NOT in scope
//!
//! - PSIP / DVB SI tables beyond PAT + PMT (no SDT, NIT, EIT).
//! - Conditional Access (CA) descriptors / scrambling.
//! - Re-multiplexing — this is a demux-only crate. The MKV writer
//!   in `oxideav-mkv` owns the output side.

#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod clock;
pub mod descriptor;
pub mod error;
pub mod packet;
pub mod pes;
pub mod psi;
pub mod stream_type;

#[cfg(feature = "registry")]
pub mod demuxer;
#[cfg(feature = "registry")]
pub mod muxer;
#[cfg(feature = "registry")]
pub mod registry;

pub use clock::{
    ContinuityEvent, ContinuityTracker, DiscontinuityReason, Pcr, PcrEvent, PcrTracker,
    PCR_MODULUS_27MHZ, PCR_TOLERANCE_27MHZ,
};
pub use descriptor::{
    iter_descriptors, parse_descriptors, AudioStreamDescriptor, AvcVideoDescriptor, CaDescriptor,
    DataStreamAlignmentDescriptor, Descriptor, DescriptorBody, DescriptorIter, HevcVideoDescriptor,
    Iso639Language, MaximumBitrateDescriptor, StdDescriptor, SystemClockDescriptor,
    VideoStreamDescriptor,
};
pub use error::TsError;
pub use packet::{
    iter_packets, AdaptationField, AdaptationFieldExtension, TsPacket, TsPacketIter, TS_PACKET_LEN,
    TS_SYNC_BYTE,
};
pub use pes::{PesPacket, PesReassembler};
pub use psi::{
    iter_sections, mpeg2_crc32, PmtStream, ProgramAssociationTable, ProgramMapTable, SectionIter,
};
pub use stream_type::StreamType;

#[cfg(feature = "registry")]
pub use demuxer::{open as open_demuxer, probe as probe_mpegts, MpegTsDemuxer};

#[cfg(feature = "registry")]
pub use muxer::{open as open_muxer, MpegTsMuxer};

#[cfg(feature = "registry")]
pub use registry::{register, register_containers};

#[cfg(feature = "registry")]
oxideav_core::register!("mpegts", register);
