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
//!   once the next start-indicator arrives or the stream ends. The
//!   resulting [`pes::PesPacket`] decodes every Table 2-17 optional
//!   header field — `PES_scrambling_control` / `PES_priority` /
//!   `data_alignment_indicator` / `copyright` / `original_or_copy` on
//!   flags1, plus the flag-gated bodies ESCR (27 MHz tick), `ES_rate`
//!   (50 bytes/s units), `DSM_trick_mode` (raw 8-bit byte),
//!   `additional_copy_info`, `previous_PES_packet_CRC`, and the full
//!   `PES_extension` body ([`pes::PesExtension`] — private data, pack
//!   header bytes, program_packet_sequence_counter, P-STD buffer,
//!   PES_extension_field_2).
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
//! - PSIP / DVB SI tables beyond PAT + PMT + CAT + TSDT + SDT + EIT +
//!   NIT + TDT + TOT (no BAT / RST yet). The SDT
//!   ([`psi::ServiceDescriptionTable`], ETSI EN 300 468 §5.2.3) is
//!   parsed including its per-service `service_descriptor` (tag `0x48`)
//!   for human-readable service / provider names. The EIT
//!   ([`psi::EventInformationTable`], §5.2.4) is parsed across all four
//!   `table_id` classifications, decoding each event's MJD/BCD
//!   `start_time`, BCD `duration`, and per-event descriptor loop — the
//!   `short_event_descriptor` (tag `0x4D`) names the event.
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
    Iso639Language, LocalTimeOffsetDescriptor, LocalTimeOffsetEntry, MaximumBitrateDescriptor,
    NetworkNameDescriptor, ServiceDescriptor, ShortEventDescriptor, SmoothingBufferDescriptor,
    StdDescriptor, SystemClockDescriptor, VideoStreamDescriptor,
};
pub use error::TsError;
pub use packet::{
    iter_packets, AdaptationField, AdaptationFieldExtension, TsPacket, TsPacketIter, TS_PACKET_LEN,
    TS_SYNC_BYTE,
};
pub use pes::{PStdBuffer, PesExtension, PesPacket, PesReassembler, ProgramPacketSequenceCounter};
pub use psi::{
    decode_utc_time, iter_sections, mpeg2_crc32, ConditionalAccessTable, EitDateTime, EitDuration,
    EitEvent, EventInformationTable, NetworkInformationTable, NitTransportStream, PmtStream,
    ProgramAssociationTable, ProgramMapTable, PsiSectionAssembler, RunningStatus, SdtService,
    SectionIter, ServiceDescriptionTable, TimeDateTable, TimeOffsetTable,
    TransportStreamDescriptionTable, CAT_PID, CAT_TABLE_ID, EIT_ACTUAL_PF_TABLE_ID,
    EIT_ACTUAL_SCHEDULE_FIRST, EIT_ACTUAL_SCHEDULE_LAST, EIT_OTHER_PF_TABLE_ID,
    EIT_OTHER_SCHEDULE_FIRST, EIT_OTHER_SCHEDULE_LAST, EIT_PID, MAX_PSI_SECTION_LEN,
    NIT_ACTUAL_TABLE_ID, NIT_OTHER_TABLE_ID, NIT_PID, PAT_PID, PAT_TABLE_ID, PMT_TABLE_ID,
    SDT_ACTUAL_TABLE_ID, SDT_OTHER_TABLE_ID, SDT_PID, TDT_TABLE_ID, TDT_TOT_PID, TOT_TABLE_ID,
    TSDT_PID, TSDT_TABLE_ID,
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
