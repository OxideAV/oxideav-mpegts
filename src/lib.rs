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
//! - Stream-type → codec-class helpers in [`stream_type`] covering the
//!   full ISO/IEC 13818-1 Table 2-29 base assignments (`0x01..=0x26`,
//!   incl. MPEG-1/2/4 video + audio, AAC-ADTS/LATM, AVC/SVC/MVC, HEVC,
//!   JPEG 2000, metadata carriers) plus the H.264/HEVC amendments and
//!   the HDMV-extended Blu-ray range (`0x80..=0xFF`: PCM, AC-3/E-AC-3,
//!   DTS/-HD, TrueHD, PGS, IGS, TextST). [`StreamType`] classifies each
//!   as video / audio / subtitle / metadata / private.
//! - PCR jitter and discontinuity tracking
//!   ([`clock::PcrTracker`], [`clock::ContinuityTracker`]) —
//!   per-PCR-PID 27 MHz clock recovery, instantaneous bitrate
//!   estimate, time-base discontinuity classification (signalled vs.
//!   tolerance-exceeded), plus per-PID continuity-counter
//!   classification (continuous / duplicate / no-payload /
//!   dropped / discontinuity).
//! - Per-PID PTS / DTS unwrapping ([`clock::PtsTracker`]) — turns the
//!   33-bit 90 kHz PES timestamps that wrap every ~26.5 h into a
//!   monotonic 64-bit extended timeline, while distinguishing a genuine
//!   `2^33` wrap from a backward splice / seek discontinuity
//!   ([`clock::TimestampEvent`]).
//! - Duration + keyframe-accurate seeking on the
//!   `demuxer::MpegTsDemuxer`. `duration_micros()` is probed once at
//!   open from the head-to-tail PCR span (§2.4.2.2). `seek_to()`
//!   honours the core contract (nearest keyframe at or before the
//!   target): a PCR-anchored binary search over the byte stream — no
//!   in-container index exists, so the demuxer brackets the target
//!   between the head/tail PCR anchors and bisects, comparing on the
//!   **extended** 64-bit timeline so a mid-stream `2^33` wrap doesn't
//!   break the search — then a windowed forward scan lands on the last
//!   access point at or before the target, with a doubling backoff for
//!   GOPs longer than the window and a cached full index as the
//!   definitive fallback. Access points are tiered
//!   (`demuxer::AccessPointKind`): §2.4.3.5 `random_access_indicator`
//!   announcements first, data-aligned PES starts (§2.4.3.7 /
//!   §2.6.10) for streams that never set the indicator, and a
//!   PCR-granular landing when neither is signalled. Every landing
//!   resets the PES reassemblers (continuity state is void after a
//!   byte jump) and re-seeds the PTS/DTS trackers at the landed time
//!   so post-seek packets continue the extended timeline.
//! - Random-access surface (§2.4.3.5): the muxer flags keyframe PES
//!   starts with the `random_access_indicator`, the reassembler folds
//!   the indicator into [`pes::PesPacket::random_access`], and the
//!   demuxer both maps it onto core keyframe flags and exposes the
//!   tiered access-point index (`random_access_points()`) plus the
//!   strict §2.4.3.5-only `seek_to_random_access()`.
//! - Write-side adaptation fields ([`packet::AdaptationFieldSpec`]) —
//!   the full §2.4.3.4 Table 2-6 optional-field set with §2.4.3.5
//!   pairing/width validation and `0xFF` stuffing.
//! - Typed DSM trick-mode decode ([`pes::DsmTrickMode`], §2.4.3.7
//!   Tables 2-20..2-22) with a wire-exact `to_byte()` inverse.
//! - Write-side PES headers ([`pes::PesHeaderSpec`]) — the full
//!   Table 2-17 optional-field set with §2.7.5 pairing validation,
//!   both `PES_packet_length` forms, and the header-less stream_ids.
//! - Physical packet-framing tolerance ([`packet::TsPacketLayout`]) —
//!   192-byte (4-byte-prefixed) source packets and 204-byte
//!   (16-byte-trailer) packets are detected at open and stripped at
//!   the read layer.
//! - Conformance validation ([`validate::validate_ts`]) — a bounded
//!   two-pass report of §2.4.3.3 / §2.4.3.5 / §2.7.2 / §2.4.4
//!   violations (including §2.4.3.5 splice-signalling coherence:
//!   countdown progression, seamless-run continuity, audio
//!   `splice_type`) with per-PID and per-PCR-PID statistics and a
//!   §2.4.2.2 transport-rate estimate.
//! - The T-STD buffer model ([`tstd::analyze_tstd`], §2.4.2) — the
//!   PCR-derived arrival clock (equations 2-1..2-5) replayed through
//!   the `TBn → Bn` / `TBn → MBn → EBn` / `TBsys → Bsys` chains with
//!   every §2.4.2.6 overflow / underflow / emptying / delay condition
//!   checked and per-chain peak-occupancy statistics.
//! - Splice-point signalling on the mux side
//!   ([`muxer::MpegTsMuxer::signal_splice_after`], §2.4.3.5 /
//!   Annex K) and CBR pacing on the §2.4.2 delivery schedule
//!   ([`muxer::MpegTsMuxer::set_mux_rate`]) — byte-clock PCRs,
//!   null-packet fill, per-class delivery leads, transport-buffer
//!   spacing.
//!
//! The crate ships **no decoders** — every payload byte stays as a
//! `&[u8]` slice. A downstream pipeline (e.g. `oxideav-cli`'s
//! `remux bluray:// …` path) iterates packets, drives a reassembler
//! per PID, and hands the resulting PES payloads to a muxer.
//!
//! ## What's NOT in scope
//!
//! - PSIP / DVB SI tables beyond PAT + PMT + CAT + TSDT + SDT + EIT +
//!   NIT + BAT + TDT + TOT + RST + ST + DIT + SIT. The ST
//!   ([`psi::StuffingTable`], §5.2.8) is the section-invalidation
//!   channel; the DIT ([`psi::DiscontinuityInformationTable`], §5.2.9)
//!   marks partial-TS transition points; and the SIT
//!   ([`psi::SelectionInformationTable`], §5.2.10 / §7.1.2) describes
//!   the services and events of a partial TS. The SDT
//!   ([`psi::ServiceDescriptionTable`], ETSI EN 300 468 §5.2.3) is
//!   parsed including its per-service `service_descriptor` (tag `0x48`)
//!   for human-readable service / provider names. The EIT
//!   ([`psi::EventInformationTable`], §5.2.4) is parsed across all four
//!   `table_id` classifications, decoding each event's MJD/BCD
//!   `start_time`, BCD `duration`, and per-event descriptor loop — the
//!   `short_event_descriptor` (tag `0x4D`) names the event and the
//!   `extended_event_descriptor` (tag `0x4E`) carries its detailed
//!   two-column item list plus non-itemized synopsis text.
//! - Descrambling of scrambled payloads. The `CA_descriptor` (tag
//!   `0x09`), `CA_identifier_descriptor` (tag `0x53`), and
//!   `scrambling_descriptor` (tag `0x65`) are *parsed* so a caller can
//!   see the CA system / PID / scrambling mode, but the crate performs
//!   no CA / CSA decryption.

#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod atsc;
mod atsc_huffman;
pub mod build;
pub mod clock;
pub mod descriptor;
pub mod error;
pub mod packet;
pub mod pes;
pub mod psi;
pub mod stream_type;
pub mod tstd;
pub mod validate;

#[cfg(test)]
mod hostile;

#[cfg(all(test, feature = "registry"))]
mod seek_roundtrip;

#[cfg(feature = "registry")]
pub mod demuxer;
#[cfg(feature = "registry")]
pub mod muxer;
#[cfg(feature = "registry")]
pub mod registry;

pub use build::{
    aac_descriptor, ac3_descriptor, bouquet_name_descriptor, build_eit_pf, build_nit, build_pat,
    build_pmt, build_sdt, dts_descriptor, enhanced_ac3_descriptor, iso639_language_descriptor,
    network_name_descriptor, registration_descriptor, service_descriptor, service_list_descriptor,
    short_event_descriptor, stream_identifier_descriptor, subtitling_descriptor,
    teletext_descriptor, EitEventEntry, NitTsEntry, PmtStreamEntry, SdtServiceEntry,
};
pub use clock::{
    extend_near, ContinuityEvent, ContinuityTracker, DiscontinuityReason, Pcr, PcrEvent,
    PcrTracker, PtsTracker, TimestampEvent, PCR_MODULUS_27MHZ, PCR_TOLERANCE_27MHZ,
    TIMESTAMP_MODULUS_90KHZ,
};
pub use descriptor::{
    iter_descriptors, parse_descriptors, AacDescriptor, Ac3Descriptor, AncillaryDataDescriptor,
    AudioStreamDescriptor, AvcVideoDescriptor, BouquetNameDescriptor, CaDescriptor,
    CaIdentifierDescriptor, CableDeliverySystemDescriptor, ComponentDescriptor, ContentDescriptor,
    ContentNibble, CopyrightDescriptor, CountryAvailabilityDescriptor, DataBroadcastDescriptor,
    DataBroadcastIdDescriptor, DataStreamAlignmentDescriptor, Descriptor, DescriptorBody,
    DescriptorIter, DtsDescriptor, EnhancedAc3Descriptor, ExtendedEventDescriptor,
    ExtendedEventItem, ExtensionBody, ExtensionDescriptor, FrequencyListDescriptor,
    HevcVideoDescriptor, HierarchyDescriptor, HierarchyType, IbpDescriptor, Iso639Language,
    LinkageDescriptor, LocalTimeOffsetDescriptor, LocalTimeOffsetEntry, MaximumBitrateDescriptor,
    MultiplexBufferUtilizationDescriptor, NetworkNameDescriptor, ParentalRatingDescriptor,
    ParentalRatingEntry, PartialTransportStreamDescriptor, PrivateDataSpecifierDescriptor,
    SatelliteDeliverySystemDescriptor, ScramblingDescriptor, ServiceDescriptor,
    ServiceListDescriptor, ServiceListEntry, ServiceMoveDescriptor, ShortEventDescriptor,
    ShortSmoothingBufferDescriptor, SmoothingBufferDescriptor, StdDescriptor,
    StreamIdentifierDescriptor, StuffingDescriptor, SubtitlingDescriptor, SubtitlingEntry,
    SupplementaryAudioDescriptor, SystemClockDescriptor, TargetBackgroundGridDescriptor,
    TeletextDescriptor, TeletextEntry, TerrestrialDeliverySystemDescriptor, VideoStreamDescriptor,
    VideoWindowDescriptor,
};
pub use error::TsError;
pub use packet::{
    detect_packet_layout, encode_clock_reference, iter_packets, AdaptationField,
    AdaptationFieldExtension, AdaptationFieldExtensionSpec, AdaptationFieldSpec, TsPacket,
    TsPacketIter, TsPacketLayout, MAX_ADAPTATION_FIELD_LEN, TS_PACKET_LEN, TS_SYNC_BYTE,
};
pub use pes::{
    CoefficientSelection, DsmTrickMode, FieldId, PStdBuffer, PesExtension, PesHeaderSpec,
    PesPacket, PesReassembler, ProgramPacketSequenceCounter,
};
pub use psi::{
    decode_utc_time, iter_sections, mpeg2_crc32, BatTransportStream, BouquetAssociationTable,
    ConditionalAccessTable, DiscontinuityInformationTable, EitDateTime, EitDuration, EitEvent,
    EventInformationTable, NetworkInformationTable, NitTransportStream, PmtStream,
    ProgramAssociationTable, ProgramMapTable, PsiSectionAssembler, RstEntry, RunningStatus,
    RunningStatusTable, SdtService, SectionIter, SelectionInformationTable,
    ServiceDescriptionTable, SitService, StuffingTable, TimeDateTable, TimeOffsetTable,
    TransportStreamDescriptionTable, BAT_PID, BAT_TABLE_ID, CAT_PID, CAT_TABLE_ID, DIT_PID,
    DIT_TABLE_ID, EIT_ACTUAL_PF_TABLE_ID, EIT_ACTUAL_SCHEDULE_FIRST, EIT_ACTUAL_SCHEDULE_LAST,
    EIT_OTHER_PF_TABLE_ID, EIT_OTHER_SCHEDULE_FIRST, EIT_OTHER_SCHEDULE_LAST, EIT_PID,
    MAX_PSI_SECTION_LEN, NIT_ACTUAL_TABLE_ID, NIT_OTHER_TABLE_ID, NIT_PID, PAT_PID, PAT_TABLE_ID,
    PMT_TABLE_ID, RST_PID, RST_TABLE_ID, SDT_ACTUAL_TABLE_ID, SDT_OTHER_TABLE_ID, SDT_PID, SIT_PID,
    SIT_TABLE_ID, ST_TABLE_ID, TDT_TABLE_ID, TDT_TOT_PID, TOT_TABLE_ID, TSDT_PID, TSDT_TABLE_ID,
};
pub use stream_type::StreamType;
pub use tstd::{
    analyze_tstd, TStdBranch, TStdChainStats, TStdConfig, TStdReport, TStdStreamModel,
    TStdViolation, AUDIO_MAIN_BUFFER_SIZE, AUDIO_RX_BPS, BSYS_SIZE, MAX_TSTD_DELAY_SECONDS,
    RSYS_MIN_BPS, RXSYS_BPS, TB_SIZE,
};
pub use validate::{
    validate_ts, PcrReport, PidReport, TsValidationReport, ViolationCounts, MAX_PCR_INTERVAL_27MHZ,
};

#[cfg(feature = "registry")]
pub use demuxer::{
    open as open_demuxer, probe as probe_mpegts, AccessPointKind, MpegTsDemuxer, RandomAccessPoint,
    TsProgram,
};

#[cfg(feature = "registry")]
pub use muxer::{open as open_muxer, MpegTsMuxer, SeamlessSpliceSpec, SpliceSpec};

#[cfg(feature = "registry")]
pub use registry::{register, register_containers};

#[cfg(feature = "registry")]
oxideav_core::register!("mpegts", register);
