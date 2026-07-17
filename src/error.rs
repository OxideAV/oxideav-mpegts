//! Error type for the demuxer surface.

use thiserror::Error;

/// Errors raised by the MPEG-TS parsers.
#[derive(Debug, Error)]
pub enum TsError {
    /// The slice handed to a parser is shorter than the spec-fixed
    /// record size.
    #[error("truncated: {what} (have {have} bytes, need {need})")]
    Truncated {
        what: &'static str,
        have: usize,
        need: usize,
    },
    /// A 188-byte TS packet's first byte is not the spec-defined sync
    /// byte (`0x47`).
    #[error("bad TS sync byte: 0x{0:02X} (want 0x47)")]
    BadSyncByte(u8),
    /// A PSI section header reported a length that exceeds the data
    /// the caller supplied.
    #[error("PSI section length {claimed} > available {have}")]
    SectionLengthOverrun { claimed: usize, have: usize },
    /// A PSI section's CRC-32/MPEG-2 trailer didn't match the body.
    #[error("PSI CRC mismatch: header CRC=0x{header:08X} computed=0x{computed:08X}")]
    PsiCrcMismatch { header: u32, computed: u32 },
    /// PES packet start code was not `00 00 01`.
    #[error("bad PES start code: {0:02X?}")]
    BadPesStartCode([u8; 3]),
    /// Catch-all for spec-permitted but currently unsupported values
    /// (e.g. a TS_program_map_section variant we haven't wired).
    #[error("{0}")]
    Unsupported(&'static str),
    /// A write-side builder was handed a value that overflows its
    /// spec-fixed field width, or a field combination §2.4.3.5
    /// forbids (e.g. OPCR without PCR).
    #[error("invalid field: {what}")]
    InvalidField { what: &'static str },
}
