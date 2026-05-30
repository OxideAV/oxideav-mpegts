//! Program-Specific Information tables — PAT + PMT. Stubs.

/// Parsed Program Association Table.
#[derive(Debug, Default)]
pub struct ProgramAssociationTable {
    /// `(program_number, pmt_pid)` pairs.
    pub programs: Vec<(u16, u16)>,
}

/// One elementary-stream descriptor inside a PMT.
#[derive(Debug)]
pub struct PmtStream {
    /// Per ISO/IEC 13818-1 Table 2-29 (`stream_type`).
    pub stream_type: u8,
    /// 13-bit elementary-stream PID.
    pub elementary_pid: u16,
    /// Raw descriptor bytes (caller decodes).
    pub descriptors: Vec<u8>,
}

/// Parsed Program Map Table for one program.
#[derive(Debug, Default)]
pub struct ProgramMapTable {
    /// Program number this PMT serves.
    pub program_number: u16,
    /// PID carrying the program's PCR.
    pub pcr_pid: u16,
    /// Per-stream descriptors keyed by `elementary_pid`.
    pub streams: Vec<PmtStream>,
}
