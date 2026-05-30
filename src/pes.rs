//! PES (Packetized Elementary Stream) reassembly. Stubs.

/// One complete PES packet — header + payload bytes.
#[derive(Debug)]
pub struct PesPacket {
    /// `stream_id` byte from the PES header (ISO/IEC 13818-1 Table 2-18).
    pub stream_id: u8,
    /// 33-bit Presentation Time Stamp (90 kHz), when present.
    pub pts_90k: Option<u64>,
    /// 33-bit Decoding Time Stamp, when present.
    pub dts_90k: Option<u64>,
    /// Elementary-stream payload bytes (after the PES header).
    pub payload: Vec<u8>,
}

/// Per-PID PES reassembler. Stub.
#[derive(Debug, Default)]
pub struct PesReassembler;
