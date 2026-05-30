//! 188-byte MPEG-TS packet — to be implemented per ISO/IEC 13818-1.

/// Fixed size of a transport-stream packet (188 bytes).
pub const TS_PACKET_LEN: usize = 188;

/// Spec-defined sync byte at offset 0 of every TS packet.
pub const TS_SYNC_BYTE: u8 = 0x47;

/// A parsed 188-byte TS packet. Stub — fields + parser TBD.
#[derive(Debug)]
pub struct TsPacket<'a> {
    /// 13-bit PID identifying the packet's elementary stream / PSI
    /// section.
    pub pid: u16,
    /// Raw packet bytes, including header.
    pub bytes: &'a [u8],
}
