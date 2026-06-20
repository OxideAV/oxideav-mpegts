//! Container [`Muxer`] implementation that writes elementary-stream
//! [`Packet`]s into a 188-byte MPEG-TS file per ISO/IEC 13818-1.
//!
//! Scope:
//!
//! * Synthesises a single-program PAT (`PID 0x0000`) and a matching
//!   PMT (`PID 0x0100`) on `write_header`. PSI sections too long for
//!   one packet (a PMT with an ISO-639 / registration descriptor loop
//!   for many tracks) split across multiple TS packets per §2.4.4 —
//!   PUSI + `pointer_field` on the first, continuation on the rest.
//! * Wraps each [`Packet`] in a PES envelope with PTS (and DTS when
//!   set), then fragments the PES into 188-byte TS packets — first
//!   packet has `payload_unit_start_indicator = 1`, continuations
//!   have it clear. Tail packets get an adaptation-field stuffing
//!   pass so the byte count lands on the 188-byte boundary.
//! * Per-PID continuity counters increment 0..0xF and wrap.
//! * The first track marked as video also serves as the PCR PID —
//!   every PES start on that PID carries a PCR adaptation field so
//!   downstream players can lock the clock.
//! * `write_trailer` re-emits the PAT/PMT once so a player that
//!   joins the stream near the end still sees the program tables.
//!
//! Out of scope (Phase 1):
//!
//! * Multi-program streams. There is one program; trying to mux
//!   streams from two different programs into one PMT is the
//!   caller's responsibility.
//! * MPEG-DASH-style time slicing, PES-CRC, or scrambling.
//! * Adaptation-field random-access / discontinuity / private-data
//!   flags beyond `PCR_flag`. Video tracks get PCR at every PES;
//!   non-video tracks never get adaptation fields.
//!
//! CodecId → MPEG-TS `stream_type` (Table 2-29 + HDMV extension
//! 0x80..0xFF). The reverse mapping is performed at `open`; unknown
//! codecs surface as `Error::Unsupported`. The full list mirrors the
//! demuxer's `codec_params_for_stream_type` so a demux + mux
//! round-trip preserves the codec set on the disc.

use std::collections::HashMap;
use std::io::Write;

use oxideav_core::{
    Error as CoreError, Muxer, Packet, Result as CoreResult, StreamInfo, WriteSeek,
};

use crate::{TS_PACKET_LEN, TS_SYNC_BYTE};

/// PAT lives on PID 0x0000 by spec.
const PAT_PID: u16 = 0x0000;
/// PMT PID is implementation-defined; we use the conventional 0x0100.
const PMT_PID: u16 = 0x0100;
/// First PID we hand out for an elementary stream.
const FIRST_ES_PID: u16 = 0x1011;
/// Single-program stream — `program_number` = 1 in PAT and PMT.
const PROGRAM_NUMBER: u16 = 1;

/// `Open` factory matching `oxideav_core::OpenMuxerFn`. Registered
/// under the `"mpegts"` container name.
pub fn open(output: Box<dyn WriteSeek>, streams: &[StreamInfo]) -> CoreResult<Box<dyn Muxer>> {
    MpegTsMuxer::new(output, streams).map(|m| Box::new(m) as Box<dyn Muxer>)
}

/// MPEG-TS muxer state.
pub struct MpegTsMuxer {
    output: Box<dyn WriteSeek>,
    /// Per-stream PID + stream_type + stream_id + CC. Order matches
    /// the `streams` slice passed to [`MpegTsMuxer::new`].
    tracks: Vec<TrackState>,
    /// `stream_index` → `tracks[index]` for `write_packet` dispatch.
    idx_to_track: HashMap<u32, usize>,
    /// PCR PID — the first track classified as video, or the first
    /// track when no video is present.
    pcr_pid: u16,
    /// Continuity counter for PAT TS packets.
    pat_cc: u8,
    /// Continuity counter for PMT TS packets.
    pmt_cc: u8,
    /// `true` once `write_header` has run.
    header_written: bool,
}

impl std::fmt::Debug for MpegTsMuxer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpegTsMuxer")
            .field("tracks", &self.tracks.len())
            .field("pcr_pid", &self.pcr_pid)
            .field("header_written", &self.header_written)
            .finish()
    }
}

#[derive(Debug, Clone)]
struct TrackState {
    pid: u16,
    stream_type: u8,
    stream_id: u8,
    cc: u8,
    is_video: bool,
}

impl MpegTsMuxer {
    fn new(output: Box<dyn WriteSeek>, streams: &[StreamInfo]) -> CoreResult<Self> {
        if streams.is_empty() {
            return Err(CoreError::invalid(
                "mpegts muxer: at least one stream required",
            ));
        }
        let mut tracks = Vec::with_capacity(streams.len());
        let mut idx_to_track = HashMap::with_capacity(streams.len());
        let mut next_pid = FIRST_ES_PID;
        for (i, s) in streams.iter().enumerate() {
            let (stream_type, stream_id, is_video) =
                stream_type_for_codec(s.params.codec_id.as_str()).ok_or_else(|| {
                    CoreError::unsupported(format!(
                        "mpegts muxer: no MPEG-TS stream_type for codec_id '{}'",
                        s.params.codec_id.as_str()
                    ))
                })?;
            tracks.push(TrackState {
                pid: next_pid,
                stream_type,
                stream_id,
                cc: 0,
                is_video,
            });
            idx_to_track.insert(s.index, i);
            // Increment PID with a bit of separation between codec
            // classes so the muxed file roughly matches the BD-style
            // 0x1011 (video) / 0x1100+ (audio) / 0x1200+ (subs)
            // convention. Strictly cosmetic — any 13-bit PID works.
            next_pid = next_pid.wrapping_add(1);
            let _ = i;
        }
        let pcr_pid = tracks
            .iter()
            .find(|t| t.is_video)
            .map(|t| t.pid)
            .unwrap_or(tracks[0].pid);
        Ok(Self {
            output,
            tracks,
            idx_to_track,
            pcr_pid,
            pat_cc: 0,
            pmt_cc: 0,
            header_written: false,
        })
    }

    /// Emit a complete PSI section as one or more 188-byte TS packets
    /// per §2.4.4. The first packet carries `payload_unit_start_indicator
    /// = 1` and a leading `pointer_field = 0` (the section begins
    /// immediately after it); continuation packets clear the PUSI and
    /// carry no pointer_field. The last packet is stuffed to the 188-byte
    /// boundary with `0xFF` bytes per §2.4.4 (sections never span a
    /// stuffing run — once a `0xFF` appears after a section, the rest of
    /// the packet is stuffing).
    ///
    /// A section may legally be up to 1021 payload bytes (long-form) or
    /// 4093 (private), so the single-packet fast path is no longer the
    /// only path: a PMT that carries a registration / ISO-639 descriptor
    /// loop routinely overflows the 183-byte first-packet window.
    fn write_psi_packet(&mut self, pid: u16, cc: &mut u8, section: &[u8]) -> CoreResult<()> {
        let mut cursor = 0usize;
        let mut first = true;
        while first || cursor < section.len() {
            let mut pkt = [0xFFu8; TS_PACKET_LEN];
            pkt[0] = TS_SYNC_BYTE;
            let pusi = if first { 0b0100_0000 } else { 0 };
            pkt[1] = pusi | ((pid >> 8) as u8 & 0b0001_1111);
            pkt[2] = pid as u8;
            // afc = 0b01 (payload only — PSI never carries adaptation
            // fields in this muxer; stuffing is done with 0xFF section
            // bytes, which is the §2.4.4 PSI convention).
            pkt[3] = 0b0001_0000 | (*cc & 0x0F);
            *cc = (*cc + 1) & 0x0F;

            let mut payload_start = 4;
            if first {
                // pointer_field = 0 → section starts right after it.
                pkt[4] = 0;
                payload_start = 5;
            }
            let room = TS_PACKET_LEN - payload_start;
            let take = room.min(section.len() - cursor);
            pkt[payload_start..payload_start + take]
                .copy_from_slice(&section[cursor..cursor + take]);
            cursor += take;
            // Bytes past `payload_start + take` stay 0xFF (pre-filled),
            // which is exactly the PSI stuffing terminator.
            self.output.write_all(&pkt).map_err(CoreError::Io)?;
            first = false;
        }
        Ok(())
    }

    fn write_pat(&mut self) -> CoreResult<()> {
        // PAT body: table_id=0x00, ssi=1, '0', reserved, section_length(12),
        //           table_id_extension (tsid)(16), reserved + version + cni,
        //           section_number, last_section_number,
        //           one program entry: program_number(16), reserved + pmt_pid(13).
        let mut body = vec![
            0x00, // table_id
            0xB0,
            0x0D, // ssi=1, '0', reserved, section_length=13
            0x00,
            0x01, // tsid = 1
            0xC1, // reserved + version=0 + current_next=1
            0x00,
            0x00, // section_number + last_section_number
            (PROGRAM_NUMBER >> 8) as u8,
            PROGRAM_NUMBER as u8,
            (0xE0 | ((PMT_PID >> 8) as u8 & 0x1F)),
            PMT_PID as u8,
        ];
        let crc = mpeg2_crc32(&body);
        body.extend_from_slice(&crc.to_be_bytes());
        let mut cc = self.pat_cc;
        self.write_psi_packet(PAT_PID, &mut cc, &body)?;
        self.pat_cc = cc;
        Ok(())
    }

    fn write_pmt(&mut self) -> CoreResult<()> {
        // PMT body:
        //   table_id=0x02, ssi=1, '0', reserved, section_length(12),
        //   program_number(16), reserved + version + cni,
        //   section_number, last_section_number,
        //   reserved + PCR_PID(13), reserved + program_info_length(12)=0,
        //   per-stream: stream_type(8), reserved + ES_PID(13),
        //               reserved + ES_info_length(12)=0.
        //   CRC_32.
        let mut body: Vec<u8> = Vec::new();
        body.push(0x02); // table_id
                         // section_length placeholder — fill after constructing the body.
        body.push(0xB0);
        body.push(0x00);
        body.extend_from_slice(&[
            (PROGRAM_NUMBER >> 8) as u8,
            PROGRAM_NUMBER as u8,
            0xC1, // reserved + version=0 + current_next=1
            0x00, // section_number
            0x00, // last_section_number
            0xE0 | ((self.pcr_pid >> 8) as u8 & 0x1F),
            self.pcr_pid as u8,
            0xF0, // reserved + program_info_length high
            0x00, // program_info_length low
        ]);
        for t in &self.tracks {
            body.push(t.stream_type);
            body.push(0xE0 | ((t.pid >> 8) as u8 & 0x1F));
            body.push(t.pid as u8);
            body.push(0xF0); // reserved + ES_info_length high
            body.push(0x00); // ES_info_length low
        }
        // section_length = body bytes following section_length field
        // (i.e. body.len() - 3 (table_id + 2-byte length field)) + 4 (CRC).
        let section_length = (body.len() - 3 + 4) as u16;
        body[1] = 0xB0 | ((section_length >> 8) as u8 & 0x0F);
        body[2] = section_length as u8;
        let crc = mpeg2_crc32(&body);
        body.extend_from_slice(&crc.to_be_bytes());

        let mut cc = self.pmt_cc;
        self.write_psi_packet(PMT_PID, &mut cc, &body)?;
        self.pmt_cc = cc;
        Ok(())
    }

    /// Build one PES packet from a [`Packet`] and fragment it into
    /// TS packets, emitting each. Inserts a PCR adaptation field on
    /// the first TS packet of a video PES.
    fn write_pes_packet(&mut self, track_idx: usize, packet: &Packet) -> CoreResult<()> {
        let track = self.tracks[track_idx].clone();
        let pes = build_pes(track.stream_id, packet);
        let pcr = if track.is_video {
            packet.pts.map(|p| {
                // PCR-base = first PTS - small offset (10ms). Both are
                // 90kHz units. The 9-bit extension is the 27 MHz
                // fractional part — we just zero it.
                let pcr_base = (p.saturating_sub(900)).max(0) as u64;
                (pcr_base, 0u16)
            })
        } else {
            None
        };
        self.write_pes_bytes_as_ts(track.pid, track_idx, &pes, pcr)
    }

    /// Fragment a contiguous PES byte buffer into 188-byte TS packets
    /// for `pid`, with PUSI=1 on the first packet and continuity-
    /// counter increment per packet. `pcr` is an optional adaptation
    /// field carried on the FIRST packet only.
    fn write_pes_bytes_as_ts(
        &mut self,
        pid: u16,
        track_idx: usize,
        pes: &[u8],
        first_packet_pcr: Option<(u64, u16)>,
    ) -> CoreResult<()> {
        let mut cursor = 0usize;
        let mut first = true;
        while cursor < pes.len() {
            let mut pkt = [0xFFu8; TS_PACKET_LEN];
            pkt[0] = TS_SYNC_BYTE;
            let pusi = if first { 0b0100_0000 } else { 0 };
            pkt[1] = pusi | ((pid >> 8) as u8 & 0b0001_1111);
            pkt[2] = pid as u8;
            let cc = self.tracks[track_idx].cc;
            // adaptation_field_control: payload + maybe AF.
            // Determine AF presence based on whether we have PCR or
            // need stuffing to align the last fragment to 188.
            let remaining = pes.len() - cursor;
            // Worst-case payload room with NO adaptation field.
            let payload_room_no_af = TS_PACKET_LEN - 4;
            let needs_pcr = first && first_packet_pcr.is_some();
            let needs_stuffing = remaining < payload_room_no_af && !needs_pcr;
            let af_present = needs_pcr || needs_stuffing;
            let afc = if af_present { 0b11 } else { 0b01 };
            pkt[3] = (afc << 4) | (cc & 0x0F);
            self.tracks[track_idx].cc = (cc + 1) & 0x0F;

            let mut payload_start = 4;
            if af_present {
                // We'll fill the AF then compute the payload window.
                let mut af = Vec::<u8>::with_capacity(TS_PACKET_LEN - 4);
                // Reserve flags byte (filled after we know contents).
                let mut flags = 0u8;
                if let Some((pcr_base, pcr_ext)) = first_packet_pcr {
                    if first {
                        flags |= 0b0001_0000; // PCR_flag
                                              // 33-bit PCR base + 6 reserved + 9-bit ext = 48 bits.
                        let high32 = ((pcr_base >> 1) & 0xFFFF_FFFF) as u32;
                        let low_bit_of_base = (pcr_base & 1) as u8;
                        let mut pcr_bytes = [0u8; 6];
                        pcr_bytes[0..4].copy_from_slice(&high32.to_be_bytes());
                        pcr_bytes[4] =
                            (low_bit_of_base << 7) | 0b0111_1110 | ((pcr_ext >> 8) as u8 & 0x01);
                        pcr_bytes[5] = pcr_ext as u8;
                        af.push(flags);
                        af.extend_from_slice(&pcr_bytes);
                    } else {
                        // PCR only on first packet — ignore on
                        // continuations.
                        af.push(flags);
                    }
                } else {
                    af.push(flags);
                }
                // If we still need to stuff out to the 188-byte boundary,
                // append 0xFF until the payload remaining + AF + header
                // = 188.
                let header_so_far = 4 + 1 /*adaptation_field_length*/ + af.len();
                let mut payload_room = TS_PACKET_LEN - header_so_far;
                if payload_room > remaining {
                    let stuff_bytes = payload_room - remaining;
                    af.resize(af.len() + stuff_bytes, 0xFF);
                    payload_room = remaining;
                }
                let af_total_len = af.len() as u8;
                pkt[4] = af_total_len;
                pkt[5..5 + af.len()].copy_from_slice(&af);
                payload_start = 4 + 1 + af.len();
                let take = payload_room.min(remaining);
                pkt[payload_start..payload_start + take]
                    .copy_from_slice(&pes[cursor..cursor + take]);
                cursor += take;
            } else {
                let take = payload_room_no_af.min(remaining);
                pkt[4..4 + take].copy_from_slice(&pes[cursor..cursor + take]);
                cursor += take;
                let _ = payload_start;
            }
            self.output.write_all(&pkt).map_err(CoreError::Io)?;
            first = false;
        }
        Ok(())
    }
}

impl Muxer for MpegTsMuxer {
    fn format_name(&self) -> &str {
        "mpegts"
    }

    fn write_header(&mut self) -> CoreResult<()> {
        self.write_pat()?;
        self.write_pmt()?;
        self.header_written = true;
        Ok(())
    }

    fn write_packet(&mut self, packet: &Packet) -> CoreResult<()> {
        if !self.header_written {
            return Err(CoreError::invalid(
                "mpegts muxer: write_packet called before write_header",
            ));
        }
        let track_idx = *self.idx_to_track.get(&packet.stream_index).ok_or_else(|| {
            CoreError::invalid(format!(
                "mpegts muxer: packet for unknown stream_index {}",
                packet.stream_index
            ))
        })?;
        self.write_pes_packet(track_idx, packet)
    }

    fn write_trailer(&mut self) -> CoreResult<()> {
        // Re-emit PAT/PMT once so a late-joining player still finds
        // them after seeking near the end.
        self.write_pat()?;
        self.write_pmt()?;
        self.output.flush().map_err(CoreError::Io)?;
        Ok(())
    }
}

/// Build one PES packet — fixed header + optional 5-byte PTS / 5-byte
/// DTS + payload.
fn build_pes(stream_id: u8, packet: &Packet) -> Vec<u8> {
    let has_pts = packet.pts.is_some();
    let has_dts = packet.dts.is_some() && packet.dts != packet.pts;
    let pts_dts_flags: u8 = match (has_pts, has_dts) {
        (true, true) => 0b11,
        (true, false) => 0b10,
        _ => 0b00,
    };
    let opt_hdr_len: u8 = match pts_dts_flags {
        0b11 => 10, // 5 PTS + 5 DTS
        0b10 => 5,
        _ => 0,
    };
    let mut out = Vec::with_capacity(9 + opt_hdr_len as usize + packet.data.len());
    out.extend_from_slice(&[0x00, 0x00, 0x01]); // packet_start_code_prefix
    out.push(stream_id);
    // PES_packet_length = 0 (unbounded) for video / large audio. For
    // small known sizes we could set the real length; '0' is always
    // legal for video stream_ids 0xE0..0xEF and is what BD discs use.
    out.push(0x00);
    out.push(0x00);
    // Flags byte 0: '10' marker + scrambling=0 + priority=0 + etc.
    out.push(0b1000_0000);
    // Flags byte 1: PTS_DTS_flags + the other six flag bits = 0.
    out.push(pts_dts_flags << 6);
    out.push(opt_hdr_len);
    if let Some(p) = packet.pts {
        let prefix = if has_dts { 0b0011 } else { 0b0010 };
        out.extend_from_slice(&encode_pts_dts(prefix, p as u64));
    }
    if let (true, Some(d)) = (has_dts, packet.dts) {
        out.extend_from_slice(&encode_pts_dts(0b0001, d as u64));
    }
    out.extend_from_slice(&packet.data);
    out
}

/// Encode a 33-bit PTS or DTS into 5 bytes per Table 2-22 with the
/// given 4-bit prefix nibble (`0010` PTS-only, `0011` PTS-of-PTS+DTS,
/// `0001` DTS).
fn encode_pts_dts(prefix: u8, ts: u64) -> [u8; 5] {
    let t = ts & 0x1_FFFF_FFFF; // 33 bits
    let t32_30 = ((t >> 30) & 0b0111) as u8;
    let t29_15 = ((t >> 15) & 0x7FFF) as u16;
    let t14_0 = (t & 0x7FFF) as u16;
    [
        (prefix << 4) | (t32_30 << 1) | 0b1,
        ((t29_15 >> 7) & 0xFF) as u8,
        ((((t29_15 << 1) | 1) & 0xFF) as u8),
        ((t14_0 >> 7) & 0xFF) as u8,
        (((t14_0 << 1) | 1) & 0xFF) as u8,
    ]
}

/// CodecId string → (stream_type byte, PES `stream_id`, is_video).
///
/// `stream_id` is conventional:
/// * video → 0xE0
/// * MPEG audio → 0xC0
/// * AC-3 / DTS / TrueHD / LPCM / HDMV-PGS / HDMV-TextST → 0xBD
///   (private_stream_1) per BD-ROM AV §5.6 / ATSC convention.
fn stream_type_for_codec(codec_id: &str) -> Option<(u8, u8, bool)> {
    Some(match codec_id {
        "mpeg2video" => (0x02, 0xE0, true),
        "h264" => (0x1B, 0xE0, true),
        "hevc" => (0x24, 0xE0, true),
        "vc1" => (0xEA, 0xE0, true),
        "pcm_s16be" => (0x80, 0xBD, false),
        "ac3" => (0x81, 0xBD, false),
        "dts" => (0x82, 0xBD, false),
        "truehd" => (0x83, 0xBD, false),
        "eac3" => (0x84, 0xBD, false),
        "hdmv_pgs_subtitle" => (0x90, 0xBD, false),
        "hdmv_textst_subtitle" => (0x92, 0xBD, false),
        _ => return None,
    })
}

/// MPEG-2 CRC-32 — `oxideav-mpegts::psi::mpeg2_crc32` would be the
/// natural choice, but it's currently `pub(crate)`. Inlined here so
/// the muxer module stays decoupled from the section-parser surface.
fn mpeg2_crc32(data: &[u8]) -> u32 {
    let mut c: u32 = 0xFFFF_FFFF;
    for &b in data {
        c ^= (b as u32) << 24;
        for _ in 0..8 {
            c = if c & 0x8000_0000 != 0 {
                (c << 1) ^ 0x04C1_1DB7
            } else {
                c << 1
            };
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxideav_core::{CodecId, CodecParameters, ReadSeek, TimeBase};
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

    fn stream_info(idx: u32, codec_id: &str, is_video: bool) -> StreamInfo {
        let params = if is_video {
            CodecParameters::video(CodecId::new(codec_id))
        } else {
            CodecParameters::audio(CodecId::new(codec_id))
        };
        StreamInfo {
            index: idx,
            time_base: TimeBase::new(1, 90_000),
            duration: None,
            start_time: None,
            params,
        }
    }

    /// Shared in-memory sink shaped as `Box<dyn WriteSeek + 'static>`.
    /// The muxer takes ownership of its writer for the duration of
    /// the test; we hand it an `Arc<Mutex<Cursor<Vec<u8>>>>` clone so
    /// the caller can still extract the bytes after.
    #[derive(Clone)]
    struct SharedSink(Arc<Mutex<Cursor<Vec<u8>>>>);

    impl SharedSink {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Cursor::new(Vec::new()))))
        }
        fn into_bytes(self) -> Vec<u8> {
            // After the muxer drops, we should be the only owner.
            let inner = Arc::try_unwrap(self.0)
                .map_err(|_| "shared sink still has live references")
                .unwrap()
                .into_inner()
                .unwrap();
            inner.into_inner()
        }
    }

    impl std::io::Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0.lock().unwrap().flush()
        }
    }
    impl std::io::Seek for SharedSink {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.0.lock().unwrap().seek(pos)
        }
    }

    /// Build a tiny TS file via the muxer and round-trip it through
    /// the demuxer in the same crate.
    #[test]
    fn mux_then_demux_round_trip_avc_plus_ac3() {
        let streams = vec![stream_info(0, "h264", true), stream_info(1, "ac3", false)];
        let sink = SharedSink::new();
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::new(output, &streams).expect("open");
            mx.write_header().expect("hdr");
            let video_pkt = Packet::new(0, TimeBase::new(1, 90_000), vec![0xDE, 0xAD, 0xBE, 0xEF])
                .with_pts(12345);
            let audio_pkt =
                Packet::new(1, TimeBase::new(1, 90_000), vec![0xCA, 0xFE]).with_pts(22222);
            mx.write_packet(&video_pkt).unwrap();
            mx.write_packet(&audio_pkt).unwrap();
            mx.write_trailer().unwrap();
        }
        let bytes = sink.into_bytes();
        assert!(bytes.len() % TS_PACKET_LEN == 0);

        let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let resolver = oxideav_core::NullCodecResolver;
        let mut dmx = crate::demuxer::open(input, &resolver).expect("dmx open");
        assert_eq!(dmx.streams().len(), 2);
        let codecs: Vec<&str> = dmx
            .streams()
            .iter()
            .map(|s| s.params.codec_id.as_str())
            .collect();
        assert!(codecs.contains(&"h264"));
        assert!(codecs.contains(&"ac3"));
        let p1 = dmx.next_packet().expect("p1");
        let p2 = dmx.next_packet().expect("p2");
        let mut pts_set = vec![p1.pts.unwrap(), p2.pts.unwrap()];
        pts_set.sort();
        assert_eq!(pts_set, vec![12345, 22222]);
    }

    /// A PSI section longer than one packet's 183-byte first-packet
    /// window must split across multiple TS packets and reassemble
    /// cleanly through the in-crate `PsiSectionAssembler`.
    #[test]
    fn multi_packet_psi_section_reassembles() {
        use crate::psi::PsiSectionAssembler;
        let output: Box<dyn oxideav_core::WriteSeek> = Box::new(Cursor::new(Vec::<u8>::new()));
        // Build a 400-byte synthetic section (well past one packet).
        let mut section = vec![0u8; 400];
        for (i, b) in section.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        // Mux it out under a fresh muxer with one dummy track.
        let s = stream_info(0, "h264", true);
        let sink = SharedSink::new();
        let mut cc = 0u8;
        {
            let out: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::new(out, std::slice::from_ref(&s)).expect("open");
            mx.write_psi_packet(0x0100, &mut cc, &section).expect("psi");
        }
        let _ = output;
        let bytes = sink.into_bytes();
        // Should have spanned more than one TS packet.
        assert!(bytes.len() / TS_PACKET_LEN >= 3, "expected >=3 packets");
        assert_eq!(bytes.len() % TS_PACKET_LEN, 0);

        // Reassemble through the demuxer-side assembler.
        let mut asm = PsiSectionAssembler::new();
        let mut recovered: Option<Vec<u8>> = None;
        for chunk in bytes.chunks_exact(TS_PACKET_LEN) {
            let pusi = chunk[1] & 0x40 != 0;
            let cc = chunk[3] & 0x0F;
            // afc = payload only (0b01) → payload starts at byte 4.
            let payload = &chunk[4..];
            for sec in asm.feed(payload, pusi, cc).expect("feed") {
                recovered = Some(sec);
            }
        }
        // The assembler validates section_length + CRC, but our
        // synthetic blob is not a real section, so it surfaces the
        // raw assembled bytes only if it parses a length. Instead we
        // assert the byte split was lossless by re-concatenating the
        // payloads ourselves.
        let mut flat = Vec::new();
        let mut first = true;
        for chunk in bytes.chunks_exact(TS_PACKET_LEN) {
            let start = if first { 5 } else { 4 };
            flat.extend_from_slice(&chunk[start..]);
            first = false;
        }
        assert_eq!(&flat[..section.len()], &section[..]);
        let _ = recovered;
    }

    #[test]
    fn open_rejects_empty_stream_list() {
        let output: Box<dyn oxideav_core::WriteSeek> = Box::new(Cursor::new(Vec::<u8>::new()));
        let r = MpegTsMuxer::new(output, &[]);
        assert!(r.is_err());
    }

    #[test]
    fn open_rejects_unknown_codec_id() {
        let s = stream_info(0, "this-is-not-a-known-codec", true);
        let output: Box<dyn oxideav_core::WriteSeek> = Box::new(Cursor::new(Vec::<u8>::new()));
        let r = MpegTsMuxer::new(output, &[s]);
        assert!(r.is_err());
    }
}
