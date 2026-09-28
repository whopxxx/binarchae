//! Network reconstruction shared by the PCAP and PCAPNG handlers
//! (#7 §7): sequence-aware bounded TCP reassembly, HTTP message
//! framing, DNS message parsing, and USB HID keystroke decoding.
//!
//! Layouts verified against:
//! - TCP/IPv4/IPv6: RFC 9293 (TCP), RFC 8200 (IPv6) — offsets are the
//!   classic ones (IPv4 ihl@0&0x0F, proto@9; IPv6 next-header@6,
//!   payload_length@4; TCP seq@+4 u32 BE, data offset@+12 >> 4).
//! - HTTP: RFC 9110/9112 — request line, status line, headers to
//!   CRLFCRLF, Content-Length and Transfer-Encoding: chunked bodies
//!   (chunk-size hex CRLF, data, CRLF, 0-sized last chunk).
//! - DNS: RFC 1035 — header (id/flags/qdcount/ancount/nscount/arcount,
//!   all u16 BE), QNAME labels, question (name+type+class), answers
//!   (name ptr 0xC0|off, type, class, ttl u32, rdlength u16, rdata);
//!   TXT rdata = u8 len + bytes.
//! - USB link-layer (Linux usbmon / LINKTYPE_USB_LINUX_MMAPPED,
//!   linktype 220): usbmon mmapped header 64 bytes — id u64, type u8,
//!   xfer_type u8, epnum u8, devnum u8, busnum u16, flag_setup u8,
//!   flag_data u8, ts_sec u64, ts_usec u32, status i32, length u32,
//!   len_cap u32, s urb flags..., setup bytes at +40 (8), data at +64
//!   when flag_data == '<' (data present inline). Interrupt IN packets
//!   from a keyboard carry 8-byte HID reports: modifier byte, reserved,
//!   6 key codes (HID usage IDs 0x04..=0x31 map to a..z, 0x1E..=0x27 to
//!   1..0 per the USB HID Usage Tables).
//!
//! Boundaries: no full TCP stack — per-flow segments are ordered by
//! sequence number with duplicate/out-of-order handling and honest gap
//! reporting; stream count and byte limits come from EngineLimits
//! (max_streams, max_reconstructed_bytes).

use crate::artifact::RelationKind;
use crate::bytesource::ByteSource;
use crate::engine::{ChildContent, ChildDraft};
use std::collections::BTreeMap;

/// One direction of a TCP flow's reassembly state. Segments are
/// buffered per sequence and merged at finish() — this handles
/// out-of-order arrival without assuming the first capture is the
/// lowest sequence.
#[derive(Default)]
struct DirState {
    /// seq -> payload bytes (BTreeMap orders by sequence).
    segs: BTreeMap<u32, Vec<u8>>,
}

impl DirState {
    /// FINAL-B6: `remaining` is the REASSEMBLER-WIDE budget left for
    /// this segment (global cap minus bytes buffered everywhere), so
    /// the cap is truly global: per-direction caps let one flow hold
    /// 2x the limit and N flows hold Nx. New bytes only count when
    /// they extend a segment (retransmissions are deduplicated).
    fn push(&mut self, seq: u32, payload: &[u8], remaining: u64) {
        if payload.is_empty() {
            return;
        }
        let existing_len = self.segs.get(&seq).map(Vec::len).unwrap_or(0) as u64;
        let new_bytes = (payload.len() as u64).saturating_sub(existing_len);
        if new_bytes == 0 || new_bytes > remaining {
            return;
        }
        let s = self.segs.entry(seq).or_default();
        if payload.len() > s.len() {
            // Retransmission: keep the longest payload for this seq
            // (more data wins; overlap resolution happens at merge).
            *s = payload.to_vec();
        }
    }

    /// Merge all buffered segments into one contiguous stream.
    /// Returns (data, gaps). Overlapping retransmitted bytes are
    /// dropped; a jump between consecutive segments is a gap.
    fn finish(self) -> (Vec<u8>, usize) {
        let mut data = Vec::new();
        let mut gaps = 0usize;
        let mut next: Option<u32> = None;
        for (seq, seg) in self.segs {
            match next {
                None => data.extend_from_slice(&seg),
                Some(n) => {
                    // Segments are in ascending seq order (BTreeMap), so
                    // seq >= n always once n is set. A seq past the
                    // expected n is a gap.
                    if seq > n {
                        gaps += 1;
                    }
                    let overlap = n.saturating_sub(seq) as usize;
                    if overlap < seg.len() {
                        data.extend_from_slice(&seg[overlap..]);
                    }
                }
            }
            next = Some(next.map_or(seq, |n: u32| n.max(seq.wrapping_add(seg.len() as u32))));
        }
        (data, gaps)
    }
}

/// One reassembled TCP flow (both directions).
pub struct TcpFlow {
    pub key: Vec<u8>,
    pub client: Vec<u8>,
    pub server: Vec<u8>,
    pub client_gaps: usize,
    pub server_gaps: usize,
}

/// One parsed TCP segment: (flow_key, seq, payload_len, payload).
pub type TcpSegment = (Vec<u8>, u32, u64, Vec<u8>);

/// L2/L3/L4 parse of one captured frame: returns (flow_key, seq,
/// payload) for TCP data segments. `linktype` is the PCAP linktype (1 =
/// Ethernet, 220/209 = usbLinux; only Ethernet carries TCP).
/// Returns Ok(None) for non-TCP frames.
#[allow(clippy::too_many_arguments)]
pub fn parse_tcp_frame(
    src: &ByteSource,
    frame_start: u64,
    frame_len: u64,
    linktype: u32,
    is_v6: bool,
) -> std::result::Result<Option<TcpSegment>, String> {
    let _ = (is_v6,);
    let packet_end = frame_start + frame_len;
    if linktype != 1 || frame_start + 14 > packet_end {
        return Ok(None);
    }
    let mut eth = [0u8; 14];
    src.read_at(frame_start, &mut eth)
        .map_err(|e| e.to_string())?;
    let mut ethertype = u16::from_be_bytes([eth[12], eth[13]]);
    let mut l3 = frame_start + 14;
    if ethertype == 0x8100 && l3 + 4 <= packet_end {
        let mut vlan = [0u8; 4];
        src.read_at(l3, &mut vlan).map_err(|e| e.to_string())?;
        ethertype = u16::from_be_bytes([vlan[2], vlan[3]]);
        l3 += 4;
    }
    match ethertype {
        0x0800 => {
            if l3 + 20 > packet_end {
                return Ok(None);
            }
            let mut h = [0u8; 20];
            src.read_at(l3, &mut h).map_err(|e| e.to_string())?;
            let ihl = u64::from(h[0] & 0x0F) * 4;
            if ihl < 20 || l3 + ihl > packet_end || h[9] != 6 {
                return Ok(None);
            }
            let total_length = u64::from(u16::from_be_bytes([h[2], h[3]])).max(ihl);
            let ip_end = l3 + total_length;
            if l3 + ihl + 20 > packet_end {
                return Ok(None);
            }
            let mut tp = [0u8; 20];
            src.read_at(l3 + ihl, &mut tp).map_err(|e| e.to_string())?;
            let data_off = u64::from(tp[12] >> 4) * 4;
            if data_off < 20 || l3 + ihl + data_off > packet_end {
                return Ok(None);
            }
            let payload_len = packet_end.min(ip_end).saturating_sub(l3 + ihl + data_off);
            let mut payload = vec![0u8; payload_len as usize];
            if payload_len > 0 {
                src.read_at(l3 + ihl + data_off, &mut payload)
                    .map_err(|e| e.to_string())?;
            }
            let seq = u32::from_be_bytes([tp[4], tp[5], tp[6], tp[7]]);
            // Direction-aware key: both directions of one connection
            // share the key; the payload direction is recorded in the
            // key's last byte (1 client->server, 2 server->client) by
            // normalizing endpoint order.
            let a = h[12..16].to_vec();
            let b = h[16..20].to_vec();
            let sp = [tp[0], tp[1]];
            let dp = [tp[2], tp[3]];
            let dir1 = [a.as_slice(), &sp, b.as_slice(), &dp];
            let dir2 = [b.as_slice(), &dp, a.as_slice(), &sp];
            let mut key = Vec::with_capacity(16);
            let dir_byte = if dir1 < dir2 {
                key.extend_from_slice(&a);
                key.extend_from_slice(&b);
                key.extend_from_slice(&sp);
                key.extend_from_slice(&dp);
                1u8
            } else {
                key.extend_from_slice(&b);
                key.extend_from_slice(&a);
                key.extend_from_slice(&dp);
                key.extend_from_slice(&sp);
                2u8
            };
            key.push(dir_byte);
            Ok(Some((key, seq, payload_len, payload)))
        }
        _ => Ok(None),
    }
}

/// State machine over a capture's frames: feed every TCP frame's
/// (key, seq, payload) here in capture order.
#[derive(Default)]
pub struct TcpReassembler {
    flows: BTreeMap<Vec<u8>, (DirState, DirState)>,
    pub total_bytes: u64,
    max_bytes: u64,
    max_flows: usize,
}

impl TcpReassembler {
    pub fn new(max_flows: usize, max_bytes: u64) -> Self {
        TcpReassembler {
            max_flows,
            max_bytes,
            ..Default::default()
        }
    }

    /// Reassembler-wide buffered bytes (deduplicated across flows and
    /// directions). This is the quantity the byte cap applies to.
    fn buffered_bytes(&self) -> u64 {
        self.flows
            .values()
            .map(|(c, s)| {
                let c: u64 = c.segs.values().map(|v| v.len() as u64).sum();
                let s: u64 = s.segs.values().map(|v| v.len() as u64).sum();
                c + s
            })
            .sum()
    }

    pub fn feed(&mut self, key: &[u8], seq: u32, payload: &[u8]) {
        if payload.is_empty() || self.buffered_bytes() >= self.max_bytes {
            return;
        }
        // FINAL-B6: the lookup key is the FLOW key (key without the
        // direction byte) — using the full key here rejected every
        // segment after the first of an existing flow once the flow
        // count reached the cap, and in general keyed lookups at the
        // wrong granularity.
        let dir = match key.split_last() {
            Some((&d, fk)) => {
                if !self.flows.contains_key(fk) && self.flows.len() >= self.max_flows {
                    return;
                }
                d
            }
            None => return,
        };
        // Buffered bytes BEFORE this segment; the push itself adds the
        // deduplicated delta, so the global cap is checked against the
        // pre-feed total plus the delta inside push (no re-entrant
        // borrow needed).
        let spent_before = self.buffered_bytes();
        let entry = self.flows.entry(key[..key.len() - 1].to_vec()).or_default();
        let (c, s) = &mut *entry;
        if dir == 1 {
            c.push(seq, payload, self.max_bytes.saturating_sub(spent_before));
        } else {
            s.push(seq, payload, self.max_bytes.saturating_sub(spent_before));
        }
    }

    /// Reconstructed flows in discovery order with gap stats.
    /// Merges (drains) the per-direction segment buffers.
    pub fn flows(self) -> Vec<TcpFlow> {
        self.flows
            .into_iter()
            .map(|(key, (c, s))| {
                let (client, cg) = c.finish();
                let (server, sg) = s.finish();
                TcpFlow {
                    key,
                    client,
                    server,
                    client_gaps: cg,
                    server_gaps: sg,
                }
            })
            .collect()
    }
}

/// HTTP messages carved from one reassembled stream (one direction).
/// Returns (method_or_status, body, complete, is_chunked).
pub fn extract_http_messages(
    stream: &[u8],
    max_messages: usize,
    max_body: usize,
) -> Vec<(String, Vec<u8>, bool, bool)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 4 < stream.len() && out.len() < max_messages {
        let window = &stream[pos..];
        let header_end = match find_sub(window, b"\r\n\r\n") {
            Some(h) => h + 4,
            None => break,
        };
        let head = String::from_utf8_lossy(&window[..header_end]).to_string();
        let first = head.lines().next().unwrap_or("");
        let is_http = first.starts_with("HTTP/")
            || first.starts_with("GET ")
            || first.starts_with("POST ")
            || first.starts_with("PUT ")
            || first.starts_with("DELETE ")
            || first.starts_with("HEAD ");
        if !is_http {
            pos += header_end;
            continue;
        }
        let mut content_length = 0usize;
        let mut chunked = false;
        for l in head.lines() {
            let lower = l.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap_or(0);
            }
            if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
                chunked = true;
            }
        }
        let body_start = header_end;
        let (body, complete) = if chunked {
            decode_chunked(&window[body_start..], max_body)
        } else {
            let want = content_length.min(max_body);
            let have = window.len().saturating_sub(body_start);
            let take = want.min(have);
            (window[body_start..body_start + take].to_vec(), take == want)
        };
        out.push((first.to_string(), body.clone(), complete, chunked));
        // Advance past the body: chunked bodies have no fixed length —
        // scan to the terminating 0 chunk inside decode_chunked and
        // approximate here (body len + 1 is a lower bound; give up if
        // we cannot move forward).
        let advanced = body.len();
        if advanced == 0 {
            pos += header_end;
        } else {
            pos += header_end + advanced;
        }
    }
    out
}

/// Chunked body decode: returns (decoded, complete).
fn decode_chunked(data: &[u8], max_body: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let line_end = match find_sub(&data[pos..], b"\r\n") {
            Some(h) => pos + h,
            None => return (out, false),
        };
        let size_str = String::from_utf8_lossy(&data[pos..line_end]);
        let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16)
            .unwrap_or(usize::MAX);
        if size == usize::MAX {
            return (out, false);
        }
        pos = line_end + 2;
        if size == 0 {
            return (out, true);
        }
        if pos + size > data.len() || out.len() + size > max_body {
            // Take what's there and report incomplete.
            let take = data.len().saturating_sub(pos).min(max_body - out.len());
            out.extend_from_slice(&data[pos..pos + take]);
            return (out, false);
        }
        out.extend_from_slice(&data[pos..pos + size]);
        pos += size + 2; // skip trailing CRLF
    }
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

// ---------------------------------------------------------------------------
// DNS (RFC 1035)
// ---------------------------------------------------------------------------

/// Parsed DNS answer rdata of interest (TXT / NULL / raw).
pub struct DnsAnswer {
    pub name: String,
    pub rtype: u16,
    pub rdata: Vec<u8>,
}

pub struct DnsMessage {
    pub id: u16,
    pub queries: Vec<String>,
    pub answers: Vec<DnsAnswer>,
}

fn parse_dns_name(data: &[u8], mut pos: usize, depth: usize) -> Option<(String, usize)> {
    if depth > 8 {
        return None;
    }
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end = pos;
    let mut hops = 0;
    loop {
        if pos >= data.len() || hops > 64 {
            return None;
        }
        let len = data[pos];
        match len {
            0 => {
                if !jumped {
                    end = pos + 1;
                }
                break;
            }
            0xC0..=0xFF => {
                if pos + 1 >= data.len() {
                    return None;
                }
                let ptr = ((u16::from(len) & 0x3F) << 8) | u16::from(data[pos + 1]);
                if !jumped {
                    end = pos + 2;
                    jumped = true;
                }
                pos = usize::from(ptr);
                hops += 1;
            }
            _ => {
                let l = usize::from(len);
                if pos + 1 + l > data.len() {
                    return None;
                }
                labels.push(String::from_utf8_lossy(&data[pos + 1..pos + 1 + l]).into_owned());
                pos += 1 + l;
            }
        }
    }
    if depth == 0 {
        let _ = end;
    }
    Some((labels.join("."), end))
}

/// Parse a DNS message from a UDP payload or TCP-framed chunk.
pub fn parse_dns(data: &[u8]) -> Option<DnsMessage> {
    if data.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([data[0], data[1]]);
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut queries = Vec::new();
    let mut answers = Vec::new();
    let mut pos = 12usize;
    for _ in 0..qd.min(16) {
        let (name, np) = parse_dns_name(data, pos, 0)?;
        pos = np + 4; // type + class
        queries.push(name);
    }
    for _ in 0..an.min(256) {
        let (name, np) = parse_dns_name(data, pos, 0)?;
        pos = np;
        if pos + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > data.len() {
            break;
        }
        let rdata = data[pos..pos + rdlen].to_vec();
        // TXT rdata: one or more character-strings (u8 len + bytes).
        // Truncated final strings still yield their readable part.
        let rdata = if rtype == 16 {
            let mut txt = Vec::new();
            let mut p = 0usize;
            while p < rdata.len() {
                let l = usize::from(rdata[p]);
                let take = (p + 1 + l).min(rdata.len()) - (p + 1).min(rdata.len());
                if take == 0 {
                    break;
                }
                txt.extend_from_slice(&rdata[p + 1..p + 1 + take]);
                p += 1 + l;
            }
            txt
        } else {
            rdata
        };
        answers.push(DnsAnswer { name, rtype, rdata });
        pos += rdlen;
    }
    Some(DnsMessage {
        id,
        queries,
        answers,
    })
}

// ---------------------------------------------------------------------------
// USB HID (usbmon mmapped, LINKTYPE 220)
// ---------------------------------------------------------------------------

/// HID usage-id -> printable key for a US layout. Only the common set;
/// unmapped IDs return None.
pub fn hid_key(code: u8, shift: bool) -> Option<char> {
    let lower = [
        Some('a'),
        Some('b'),
        Some('c'),
        Some('d'),
        Some('e'),
        Some('f'),
        Some('g'),
        Some('h'),
        Some('i'),
        Some('j'),
        Some('k'),
        Some('l'),
        Some('m'),
        Some('n'),
        Some('o'),
        Some('p'),
        Some('q'),
        Some('r'),
        Some('s'),
        Some('t'),
        Some('u'),
        Some('v'),
        Some('w'),
        Some('x'),
        Some('y'),
        Some('z'),
        Some('1'),
        Some('2'),
        Some('3'),
        Some('4'),
        Some('5'),
        Some('6'),
        Some('7'),
        Some('8'),
        Some('9'),
        Some('0'),
        Some('\n'),
        Some('\x1b'),
        Some('\x08'),
        Some('\t'),
        Some(' '),
        Some('-'),
        Some('='),
        Some('['),
        Some(']'),
        Some('\\'),
        None,
        Some(';'),
        Some('\''),
        Some('`'),
        Some(','),
        Some('.'),
        Some('/'),
    ];
    let shifted = [
        Some('A'),
        Some('B'),
        Some('C'),
        Some('D'),
        Some('E'),
        Some('F'),
        Some('G'),
        Some('H'),
        Some('I'),
        Some('J'),
        Some('K'),
        Some('L'),
        Some('M'),
        Some('N'),
        Some('O'),
        Some('P'),
        Some('Q'),
        Some('R'),
        Some('S'),
        Some('T'),
        Some('U'),
        Some('V'),
        Some('W'),
        Some('X'),
        Some('Y'),
        Some('Z'),
        Some('!'),
        Some('@'),
        Some('#'),
        Some('$'),
        Some('%'),
        Some('^'),
        Some('&'),
        Some('*'),
        Some('('),
        Some(')'),
        Some('\n'),
        Some('\x1b'),
        Some('\x08'),
        Some('\t'),
        Some(' '),
        Some('_'),
        Some('+'),
        Some('{'),
        Some('}'),
        Some('|'),
        None,
        Some(':'),
        Some('"'),
        Some('~'),
        Some('<'),
        Some('>'),
        Some('?'),
    ];
    let idx = usize::from(code.checked_sub(4)?);
    if idx >= lower.len() {
        return None;
    }
    if shift {
        shifted[idx]
    } else {
        lower[idx]
    }
}

/// usbmon mmapped packet: (device, endpoint, data payload).
pub struct UsbPacket {
    pub dev: u8,
    pub ep: u8,
    pub data: Vec<u8>,
}

/// Parse a usbmon-mmapped frame (linktype 220): 64-byte header, data
/// follows when flag_data == '<' (0x3C).
pub fn parse_usbmon(src: &ByteSource, frame_start: u64, frame_len: u64) -> Option<UsbPacket> {
    if frame_len < 64 {
        return None;
    }
    let base = frame_start;
    let xfer = read_u8(src, base + 9)?;
    let _epnum = read_u8(src, base + 10)?;
    let dev = read_u8(src, base + 11)?;
    let flag_data = read_u8(src, base + 19)?;
    let len_cap = u32::from_le_bytes([
        read_u8(src, base + 36)?,
        read_u8(src, base + 37)?,
        read_u8(src, base + 38)?,
        read_u8(src, base + 39)?,
    ]);
    if flag_data != b'<' || len_cap == 0 {
        return None;
    }
    let take = len_cap.min((frame_len - 64) as u32) as usize;
    let mut data = vec![0u8; take];
    src.read_at(base + 64, &mut data).ok()?;
    Some(UsbPacket {
        dev,
        ep: xfer,
        data,
    })
}

fn read_u8(src: &ByteSource, off: u64) -> Option<u8> {
    let mut b = [0u8; 1];
    src.read_at(off, &mut b).ok()?;
    Some(b[0])
}

/// Reconstruct keystrokes from interrupt IN HID reports (8-byte):
/// byte 0 = modifier (shift = 0x22/0x20), byte 2..8 = key codes.
/// `prev` tracks the previous report to detect key-down edges.
pub struct HidDecoder {
    prev: [u8; 6],
    text: String,
    max_chars: usize,
}

impl HidDecoder {
    pub fn new(max_chars: usize) -> Self {
        HidDecoder {
            prev: [0; 6],
            text: String::new(),
            max_chars,
        }
    }

    pub fn feed(&mut self, report: &[u8]) {
        if report.len() < 8 {
            return;
        }
        let shift = report[0] & 0x22 != 0;
        for &code in &report[2..8] {
            if code == 0 || self.prev.contains(&code) {
                continue;
            }
            if let Some(c) = hid_key(code, shift) {
                if self.text.len() < self.max_chars {
                    self.text.push(c);
                }
            }
        }
        self.prev.copy_from_slice(&report[2..8]);
    }

    pub fn text(self) -> String {
        self.text
    }
}

/// Convenience: build a ChildDraft for reconstructed content.
#[allow(clippy::too_many_arguments)]
/// FINAL-B6: channel decoding — CTF exfil hides payloads in DNS
/// rdata as base64 or hex. A printable rdata that decodes cleanly as
/// one of the two yields nested artifact bytes.
pub fn decode_channel(rdata: &[u8]) -> Option<(&'static str, Vec<u8>)> {
    if rdata.is_empty() || rdata.len() > 64 * 1024 {
        return None;
    }
    const PRINTABLE_WS: &[u8] = b" 	
";
    if !rdata
        .iter()
        .all(|b| b.is_ascii_graphic() || PRINTABLE_WS.contains(b))
    {
        return None;
    }
    let text = String::from_utf8_lossy(rdata);
    let trimmed = text.trim();
    // Hex: even length, all hex digits, length >= 8.
    let hex_ok = trimmed.len() >= 8
        && trimmed.len() % 2 == 0
        && trimmed.as_bytes().iter().all(|b| b.is_ascii_hexdigit());
    if hex_ok {
        let bytes: Vec<u8> = trimmed
            .as_bytes()
            .chunks_exact(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect();
        return Some(("hex", bytes));
    }
    // Base64 (standard alphabet, optional padding, length >= 8).
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let compact: Vec<u8> = trimmed
        .as_bytes()
        .iter()
        .copied()
        .filter(|b| {
            !b" 	
"
            .contains(b)
        })
        .collect();
    if compact.len() >= 8
        && compact.len() % 4 == 0
        && compact.iter().all(|b| B64.contains(b) || *b == b'=')
    {
        let mut out = Vec::with_capacity(compact.len() / 4 * 3);
        for chunk in compact.chunks_exact(4) {
            let mut vals = [0u32; 4];
            let mut pad = 0usize;
            for (i, c) in chunk.iter().enumerate() {
                if *c == b'=' {
                    pad += 1;
                    vals[i] = 0;
                } else {
                    vals[i] = B64.iter().position(|v| v == c).unwrap_or(0) as u32;
                }
            }
            let n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
            out.push((n >> 16) as u8);
            if pad < 2 {
                out.push((n >> 8) as u8);
            }
            if pad < 1 {
                out.push(n as u8);
            }
        }
        return Some(("base64", out));
    }
    None
}

pub fn owned_child(
    relation: RelationKind,
    label: String,
    format_hint: &'static str,
    bytes: Vec<u8>,
    meta: BTreeMap<String, String>,
) -> ChildDraft {
    ChildDraft {
        relation,
        label,
        format_hint,
        content: ChildContent::Owned(bytes),
        size: meta.get("size").and_then(|s| s.parse().ok()).unwrap_or(0),
        metadata: meta,
        warnings: Vec::new(),
        entry_name: None,
    }
}

/// Reconstructed reconstruction result shared by capture containers.
pub struct Reconstructed {
    pub children: Vec<ChildDraft>,
    pub flow_summary: Vec<(String, usize, usize)>,
    pub dns_messages: usize,
    pub usb_reports: usize,
}

/// Post-process raw frames (from ANY capture container): TCP
/// reassembly -> HTTP framing, DNS-over-UDP parsing, USB HID
/// keystrokes. `frames` yields (frame_start, frame_len) in capture
/// order; `read` pulls one frame's bytes. Shared by the PCAP and
/// PCAPNG handlers (#7 §7.1 parity).
/// One capture frame with the LINKTYPE of the interface it arrived on
/// (FINAL-B6: PCAPNG EPBs name their interface; each interface has its
/// own IDB linktype. Classic PCAP uses one linktype for all frames).
pub struct FrameRef {
    pub start: u64,
    pub len: u64,
    pub linktype: u32,
}

pub fn reconstruct_frames(
    frames: &[FrameRef],
    _linktype: u32,
    limits: &crate::engine::EngineLimits,
    read_frame: impl Fn(u64, u64) -> Option<Vec<u8>>,
) -> Reconstructed {
    let mut reasm = TcpReassembler::new(limits.max_streams, limits.max_reconstructed_bytes);
    let mut dns_payloads: Vec<Vec<u8>> = Vec::new();
    let mut hid = HidDecoder::new(4096);
    let mut usb_reports = 0usize;
    for FrameRef {
        start: frame_start,
        len: frame_len,
        linktype,
    } in frames
    {
        let frame = match read_frame(*frame_start, *frame_len) {
            Some(f) => f,
            None => continue,
        };
        if *linktype == 220 {
            // USB (usbmon mmapped): 64-byte header + data.
            if frame.len() >= 64 && frame[19] == b'<' {
                let len_cap = u32::from_le_bytes([frame[36], frame[37], frame[38], frame[39]])
                    .min((frame.len() - 64) as u32) as usize;
                let xfer = frame[9];
                if len_cap == 8 && xfer == 1 {
                    hid.feed(&frame[64..64 + 8]);
                    usb_reports += 1;
                }
            }
            continue;
        }
        // Ethernet TCP segments.
        if frame.len() >= 14 {
            if let Ok(Some((key, seq, _len, payload))) = parse_tcp_frame_bytes(&frame) {
                reasm.feed(&key, seq, &payload);
            }
            // DNS over UDP (IPv4 proto 17, dport 53).
            parse_dns_from_frame(&frame, &mut dns_payloads);
        }
    }

    let mut children = Vec::new();
    let mut flow_summary = Vec::new();
    let flow_buffers = reasm.flows();
    for flow in &flow_buffers {
        let key_hex: String = flow.key.iter().map(|b| format!("{b:02x}")).collect();
        let gcount = flow.client_gaps + flow.server_gaps;
        for (dir_name, data) in [("c2s", &flow.client), ("s2c", &flow.server)] {
            if data.len() < 16 {
                continue;
            }
            for (first, body, complete, chunked) in
                extract_http_messages(data, limits.max_records.min(256), 16 * 1024 * 1024)
            {
                if children.len() >= limits.max_records {
                    break;
                }
                let mut meta = BTreeMap::new();
                meta.insert("flow".to_string(), key_hex.clone());
                meta.insert("direction".to_string(), dir_name.to_string());
                meta.insert("request_line".to_string(), first.clone());
                meta.insert("complete".to_string(), complete.to_string());
                if chunked {
                    meta.insert("transfer_encoding".to_string(), "chunked".to_string());
                }
                if gcount > 0 {
                    meta.insert("tcp_gaps".to_string(), gcount.to_string());
                }
                let mut label = format!(
                    "HTTP body ({} bytes, {})",
                    body.len(),
                    if complete { "complete" } else { "partial" }
                );
                if chunked {
                    label.push_str(", de-chunked");
                }
                meta.insert("size".to_string(), body.len().to_string());
                children.push(owned_child(
                    RelationKind::ReconstructedFrom,
                    label,
                    "http",
                    body,
                    meta,
                ));
            }
        }
        flow_summary.push((key_hex, flow.client.len() + flow.server.len(), gcount));
    }

    let mut dns_messages = 0usize;
    for payload in &dns_payloads {
        if let Some(msg) = parse_dns(payload) {
            dns_messages += 1;
            for ans in &msg.answers {
                if children.len() >= limits.max_records || ans.rdata.is_empty() {
                    continue;
                }
                let printable = ans
                    .rdata
                    .iter()
                    .filter(|b| b.is_ascii_graphic() || **b == b'\n')
                    .count();
                if ans.rtype != 16 && ans.rtype != 10 && printable * 2 < ans.rdata.len() {
                    continue;
                }
                let mut meta = BTreeMap::new();
                meta.insert("dns_id".to_string(), msg.id.to_string());
                meta.insert(
                    "query".to_string(),
                    msg.queries.first().cloned().unwrap_or_default(),
                );
                meta.insert("answer_name".to_string(), ans.name.clone());
                meta.insert("rr_type".to_string(), ans.rtype.to_string());
                meta.insert("size".to_string(), ans.rdata.len().to_string());
                children.push(owned_child(
                    RelationKind::ReconstructedFrom,
                    format!(
                        "DNS rdata {} ({} bytes, type {})",
                        ans.name,
                        ans.rdata.len(),
                        ans.rtype
                    ),
                    "raw",
                    ans.rdata.clone(),
                    meta,
                ));
                if let Some((codec, decoded)) = decode_channel(&ans.rdata) {
                    let mut dmeta = BTreeMap::new();
                    dmeta.insert("codec".to_string(), codec.to_string());
                    dmeta.insert("source".to_string(), "dns-udp".to_string());
                    dmeta.insert(
                        "query".to_string(),
                        msg.queries.first().cloned().unwrap_or_default(),
                    );
                    dmeta.insert("size".to_string(), decoded.len().to_string());
                    children.push(owned_child(
                        RelationKind::ReconstructedFrom,
                        format!(
                            "Decoded {} payload from DNS rdata ({} bytes)",
                            codec,
                            decoded.len()
                        ),
                        "raw",
                        decoded,
                        dmeta,
                    ));
                }
            }
        }
    }

    // FINAL-B6: DNS over TCP — port 53 flows carry length-prefixed
    // DNS messages (u16 BE length + message). The reassembled stream
    // is walked as a sequence of framed messages in each direction.
    for flow in &flow_buffers {
        let key_hex: String = flow.key.iter().map(|b| format!("{b:02x}")).collect();
        // TCP DNS ports: src/dst ports are the 3rd/5th bytes of the
        // flow key (addr(4) port(2) addr(4) port(2)).
        if flow.key.len() < 12 {
            continue;
        }
        // Flow key layout (dir byte stripped): addr_a(4) addr_b(4)
        // port_a(2) port_b(2) — ports at [8..10] and [10..12].
        let sp = u16::from_be_bytes([flow.key[8], flow.key[9]]);
        let dp = u16::from_be_bytes([flow.key[10], flow.key[11]]);
        if sp != 53 && dp != 53 {
            continue;
        }
        for (data, dir_name) in [(&flow.client, "c2s"), (&flow.server, "s2c")] {
            let mut pos = 0usize;
            while pos + 2 <= data.len() && dns_messages < limits.max_records {
                let msg_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                if msg_len == 0 || pos + 2 + msg_len > data.len() {
                    break;
                }
                let framed = &data[pos + 2..pos + 2 + msg_len];
                pos += 2 + msg_len;
                if let Some(msg) = parse_dns(framed) {
                    dns_messages += 1;
                    for ans in &msg.answers {
                        if ans.rdata.is_empty() || children.len() >= limits.max_records {
                            continue;
                        }
                        let printable = ans
                            .rdata
                            .iter()
                            .filter(|b| b.is_ascii_graphic() || **b == b'\n')
                            .count();
                        if ans.rtype != 16 && ans.rtype != 10 && printable * 2 < ans.rdata.len() {
                            continue;
                        }
                        let mut meta = BTreeMap::new();
                        meta.insert("dns_id".to_string(), msg.id.to_string());
                        meta.insert(
                            "query".to_string(),
                            msg.queries.first().cloned().unwrap_or_default(),
                        );
                        meta.insert("answer_name".to_string(), ans.name.clone());
                        meta.insert("rr_type".to_string(), ans.rtype.to_string());
                        meta.insert("transport".to_string(), "tcp".to_string());
                        meta.insert("direction".to_string(), dir_name.to_string());
                        meta.insert("flow".to_string(), key_hex.clone());
                        meta.insert("size".to_string(), ans.rdata.len().to_string());
                        children.push(owned_child(
                            RelationKind::ReconstructedFrom,
                            format!(
                                "DNS-over-TCP rdata {} ({} bytes, type {})",
                                ans.name,
                                ans.rdata.len(),
                                ans.rtype
                            ),
                            "raw",
                            ans.rdata.clone(),
                            meta,
                        ));
                        if let Some((codec, decoded)) = decode_channel(&ans.rdata) {
                            let mut dmeta = BTreeMap::new();
                            dmeta.insert("codec".to_string(), codec.to_string());
                            dmeta.insert("source".to_string(), "dns-tcp".to_string());
                            dmeta.insert(
                                "query".to_string(),
                                msg.queries.first().cloned().unwrap_or_default(),
                            );
                            dmeta.insert("size".to_string(), decoded.len().to_string());
                            children.push(owned_child(
                                RelationKind::ReconstructedFrom,
                                format!(
                                    "Decoded {} payload from DNS-over-TCP rdata ({} bytes)",
                                    codec,
                                    decoded.len()
                                ),
                                "raw",
                                decoded,
                                dmeta,
                            ));
                        }
                    }
                }
            }
        }
    }

    let text = hid.text();
    if usb_reports > 0 && !text.is_empty() {
        let mut meta = BTreeMap::new();
        meta.insert("keystrokes".to_string(), text.chars().count().to_string());
        meta.insert("reports".to_string(), usb_reports.to_string());
        meta.insert("size".to_string(), text.len().to_string());
        children.push(owned_child(
            RelationKind::ReconstructedFrom,
            format!("USB HID keystrokes ({} chars)", text.chars().count()),
            "text",
            text.into_bytes(),
            meta,
        ));
    }

    Reconstructed {
        children,
        flow_summary,
        dns_messages,
        usb_reports,
    }
}

/// Parse TCP from a fully-read frame's bytes.
fn parse_tcp_frame_bytes(frame: &[u8]) -> std::result::Result<Option<TcpSegment>, String> {
    let src = ByteSource::from_vec(frame.to_vec());
    parse_tcp_frame(&src, 0, frame.len() as u64, 1, false)
}

/// Extract a DNS payload from a raw Ethernet frame if it's IPv4/UDP/53.
fn parse_dns_from_frame(frame: &[u8], out: &mut Vec<Vec<u8>>) {
    if frame.len() < 14 + 20 + 8 + 12 {
        return;
    }
    let ihl = u64::from(frame[14] & 0x0F) * 4;
    if frame[14] >> 4 != 4 || frame.len() < 14 + ihl as usize + 8 {
        return;
    }
    let proto = frame[14 + 9];
    if proto != 17 {
        return;
    }
    let udp = 14 + ihl as usize;
    let dport = u16::from_be_bytes([frame[udp + 2], frame[udp + 3]]);
    if dport != 53 {
        return;
    }
    let dns = &frame[udp + 8..];
    if dns.len() >= 12 && dns.len() <= 512 {
        out.push(dns.to_vec());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FINAL-B6: max_streams must not reject later segments of an
    /// ALREADY-TRACKED flow (the old lookup used the full key with the
    /// direction byte while flows are stored without it).
    #[test]
    fn reassembler_existing_flow_survives_stream_cap() {
        let mut reasm = TcpReassembler::new(1, 1 << 20);
        // Flow key: 12 bytes + dir byte.
        let mut k1 = vec![0u8; 13];
        k1[12] = 1;
        reasm.feed(&k1, 0, b"first");
        // Same flow, opposite direction: full key differs in the dir
        // byte; the flow is already tracked so this must be accepted
        // even at max_flows = 1.
        let mut k2 = k1.clone();
        k2[12] = 2;
        reasm.feed(&k2, 0, b"response-from-server");
        let flows = reasm.flows();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].client, b"first");
        assert_eq!(flows[0].server, b"response-from-server");
    }

    /// FINAL-B6: the reconstructed-bytes cap is GLOBAL — N flows and
    /// both directions together cannot exceed max_bytes.
    #[test]
    fn reassembler_byte_cap_is_global() {
        let mut reasm = TcpReassembler::new(64, 1000);
        // 10 flows x 2 directions x 300 bytes would be 6000 without a
        // global cap; with the global cap the buffered total stays
        // <= 1000.
        for i in 0..10u32 {
            for dir in 1..=2u8 {
                let mut k = vec![0u8; 13];
                k[0..4].copy_from_slice(&i.to_le_bytes());
                k[12] = dir;
                reasm.feed(&k, 0, &[b'A'; 300]);
            }
        }
        let flows = reasm.flows();
        let total: usize = flows.iter().map(|f| f.client.len() + f.server.len()).sum();
        assert!(total <= 1000, "global byte cap must hold: {total} > 1000");
    }

    /// FINAL-B6: retransmissions must not double-count against the cap.
    #[test]
    fn reassembler_retransmission_dedup_against_cap() {
        let mut reasm = TcpReassembler::new(4, 100);
        let mut k = vec![0u8; 13];
        k[12] = 1;
        reasm.feed(&k, 0, &[b'X'; 80]);
        // Retransmit the same seq with a shorter payload: no new bytes.
        reasm.feed(&k, 0, &[b'X'; 40]);
        // Different seq, within cap.
        reasm.feed(&k, 80, &[b'Y'; 20]);
        let flows = reasm.flows();
        assert_eq!(flows[0].client.len(), 100);
    }

    /// FINAL-B6: decode_channel accepts canonical hex and base64 and
    /// rejects arbitrary printable text.
    #[test]
    fn decode_channel_hex_and_base64() {
        let hex = decode_channel(b"4142434445464748");
        assert!(matches!(hex, Some(("hex", _))));
        if let Some(("hex", bytes)) = hex {
            assert_eq!(bytes, b"ABCDEFGH");
        }
        let b64 = decode_channel(b"Q1RGe2I2NH0=");
        assert!(matches!(b64, Some(("base64", _))));
        if let Some(("base64", bytes)) = b64 {
            assert_eq!(&bytes, b"CTF{b64}");
        }
        assert!(decode_channel(b"just a normal sentence!").is_none());
    }
}
