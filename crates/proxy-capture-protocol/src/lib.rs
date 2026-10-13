//! Bounded capture transport framing and control messages.
//! Callers validate message versions, identifiers, and handshake ordering.
//!
//! After the handshake a connection sends either metadata records or
//! inspection queries. Queries read the agent's spool without changing it and
//! need an inspect grant on the producer; an agent that predates them rejects
//! the unknown frame kind and closes the connection.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION: u16 = 1;
pub const MAX_RECORD_BYTES: usize = 524288;
/// Most records one [`RecordsQuery`] page may carry.
pub const MAX_INSPECT_RECORDS: u16 = 100;
/// Most decrypted record bytes one [`RecordsReply`] page may carry. The frame
/// limit below leaves room for the JSON envelope around them.
pub const MAX_INSPECT_RECORD_BYTES: usize = 1_048_576;
const MAX_RECORDS_REPLY_BYTES: usize = 2 * MAX_INSPECT_RECORD_BYTES;
const MAX_CONTROL_BYTES: usize = 1024;
const MAGIC: &[u8; 4] = b"LMC1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Hello = 1,
    Welcome = 2,
    Record = 3,
    Receipt = 4,
    StatsQuery = 5,
    StatsReply = 6,
    RecordsQuery = 7,
    RecordsReply = 8,
}

impl Kind {
    pub const ALL: [Kind; 8] = [
        Kind::Hello,
        Kind::Welcome,
        Kind::Record,
        Kind::Receipt,
        Kind::StatsQuery,
        Kind::StatsReply,
        Kind::RecordsQuery,
        Kind::RecordsReply,
    ];
}

#[derive(PartialEq, Eq)]
pub struct Frame {
    pub kind: Kind,
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Frame")
            .field("kind", &self.kind)
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub version: u16,
    pub producer_id: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Welcome {
    pub version: u16,
    pub node_id: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub version: u16,
    pub event_id: String,
    pub node_id: String,
    pub sequence: Option<u64>,
    pub outcome: Outcome,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Durable,
    Full,
    Unauthorized,
    Invalid,
    Unavailable,
}

/// Asks for the agent's spool counters. Needs an inspect grant.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatsQuery {
    pub version: u16,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatsReply {
    pub version: u16,
    pub outcome: InspectOutcome,
    /// `Some` exactly when `outcome` is [`InspectOutcome::Ok`].
    pub stats: Option<SpoolSnapshot>,
}

/// The spool's own counters plus the agent's lifetime totals since start.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SpoolSnapshot {
    pub node_id: String,
    pub next_sequence: u64,
    pub durable_through_sequence: u64,
    pub acknowledged_through_sequence: u64,
    pub pending_records: u64,
    pub retained_records: u64,
    pub database_bytes: u64,
    pub disk_bytes: u64,
    pub max_disk_bytes: u64,
    pub quarantine_bytes: u64,
    pub poisoned: bool,
    pub durable_total: u64,
    pub rejected_total: u64,
    pub failures_total: u64,
}

/// Asks for durable records with sequences above `after_sequence`, oldest
/// first. Needs an inspect grant; only records of the grant's tenants return.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecordsQuery {
    pub version: u16,
    pub after_sequence: u64,
    /// At most [`MAX_INSPECT_RECORDS`].
    pub max_records: u16,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RecordsReply {
    pub version: u16,
    pub outcome: InspectOutcome,
    pub records: Vec<SpooledRecord>,
    /// The cursor for the next page: the last sequence this page scanned,
    /// including records filtered out for another tenant, so a sparse page
    /// still advances. Equal to the query's `after_sequence` when nothing
    /// newer is durable.
    pub next_after_sequence: u64,
    pub durable_through_sequence: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SpooledRecord {
    pub sequence: u64,
    /// The stored request record, as JSON. This crate does not depend on the
    /// record schema; the agent validated it on admission.
    pub record: serde_json::Value,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InspectOutcome {
    Ok,
    Unauthorized,
    Invalid,
    Unavailable,
}

// Only records and record pages may be large; every control message shares
// the small limit.
fn max_payload_bytes(kind: Kind) -> usize {
    match kind {
        Kind::Record => MAX_RECORD_BYTES,
        Kind::RecordsReply => MAX_RECORDS_REPLY_BYTES,
        _ => MAX_CONTROL_BYTES,
    }
}

fn valid_length(kind: Kind, length: usize) -> bool {
    length != 0 && length <= max_payload_bytes(kind)
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Frame> {
    let mut header = [0; 9];
    r.read_exact(&mut header).await?;
    if &header[..4] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid capture frame magic",
        ));
    }
    let kind = match header[4] {
        1 => Kind::Hello,
        2 => Kind::Welcome,
        3 => Kind::Record,
        4 => Kind::Receipt,
        5 => Kind::StatsQuery,
        6 => Kind::StatsReply,
        7 => Kind::RecordsQuery,
        8 => Kind::RecordsReply,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid capture frame kind",
            ))
        }
    };
    let length = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    if !valid_length(kind, length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid capture frame length",
        ));
    }
    let mut payload = vec![0; length];
    r.read_exact(&mut payload).await?;
    Ok(Frame { kind, payload })
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    kind: Kind,
    payload: &[u8],
) -> io::Result<()> {
    if !valid_length(kind, payload.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid capture frame length",
        ));
    }
    let mut header = [0; 9];
    header[..4].copy_from_slice(MAGIC);
    header[4] = kind as u8;
    header[5..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&header).await?;
    w.write_all(payload).await
}

pub fn encode<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "capture message encoding failed",
        )
    })
}

pub fn decode<T: DeserializeOwned>(payload: &[u8]) -> io::Result<T> {
    serde_json::from_slice(payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "capture message decoding failed",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(magic: &[u8; 4], kind: u8, length: u32) -> Vec<u8> {
        let mut bytes = magic.to_vec();
        bytes.push(kind);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes
    }

    async fn read_bytes(bytes: &[u8]) -> io::Result<Frame> {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        let (sent, received) = tokio::join!(
            async {
                writer.write_all(bytes).await.unwrap();
                writer.shutdown().await.unwrap();
            },
            read_frame(&mut reader)
        );
        let () = sent;
        received
    }

    #[tokio::test]
    async fn roundtrip_all_kinds_and_exact_limits() {
        for kind in Kind::ALL {
            for size in [1, max_payload_bytes(kind)] {
                let payload = vec![42; size];
                let (mut writer, mut reader) = tokio::io::duplex(17);
                let (sent, received) = tokio::join!(
                    write_frame(&mut writer, kind, &payload),
                    read_frame(&mut reader)
                );
                sent.unwrap();
                assert_eq!(received.unwrap(), Frame { kind, payload });
            }
        }
    }

    #[tokio::test]
    async fn wire_header_and_consecutive_frames() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        write_frame(&mut writer, Kind::Record, b"abc")
            .await
            .unwrap();
        let mut bytes = [0; 12];
        reader.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"LMC1\x03\x00\x00\x00\x03abc");
        write_frame(&mut writer, Kind::Hello, b"a").await.unwrap();
        write_frame(&mut writer, Kind::Receipt, b"b").await.unwrap();
        assert_eq!(read_frame(&mut reader).await.unwrap().payload, b"a");
        assert_eq!(read_frame(&mut reader).await.unwrap().kind, Kind::Receipt);
    }

    #[tokio::test]
    async fn fragmented_header_and_body() {
        let mut bytes = header(MAGIC, 3, 5);
        bytes.extend_from_slice(b"hello");
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let (sent, received) = tokio::join!(
            async {
                for byte in bytes {
                    writer.write_all(&[byte]).await.unwrap();
                    tokio::task::yield_now().await;
                }
            },
            read_frame(&mut reader)
        );
        let () = sent;
        assert_eq!(received.unwrap().payload, b"hello");
    }

    #[tokio::test]
    async fn invalid_headers_rejected_without_waiting_for_body() {
        let mut headers = vec![header(b"BAD!", 1, 1), header(b"LMC2", 1, 1)];
        for kind in [0, 9, 255] {
            headers.push(header(MAGIC, kind, 1));
        }
        for kind in 1..=8 {
            let maximum = match kind {
                3 => MAX_RECORD_BYTES,
                8 => MAX_RECORDS_REPLY_BYTES,
                _ => MAX_CONTROL_BYTES,
            };
            for length in [0, maximum as u32 + 1, u32::MAX] {
                headers.push(header(MAGIC, kind, length));
            }
        }
        for bytes in headers {
            let (mut writer, mut reader) = tokio::io::duplex(16);
            writer.write_all(&bytes).await.unwrap();
            // Keep the writer open: rejection must not attempt a body read.
            let error =
                tokio::time::timeout(std::time::Duration::from_secs(1), read_frame(&mut reader))
                    .await
                    .unwrap()
                    .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn every_truncated_header_and_body_is_unexpected_eof() {
        let mut bytes = header(MAGIC, 3, 4);
        bytes.extend_from_slice(b"body");
        for length in 0..bytes.len() {
            assert_eq!(
                read_bytes(&bytes[..length]).await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }

    #[tokio::test]
    async fn invalid_writes_emit_no_header() {
        for kind in Kind::ALL {
            for payload in [vec![], vec![0; max_payload_bytes(kind) + 1]] {
                let (mut writer, mut reader) = tokio::io::duplex(16);
                assert_eq!(
                    write_frame(&mut writer, kind, &payload)
                        .await
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidInput
                );
                writer.shutdown().await.unwrap();
                assert_eq!(
                    reader.read_u8().await.unwrap_err().kind(),
                    io::ErrorKind::UnexpectedEof
                );
            }
        }
    }

    #[test]
    fn control_messages_roundtrip_and_outcomes_use_snake_case() {
        let hello = Hello {
            version: VERSION,
            producer_id: "producer".into(),
        };
        assert_eq!(decode::<Hello>(&encode(&hello).unwrap()).unwrap(), hello);
        let welcome = Welcome {
            version: VERSION,
            node_id: "node".into(),
        };
        assert_eq!(
            decode::<Welcome>(&encode(&welcome).unwrap()).unwrap(),
            welcome
        );
        for (outcome, name) in [
            (Outcome::Durable, "durable"),
            (Outcome::Full, "full"),
            (Outcome::Unauthorized, "unauthorized"),
            (Outcome::Invalid, "invalid"),
            (Outcome::Unavailable, "unavailable"),
        ] {
            assert_eq!(encode(&outcome).unwrap(), format!("\"{name}\"").as_bytes());
            for sequence in [None, Some(0), Some(u64::MAX)] {
                let receipt = Receipt {
                    version: VERSION,
                    event_id: "event".into(),
                    node_id: "node".into(),
                    sequence,
                    outcome,
                };
                assert_eq!(
                    decode::<Receipt>(&encode(&receipt).unwrap()).unwrap(),
                    receipt
                );
            }
        }
    }

    #[test]
    fn unknown_fields_and_invalid_json_are_sanitized() {
        for payload in [br#"{"version":1,"event_id":"event","node_id":"node","sequence":null,"outcome":"durable","secret":"private"}"#.as_slice(), br#"{"version":1,"event_id":"event","node_id":"node","outcome":"private"}"#, b"private"] {
            let error = decode::<Receipt>(payload).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "capture message decoding failed");
        }
        assert!(decode::<Hello>(br#"{"version":1,"producer_id":"p","extra":true}"#).is_err());
        assert!(decode::<Welcome>(br#"{"version":1,"node_id":"n","extra":true}"#).is_err());
        assert!(decode::<Hello>(br#"{"version":1,"node_id":"n"}"#).is_err());
        assert!(decode::<Hello>(br#"{"version":65536,"producer_id":"p"}"#).is_err());
    }

    #[test]
    fn inspect_messages_roundtrip_with_snake_case_outcomes() {
        for (outcome, name) in [
            (InspectOutcome::Ok, "ok"),
            (InspectOutcome::Unauthorized, "unauthorized"),
            (InspectOutcome::Invalid, "invalid"),
            (InspectOutcome::Unavailable, "unavailable"),
        ] {
            assert_eq!(encode(&outcome).unwrap(), format!("\"{name}\"").as_bytes());
        }
        let stats = StatsReply {
            version: VERSION,
            outcome: InspectOutcome::Ok,
            stats: Some(SpoolSnapshot {
                node_id: "node".into(),
                next_sequence: 4,
                durable_through_sequence: 3,
                acknowledged_through_sequence: 0,
                pending_records: 0,
                retained_records: 3,
                database_bytes: 1,
                disk_bytes: 2,
                max_disk_bytes: 3,
                quarantine_bytes: 0,
                poisoned: false,
                durable_total: 3,
                rejected_total: 1,
                failures_total: 0,
            }),
        };
        assert_eq!(
            decode::<StatsReply>(&encode(&stats).unwrap()).unwrap(),
            stats
        );
        let query = RecordsQuery {
            version: VERSION,
            after_sequence: 7,
            max_records: MAX_INSPECT_RECORDS,
        };
        assert_eq!(
            decode::<RecordsQuery>(&encode(&query).unwrap()).unwrap(),
            query
        );
        let page = RecordsReply {
            version: VERSION,
            outcome: InspectOutcome::Ok,
            records: vec![SpooledRecord {
                sequence: 8,
                record: serde_json::json!({"event_id": "e", "tenant_id": "t"}),
            }],
            next_after_sequence: 9,
            durable_through_sequence: 9,
        };
        assert_eq!(
            decode::<RecordsReply>(&encode(&page).unwrap()).unwrap(),
            page
        );
        assert!(decode::<StatsQuery>(br#"{"version":1,"extra":true}"#).is_err());
        assert!(
            decode::<RecordsQuery>(br#"{"version":1,"after_sequence":0,"max_records":65536}"#)
                .is_err()
        );
    }

    #[test]
    fn encoding_errors_are_sanitized() {
        struct Failing;
        impl Serialize for Failing {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("private body"))
            }
        }
        let error = encode(&Failing).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "capture message encoding failed");
    }
}
