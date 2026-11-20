// SPDX-License-Identifier: Apache-2.0

use crate::{proto, EngineError};

const MAX_PACKETS_PER_REQUEST: usize = 64;
const MAX_PACKET_TEXT_BYTES: usize = 256;
const MAX_PAYLOAD_VALUE_BYTES: usize = 1024 * 1024;

pub fn validate_packets(
    request: &proto::PacketProofsRequest,
    configured_client: &str,
    counterparty_client: &str,
) -> Result<(), EngineError> {
    let kind = proto::ProofKind::try_from(request.kind)
        .map_err(|_| EngineError::InvalidRequest("unsupported proof kind".into()))?;
    if kind == proto::ProofKind::Unspecified {
        return Err(EngineError::InvalidRequest("proof kind is required".into()));
    }
    if request.packets.len() > MAX_PACKETS_PER_REQUEST {
        return Err(EngineError::InvalidRequest(format!(
            "a request may contain at most {MAX_PACKETS_PER_REQUEST} packets"
        )));
    }
    for (index, packet) in request.packets.iter().enumerate() {
        if packet.sequence == 0 || packet.payloads.len() != 1 {
            return Err(EngineError::InvalidRequest(format!(
                "packet {index} must have a nonzero sequence and exactly one payload"
            )));
        }
        if kind == proto::ProofKind::ReceiptAbsence && packet.timeout_timestamp == 0 {
            return Err(EngineError::InvalidRequest(format!(
                "packet {index} receipt-absence proof requires a nonzero timeout timestamp"
            )));
        }
        let direction = match kind {
            proto::ProofKind::PacketCommitment => {
                packet.destination_client == configured_client
                    && packet.source_client == counterparty_client
            }
            proto::ProofKind::Acknowledgement | proto::ProofKind::ReceiptAbsence => {
                packet.source_client == configured_client
                    && packet.destination_client == counterparty_client
            }
            proto::ProofKind::Unspecified => false,
        };
        if !direction {
            return Err(EngineError::InvalidRequest(format!(
                "packet {index} direction does not match the proof kind"
            )));
        }
        let payload = &packet.payloads[0];
        require_bounded_text(index, "source port", &payload.source_port)?;
        require_bounded_text(index, "destination port", &payload.destination_port)?;
        require_bounded_text(index, "version", &payload.version)?;
        require_bounded_text(index, "encoding", &payload.encoding)?;
        if payload.value.len() > MAX_PAYLOAD_VALUE_BYTES {
            return Err(EngineError::InvalidRequest(format!(
                "packet {index} payload exceeds {MAX_PAYLOAD_VALUE_BYTES} bytes"
            )));
        }
    }
    Ok(())
}

fn require_bounded_text(index: usize, field: &str, value: &str) -> Result<(), EngineError> {
    if value.len() > MAX_PACKET_TEXT_BYTES || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(EngineError::InvalidRequest(format!(
            "packet {index} {field} must contain at most {MAX_PACKET_TEXT_BYTES} non-control bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet() -> proto::Packet {
        proto::Packet {
            sequence: 1,
            source_client: "source".into(),
            destination_client: "destination".into(),
            timeout_timestamp: 10,
            payloads: vec![proto::Payload {
                source_port: "transfer".into(),
                destination_port: "transfer".into(),
                version: "1".into(),
                encoding: "application/octet-stream".into(),
                value: vec![1],
            }],
        }
    }

    #[test]
    fn accepts_reviewed_direction_and_bounded_payload() {
        let request = proto::PacketProofsRequest {
            client: None,
            height: 1,
            kind: proto::ProofKind::PacketCommitment as i32,
            packets: vec![packet()],
        };
        assert_eq!(validate_packets(&request, "destination", "source"), Ok(()));
    }

    #[test]
    fn rejects_wrong_direction_and_missing_timeout() {
        let mut wrong = packet();
        wrong.source_client = "wrong".into();
        let request = proto::PacketProofsRequest {
            client: None,
            height: 1,
            kind: proto::ProofKind::PacketCommitment as i32,
            packets: vec![wrong],
        };
        assert!(validate_packets(&request, "destination", "source").is_err());

        let mut no_timeout = packet();
        no_timeout.source_client = "destination".into();
        no_timeout.destination_client = "source".into();
        no_timeout.timeout_timestamp = 0;
        let request = proto::PacketProofsRequest {
            client: None,
            height: 1,
            kind: proto::ProofKind::ReceiptAbsence as i32,
            packets: vec![no_timeout],
        };
        assert!(validate_packets(&request, "destination", "source").is_err());
    }

    #[test]
    fn rejects_oversized_batch_and_payload() {
        let request = proto::PacketProofsRequest {
            client: None,
            height: 1,
            kind: proto::ProofKind::PacketCommitment as i32,
            packets: vec![packet(); MAX_PACKETS_PER_REQUEST + 1],
        };
        assert!(validate_packets(&request, "destination", "source").is_err());

        let mut oversized = packet();
        oversized.payloads[0].value = vec![0; MAX_PAYLOAD_VALUE_BYTES + 1];
        let request = proto::PacketProofsRequest {
            client: None,
            height: 1,
            kind: proto::ProofKind::PacketCommitment as i32,
            packets: vec![oversized],
        };
        assert!(validate_packets(&request, "destination", "source").is_err());
    }
}
