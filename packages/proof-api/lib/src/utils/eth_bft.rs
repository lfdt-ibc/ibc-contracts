// SPDX-License-Identifier: Apache-2.0

//! Helpers shared by the modules that relay from EVM chains with BFT finality.
//!
//! These are Besu IBFT 2.0 and QBFT chains and Linea's Maru QBFT, whose light clients verify commit
//! seals and `eth_getProof` account and storage proofs.

use std::{
    collections::{HashMap, HashSet},
    hash::BuildHasher,
};

use alloy::{
    primitives::{Address, Bytes, Signature, B256, U256},
    rpc::types::EIP1186StorageProof,
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use ethereum_light_client::membership::evm_ics26_commitment_path;
use ibc_eureka_solidity_types::ics26::{router::routerCalls, ICS26_IBC_STORAGE_SLOT};

/// The `CreateClient` parameters of a BFT light client.
pub struct CreateClientParams {
    /// The trusting period in seconds.
    pub trusting_period: u64,
    /// The maximum clock drift in seconds.
    pub max_clock_drift: u64,
    /// The trust level as `(numerator, denominator)`.
    pub trust_level: (u8, u8),
    /// The height to trust initially, the latest source height when unset.
    pub trusted_height: Option<u64>,
}

const TRUSTING_PERIOD: &str = "trusting_period";
const MAX_CLOCK_DRIFT: &str = "max_clock_drift";
/// The `CreateClient` parameter holding the trust level as `<numerator>/<denominator>`.
pub const TRUST_LEVEL: &str = "trust_level";
const TRUSTED_HEIGHT: &str = "trusted_height";

/// Whether the destination client must be updated before proving at `proof_height`.
///
/// The light client requires an update header strictly above its trusted height, so an update is
/// only built once the source has advanced past it. At equal heights the client already stores
/// the consensus state proofs are verified against.
///
/// # Errors
/// Returns an error if the client is ahead of `proof_height`.
pub fn needs_update(trusted_height: u64, proof_height: u64) -> Result<bool> {
    ensure!(
        proof_height >= trusted_height,
        "destination client trusts height {trusted_height}, ahead of the latest source block {proof_height}; retry once the source node catches up"
    );
    Ok(proof_height > trusted_height)
}

/// The source router storage slot whose proof a packet call needs.
///
/// # Panics
/// Panics if `call` is not a recv, ack, or timeout call.
#[must_use]
pub fn packet_storage_key(call: &routerCalls) -> B256 {
    let path = match call {
        routerCalls::recvPacket(call) => call.msg_.packet.commitment_path(),
        routerCalls::ackPacket(call) => call.msg_.packet.ack_commitment_path(),
        routerCalls::timeoutPacket(call) => call.msg_.packet.receipt_commitment_path(),
        _ => unreachable!("only recv, ack, and timeout calls are constructed"),
    };
    evm_ics26_commitment_path(&path, U256::from_be_slice(&ICS26_IBC_STORAGE_SLOT)).into()
}

/// The `eth_getProof` result for a single storage slot of the source router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSlotProof {
    /// The slot value at the proven height, zero when the slot is empty.
    pub value: U256,
    /// Ordered, RLP-encoded MPT nodes from the router account storage trie.
    pub nodes: Vec<Bytes>,
}

/// Drops packet calls whose proof can no longer be verified against the proven source state.
///
/// Proofs are fetched at the latest source block, so a packet completed on the source chain after
/// its event was emitted yields a proof of the opposite kind from what the router call needs.
/// `ICS26Router` verifies the proof before its no-op checks, so such a call would revert the whole
/// multicall instead of no-op'ing. Each dropped call is logged.
///
/// # Errors
/// Returns an error if a call has no storage proof.
///
/// # Panics
/// Panics if a call is not a recv, ack, or timeout call.
pub fn retain_provable_packet_calls<S: BuildHasher>(
    packet_calls: &mut Vec<routerCalls>,
    storage_proofs: &HashMap<B256, StorageSlotProof, S>,
) -> Result<()> {
    let mut error = None;
    packet_calls.retain(|call| {
        let storage_key = packet_storage_key(call);
        let Some(slot) = storage_proofs.get(&storage_key) else {
            error.get_or_insert_with(|| anyhow!("missing storage proof for key {storage_key}"));
            return false;
        };
        let slot_is_set = !slot.value.is_zero();
        let (kind, packet, reason) = match call {
            routerCalls::recvPacket(call) if !slot_is_set => (
                "recvPacket",
                &call.msg_.packet,
                "packet commitment is absent from the source router; the packet was already acknowledged or timed out",
            ),
            routerCalls::ackPacket(call) if !slot_is_set => (
                "ackPacket",
                &call.msg_.packet,
                "acknowledgement commitment is absent from the source router",
            ),
            routerCalls::timeoutPacket(call) if slot_is_set => (
                "timeoutPacket",
                &call.msg_.packet,
                "packet receipt exists on the source router; the packet was received before it could time out",
            ),
            routerCalls::recvPacket(_) | routerCalls::ackPacket(_) | routerCalls::timeoutPacket(_) => {
                return true;
            }
            _ => unreachable!("only recv, ack, and timeout calls are constructed"),
        };
        tracing::warn!(
            kind,
            source_client = %packet.sourceClient,
            dest_client = %packet.destClient,
            sequence = packet.sequence,
            "skipping packet call: {reason}"
        );
        false
    });
    error.map_or(Ok(()), Err)
}

/// Attaches a membership proof to every packet call, built by `encode_proof` from the router account
/// proof nodes and the storage proof nodes for the packet's commitment slot.
///
/// The router account proof is only passed for the first call. All calls share the same proof
/// height and execute in a single multicall, so the light client verifies the account proof once,
/// caches the storage root in transient storage, and serves the remaining calls from that cache
/// when their account proof nodes are empty. The first call is not allowed to fail, so the cache is
/// always set before the remaining calls run.
///
/// # Errors
/// Returns an error if a call has no storage proof.
///
/// # Panics
/// Panics if a call is not a recv, ack, or timeout call.
pub fn attach_packet_proofs<S: BuildHasher>(
    packet_calls: &mut [routerCalls],
    account_proof: &[Bytes],
    storage_proofs: &HashMap<B256, StorageSlotProof, S>,
    encode_proof: impl Fn(Vec<Bytes>, Vec<Bytes>) -> Bytes,
) -> Result<()> {
    let mut account_proof = Some(account_proof);
    packet_calls.iter_mut().try_for_each(|call| {
        let storage_key = packet_storage_key(call);
        let proof_nodes = &storage_proofs
            .get(&storage_key)
            .ok_or_else(|| anyhow!("missing storage proof for key {storage_key}"))?
            .nodes;
        let proof = encode_proof(
            account_proof.take().map_or_default(<[Bytes]>::to_vec),
            proof_nodes.clone(),
        );

        match call {
            routerCalls::recvPacket(call) => call.msg_.proofCommitment = proof,
            routerCalls::ackPacket(call) => call.msg_.proofAcked = proof,
            routerCalls::timeoutPacket(call) => call.msg_.proofTimeout = proof,
            _ => unreachable!("only recv, ack, and timeout calls are constructed"),
        }
        Ok(())
    })
}

/// Indexes storage slot proofs by slot key, requiring exactly one proof per expected key.
///
/// # Errors
/// Returns an error on a missing, duplicate, or unexpected storage proof.
pub fn map_storage_proofs(
    expected_keys: &[B256],
    storage_proofs: &[EIP1186StorageProof],
) -> Result<HashMap<B256, StorageSlotProof>> {
    let expected_keys = expected_keys.iter().copied().collect::<HashSet<_>>();
    let proofs = storage_proofs.iter().try_fold(
        HashMap::with_capacity(expected_keys.len()),
        |mut proofs, storage_proof| {
            let key = storage_proof.key.as_b256();
            ensure!(
                expected_keys.contains(&key),
                "unexpected storage proof key {key}"
            );
            let slot = StorageSlotProof {
                value: storage_proof.value,
                nodes: storage_proof.proof.clone(),
            };
            ensure!(
                proofs.insert(key, slot).is_none(),
                "duplicate storage proof key {key}"
            );
            Ok(proofs)
        },
    )?;

    if let Some(key) = expected_keys.iter().find(|key| !proofs.contains_key(*key)) {
        bail!("missing storage proof for key {key}");
    }
    Ok(proofs)
}

/// Parses the `CreateClient` parameters of a BFT light client.
///
/// # Errors
/// Returns an error on an unknown, missing, or malformed parameter.
pub fn parse_create_client_params<S: BuildHasher>(
    parameters: &HashMap<String, String, S>,
) -> Result<CreateClientParams> {
    parameters
        .keys()
        .find(|key| {
            ![
                TRUSTING_PERIOD,
                MAX_CLOCK_DRIFT,
                TRUST_LEVEL,
                TRUSTED_HEIGHT,
            ]
            .contains(&key.as_str())
        })
        .map_or(Ok(()), |key| {
            Err(anyhow!(
                "unexpected parameter `{key}`, only `{TRUSTING_PERIOD}`, `{MAX_CLOCK_DRIFT}`, `{TRUST_LEVEL}`, and `{TRUSTED_HEIGHT}` are allowed"
            ))
        })?;

    Ok(CreateClientParams {
        trusting_period: parameters
            .get(TRUSTING_PERIOD)
            .ok_or_else(|| anyhow!("missing `{TRUSTING_PERIOD}` parameter"))?
            .parse()
            .with_context(|| format!("failed to parse `{TRUSTING_PERIOD}` as decimal seconds"))?,
        max_clock_drift: parameters
            .get(MAX_CLOCK_DRIFT)
            .ok_or_else(|| anyhow!("missing `{MAX_CLOCK_DRIFT}` parameter"))?
            .parse()
            .with_context(|| format!("failed to parse `{MAX_CLOCK_DRIFT}` as decimal seconds"))?,
        trust_level: parameters
            .get(TRUST_LEVEL)
            .map_or(Ok(DEFAULT_TRUST_LEVEL), |value| parse_trust_level(value))?,
        trusted_height: parameters
            .get(TRUSTED_HEIGHT)
            .map(|value| {
                value.parse().with_context(|| {
                    format!("failed to parse `{TRUSTED_HEIGHT}` as decimal block height")
                })
            })
            .transpose()?,
    })
}

/// Default trust level, matching the `ceil(2n / 3)` commit-seal quorum.
const DEFAULT_TRUST_LEVEL: (u8, u8) = (2, 3);

/// Parses a `<numerator>/<denominator>` trust level and checks that it is within `[1/3, 2/3]`.
fn parse_trust_level(value: &str) -> Result<(u8, u8)> {
    let (numerator, denominator) = value
        .split_once('/')
        .and_then(|(numerator, denominator)| {
            Some((
                numerator.trim().parse::<u8>().ok()?,
                denominator.trim().parse::<u8>().ok()?,
            ))
        })
        .with_context(|| {
            format!("failed to parse `{TRUST_LEVEL}` as `<numerator>/<denominator>`: {value}")
        })?;
    ensure!(
        denominator != 0
            && 3 * u16::from(numerator) >= u16::from(denominator)
            && 3 * u16::from(numerator) <= 2 * u16::from(denominator),
        "`{TRUST_LEVEL}` must be within [1/3, 2/3], got {numerator}/{denominator}"
    );
    Ok((numerator, denominator))
}

/// Orders commit seals by the address recovered from `digest` and encodes them with 27/28
/// recovery ids.
///
/// The light clients require commit seals in strictly ascending signer order with 27/28 recovery
/// ids, but Besu and Maru order them arbitrarily and use 0/1 recovery ids.
///
/// # Errors
/// Returns an error if a seal is malformed or two seals recover to the same signer.
pub fn sort_commit_seals(
    digest: &B256,
    seals: impl IntoIterator<Item = impl AsRef<[u8]>>,
) -> Result<Vec<Bytes>> {
    let mut signed_seals = seals
        .into_iter()
        .map(|seal| {
            let signature = Signature::from_raw(seal.as_ref())
                .context("failed to decode commit seal signature")?;
            let signer = signature
                .recover_address_from_prehash(digest)
                .context("failed to recover commit seal signer")?;
            // `as_bytes` encodes the recovery id as 27/28, whichever form the source used.
            Ok((signer, Bytes::from(signature.as_bytes())))
        })
        .collect::<Result<Vec<(Address, Bytes)>>>()?;
    signed_seals.sort_by_key(|(signer, _)| *signer);
    if let Some(pair) = signed_seals.windows(2).find(|pair| pair[0].0 == pair[1].0) {
        bail!("duplicate commit seal signer {}", pair[0].0);
    }

    Ok(signed_seals.into_iter().map(|(_, seal)| seal).collect())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        attach_packet_proofs, map_storage_proofs, needs_update, packet_storage_key,
        parse_create_client_params, retain_provable_packet_calls, sort_commit_seals,
        StorageSlotProof, TRUST_LEVEL,
    };
    use alloy::{
        primitives::{keccak256, Bytes, Signature, B256, U256},
        rpc::types::EIP1186StorageProof,
        signers::{local::PrivateKeySigner, SignerSync},
        sol_types::SolValue,
    };
    use ibc_eureka_solidity_types::ics26::{
        router::{ackPacketCall, recvPacketCall, routerCalls, timeoutPacketCall},
        IICS02ClientMsgs::Height,
        IICS26RouterMsgs::{MsgAckPacket, MsgRecvPacket, MsgTimeoutPacket, Packet},
    };

    fn packet(sequence: u64) -> Packet {
        Packet {
            sequence,
            sourceClient: "client-0".to_string(),
            destClient: "client-1".to_string(),
            timeoutTimestamp: 0,
            payloads: vec![],
        }
    }

    fn proof_height() -> Height {
        Height {
            revisionNumber: 0,
            revisionHeight: 1,
        }
    }

    fn recv_packet_call(sequence: u64) -> routerCalls {
        routerCalls::recvPacket(recvPacketCall {
            msg_: MsgRecvPacket {
                packet: packet(sequence),
                proofHeight: proof_height(),
                proofCommitment: Bytes::default(),
            },
        })
    }

    fn ack_packet_call(sequence: u64) -> routerCalls {
        routerCalls::ackPacket(ackPacketCall {
            msg_: MsgAckPacket {
                packet: packet(sequence),
                acknowledgement: Bytes::from(vec![0x01]),
                proofAcked: Bytes::default(),
                proofHeight: proof_height(),
            },
        })
    }

    fn timeout_packet_call(sequence: u64) -> routerCalls {
        routerCalls::timeoutPacket(timeoutPacketCall {
            msg_: MsgTimeoutPacket {
                packet: packet(sequence),
                proofTimeout: Bytes::default(),
                proofHeight: proof_height(),
            },
        })
    }

    fn sequence_of(call: &routerCalls) -> u64 {
        match call {
            routerCalls::recvPacket(call) => call.msg_.packet.sequence,
            routerCalls::ackPacket(call) => call.msg_.packet.sequence,
            routerCalls::timeoutPacket(call) => call.msg_.packet.sequence,
            _ => unreachable!("only recv, ack, and timeout calls are constructed"),
        }
    }

    /// Encodes a proof as its `(accountProofNodes, proofNodes)` pair.
    fn encode_proof(account_proof_nodes: Vec<Bytes>, proof_nodes: Vec<Bytes>) -> Bytes {
        (account_proof_nodes, proof_nodes).abi_encode().into()
    }

    /// Returns the `(accountProofNodes, proofNodes)` pair attached to a recv call.
    fn decode_recv_proof(call: &routerCalls) -> (Vec<Bytes>, Vec<Bytes>) {
        let routerCalls::recvPacket(call) = call else {
            unreachable!("call kind is preserved");
        };
        <(Vec<Bytes>, Vec<Bytes>)>::abi_decode(&call.msg_.proofCommitment)
            .expect("proof decodes as a pair of node lists")
    }

    /// Builds one slot proof per call with a distinct single node, using `value` to pick the
    /// proven slot value from the call's index.
    fn slot_proofs(
        calls: &[routerCalls],
        value: impl Fn(usize) -> U256,
    ) -> HashMap<B256, StorageSlotProof> {
        calls
            .iter()
            .enumerate()
            .map(|(i, call)| {
                let slot = StorageSlotProof {
                    value: value(i),
                    nodes: vec![Bytes::from(vec![0xc1, u8::try_from(i).unwrap()])],
                };
                (packet_storage_key(call), slot)
            })
            .collect()
    }

    const SET: U256 = U256::from_limbs([1, 0, 0, 0]);

    #[test]
    fn maps_storage_proof_values_and_nodes_by_key() {
        let key = B256::from(U256::from(1));
        let nodes = vec![Bytes::from(vec![0xc2, 0x01, 0x02])];
        let mapped = map_storage_proofs(
            &[key],
            &[EIP1186StorageProof {
                key: U256::from(1).into(),
                value: U256::from(42),
                proof: nodes.clone(),
            }],
        )
        .unwrap();

        assert_eq!(
            mapped[&key],
            StorageSlotProof {
                value: U256::from(42),
                nodes,
            }
        );
    }

    #[test]
    fn rejects_missing_duplicate_and_unexpected_storage_proofs() {
        let key = B256::from(U256::from(1));
        let proof = |key: U256| EIP1186StorageProof {
            key: key.into(),
            value: U256::ZERO,
            proof: vec![],
        };

        assert!(map_storage_proofs(&[key], &[]).is_err());
        assert!(map_storage_proofs(&[key], &[proof(U256::from(1)), proof(U256::from(1))]).is_err());
        assert!(map_storage_proofs(&[key], &[proof(U256::from(2))]).is_err());
    }

    #[test]
    fn retains_recv_and_ack_calls_only_while_their_commitment_exists() {
        let mut calls = vec![
            recv_packet_call(1),
            recv_packet_call(2),
            ack_packet_call(3),
            ack_packet_call(4),
        ];
        // Sequences 2 and 4 have been cleared on the source chain.
        let storage_proofs = slot_proofs(&calls, |i| if i % 2 == 0 { SET } else { U256::ZERO });

        retain_provable_packet_calls(&mut calls, &storage_proofs).unwrap();

        assert_eq!(
            calls.iter().map(sequence_of).collect::<Vec<_>>(),
            vec![1, 3]
        );
        assert!(matches!(calls[0], routerCalls::recvPacket(_)));
        assert!(matches!(calls[1], routerCalls::ackPacket(_)));
    }

    #[test]
    fn retains_timeout_calls_only_while_no_receipt_exists() {
        let mut calls = vec![timeout_packet_call(1), timeout_packet_call(2)];
        // Sequence 1 was received on the source chain, so it can no longer time out.
        let storage_proofs = slot_proofs(&calls, |i| if i == 0 { SET } else { U256::ZERO });

        retain_provable_packet_calls(&mut calls, &storage_proofs).unwrap();

        assert_eq!(calls.iter().map(sequence_of).collect::<Vec<_>>(), vec![2]);
    }

    #[test]
    fn retain_rejects_missing_storage_proof() {
        let mut calls = vec![recv_packet_call(1)];
        assert!(retain_provable_packet_calls(&mut calls, &HashMap::new()).is_err());
    }

    #[test]
    fn attaches_account_and_storage_proof_nodes() {
        let mut calls = vec![recv_packet_call(1)];
        let storage_key = packet_storage_key(&calls[0]);
        let nodes = vec![Bytes::from(vec![0xc2, 0x01, 0x02])];
        let account_nodes = vec![Bytes::from(vec![0xc3, 0x01, 0x02, 0x03])];

        assert!(
            attach_packet_proofs(&mut calls, &account_nodes, &HashMap::new(), encode_proof)
                .is_err(),
            "missing storage proof must be rejected"
        );

        let storage_proofs = HashMap::from([(
            storage_key,
            StorageSlotProof {
                value: SET,
                nodes: nodes.clone(),
            },
        )]);
        attach_packet_proofs(&mut calls, &account_nodes, &storage_proofs, encode_proof).unwrap();

        assert_eq!(decode_recv_proof(&calls[0]), (account_nodes, nodes));
    }

    #[test]
    fn attaches_account_proof_only_to_first_call_in_batch() {
        let mut calls = vec![
            recv_packet_call(1),
            recv_packet_call(2),
            recv_packet_call(3),
        ];
        let account_nodes = vec![Bytes::from(vec![0xc3, 0x01, 0x02, 0x03])];
        let storage_proofs = slot_proofs(&calls, |_| SET);

        attach_packet_proofs(&mut calls, &account_nodes, &storage_proofs, encode_proof).unwrap();

        for (i, call) in calls.iter().enumerate() {
            let (account_proof_nodes, proof_nodes) = decode_recv_proof(call);
            let expected_account_nodes = if i == 0 { &account_nodes[..] } else { &[][..] };
            assert_eq!(
                account_proof_nodes, expected_account_nodes,
                "only the first call should carry the account proof"
            );
            assert_eq!(
                proof_nodes,
                storage_proofs[&packet_storage_key(call)].nodes,
                "every call carries its own storage proof"
            );
        }
    }

    #[test]
    fn account_proof_moves_to_first_surviving_call_after_filtering() {
        let mut calls = vec![recv_packet_call(1), recv_packet_call(2)];
        let account_nodes = vec![Bytes::from(vec![0xc3, 0x01, 0x02, 0x03])];
        // The first packet was already completed on the source chain.
        let storage_proofs = slot_proofs(&calls, |i| if i == 0 { U256::ZERO } else { SET });

        retain_provable_packet_calls(&mut calls, &storage_proofs).unwrap();
        attach_packet_proofs(&mut calls, &account_nodes, &storage_proofs, encode_proof).unwrap();

        assert_eq!(calls.iter().map(sequence_of).collect::<Vec<_>>(), vec![2]);
        assert_eq!(decode_recv_proof(&calls[0]).0, account_nodes);
    }

    #[test]
    fn needs_update_only_when_source_is_ahead() {
        assert!(needs_update(10, 11).unwrap());
        assert!(!needs_update(10, 10).unwrap());
        assert!(needs_update(10, 9).is_err());
    }

    #[test]
    fn create_client_params_trust_level() {
        let params = |trust_level: Option<&str>| {
            let mut params = HashMap::from([
                ("trusting_period".to_string(), "1000".to_string()),
                ("max_clock_drift".to_string(), "10".to_string()),
            ]);
            if let Some(trust_level) = trust_level {
                params.insert(TRUST_LEVEL.to_string(), trust_level.to_string());
            }
            parse_create_client_params(&params).map(|params| params.trust_level)
        };

        assert_eq!(params(None).unwrap(), (2, 3));
        assert_eq!(params(Some("1/3")).unwrap(), (1, 3));
        assert_eq!(params(Some("4/6")).unwrap(), (4, 6));
        for invalid in [
            "", "2", "2/", "a/3", "1/0", "0/0", "1/4", "3/4", "1/1", "4/3", "256/256",
        ] {
            assert!(
                params(Some(invalid)).is_err(),
                "{invalid} should be rejected"
            );
        }
    }

    #[test]
    fn sorts_commit_seals_by_signer_with_27_28_recovery_ids() {
        let digest = keccak256("header");
        let mut signers: Vec<_> = (0..4).map(|_| PrivateKeySigner::random()).collect();
        signers.sort_by_key(|signer| std::cmp::Reverse(signer.address()));
        let seals: Vec<_> = signers
            .iter()
            .map(|signer| {
                let mut seal = signer.sign_hash_sync(&digest).unwrap().as_bytes();
                seal[64] -= 27;
                seal
            })
            .collect();

        let recovered: Vec<_> = sort_commit_seals(&digest, &seals)
            .unwrap()
            .iter()
            .map(|seal| {
                assert!(matches!(seal[64], 27 | 28));
                Signature::from_raw(seal)
                    .unwrap()
                    .recover_address_from_prehash(&digest)
                    .unwrap()
            })
            .collect();
        signers.reverse();
        assert_eq!(
            recovered,
            signers
                .iter()
                .map(PrivateKeySigner::address)
                .collect::<Vec<_>>()
        );

        let err = sort_commit_seals(&digest, [seals[0], seals[0]]).unwrap_err();
        assert!(err.to_string().contains("duplicate commit seal signer"));
        assert!(sort_commit_seals(&B256::ZERO, [[0u8; 3]]).is_err());
    }
}
