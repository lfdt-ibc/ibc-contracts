// SPDX-License-Identifier: Apache-2.0

use prividium_proof_api::{
    backend::Sp1Backend,
    bootstrap::BootstrapResolver,
    config::{Config, ValidatedConfig},
    dedup::DeduplicatingEngine,
    destination::{DestinationLightClient, DestinationTrustUpdateRegistrar, ExpectedIdentity},
    engine::{ArtifactBindings, ChainSources, PrividiumEngine},
    rpc::{JsonRpcClient, ZksyncHeightProvider},
    server::{serve, ProofApi},
    state::SettlementEvidenceCollector,
    storage::PacketEvidenceCollector,
    trust::BeaconTrustUpdateCollector,
};
use std::{env, path::Path, sync::Arc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    run(config).await
}

async fn run(config: ValidatedConfig) -> Result<(), Box<dyn std::error::Error>> {
    let vkeys = [
        config.destination.trust_update_vkey,
        config.destination.settlement_update_vkey,
        config.destination.membership_vkey,
        config.destination.non_membership_vkey,
    ];
    let prover_config = config.prover.clone();
    let destination_config = config.destination.clone();
    let source_profile_id = config.bootstrap.source_profile_id_bytes;
    let backend = tokio::task::spawn_blocking(move || {
        Sp1Backend::new(&prover_config, &destination_config, source_profile_id)
    })
    .await
    .map_err(|error| format!("SP1 backend initialization worker failed: {error}"))??;
    let l2_rpc = JsonRpcClient::new(&config.l2_rpc, config.request_timeout)?;
    let l1_rpc = JsonRpcClient::new(&config.l1_rpc, config.request_timeout)?;
    let destination_rpc = JsonRpcClient::new(&config.destination.rpc, config.request_timeout)?;
    l2_rpc.verify_chain_id(config.l2_rpc.chain_id)?;
    l1_rpc.verify_chain_id(config.l1_rpc.chain_id)?;
    destination_rpc.verify_chain_id(config.destination.rpc.chain_id)?;
    let destination_state_source = DestinationLightClient::resolve_and_validate(
        destination_rpc.clone(),
        &config.client.client_id,
        &ExpectedIdentity {
            router: config.destination.router_address,
            source_profile_id: config.bootstrap.source_profile_id_bytes,
            ibc_store: config.ibc_storage.store_address,
            absence_profile_id: config.ibc_storage.absence_profile_id,
            verifier: config.destination.verifier_address,
            vkeys,
            counterparty_client_id: config.client.counterparty_client_id.clone(),
            counterparty_merkle_prefix: config.counterparty_merkle_prefix.clone(),
        },
    )?;
    let trust_update_registrar = DestinationTrustUpdateRegistrar::new(
        destination_rpc,
        destination_state_source.address(),
        config.destination.router_address,
        config.client.client_id.clone(),
        config.destination.trust_update_registrar.clone(),
    )?;
    let height_source = ZksyncHeightProvider::new(l2_rpc.clone(), config.l2_rpc.max_batch_lookback);
    let packet_evidence_source =
        PacketEvidenceCollector::new(l2_rpc.clone(), config.ibc_storage.clone());
    let bootstrap = Arc::new(
        BootstrapResolver::new(config.bootstrap.clone(), config.request_timeout)?.resolve()?,
    );
    let trust_evidence_source = Arc::new(BeaconTrustUpdateCollector::new(
        config.bootstrap.clone(),
        config.request_timeout,
        &bootstrap,
    )?);
    let state_evidence_source = SettlementEvidenceCollector::new(
        l2_rpc,
        l1_rpc,
        config.ibc_storage.clone(),
        config.settlement.clone(),
        &config.bootstrap,
        config.request_timeout,
    )?;
    let engine = Arc::new(PrividiumEngine::new(
        config.client.clone(),
        backend,
        ChainSources {
            height: height_source,
            packet_evidence: packet_evidence_source,
            state_evidence: state_evidence_source,
            destination_state: destination_state_source,
            trust_update_registrar,
            trust_evidence: trust_evidence_source,
        },
        bootstrap,
        ArtifactBindings {
            source_profile_id: config.bootstrap.source_profile_id_bytes,
            ibc: config.ibc_storage.clone(),
            slots_per_sync_committee_period: sync_committee_period_slots(&config)?,
            max_automatic_trust_updates: config.max_automatic_trust_updates,
        },
    ));
    engine.check_backend()?;
    let engine = Arc::new(DeduplicatingEngine::new(
        engine,
        config.max_concurrent_requests + config.max_queued_requests,
    ));
    let service = ProofApi::new(
        engine,
        config.client.clone(),
        config.api_authorization.clone(),
        config.max_concurrent_requests,
        config.max_queued_requests,
        config.max_concurrent_height_requests,
    );
    eprintln!("Prividium Proof API listening on {}", config.bind_address);
    serve(config.bind_address, service, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}

fn load_config() -> Result<ValidatedConfig, Box<dyn std::error::Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let flag = arguments.next();
    let path = arguments.next();
    if flag.as_deref() != Some(std::ffi::OsStr::new("--config"))
        || path.is_none()
        || arguments.next().is_some()
    {
        return Err("usage: prividium-proof-api --config <config.json>".into());
    }
    Ok(Config::load(Path::new(&path.ok_or("configuration path is missing")?))?.validate()?)
}

fn sync_committee_period_slots(config: &ValidatedConfig) -> Result<u64, &'static str> {
    config
        .bootstrap
        .slots_per_epoch
        .checked_mul(config.bootstrap.epochs_per_sync_committee_period)
        .ok_or("sync committee period size overflow")
}
