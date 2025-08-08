// Copyright (C) 2025-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use netgauze_flow_pkt::{
    ie::{netgauze, Field, HasIE, IE},
    ipfix, FlowInfo,
};
use netgauze_flow_service::FlowRequest;
use std::{
    collections::BTreeSet,
    hash::{DefaultHasher, Hash, Hasher},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};

use crate::flow::enrichment::{EnrichmentActorHandle, EnrichmentOperation, Scope};

#[derive(Debug)]
enum FlowOptionsActorCommand {
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum FlowOptionsActorError {
    FlowReceiveError,
}

impl std::fmt::Display for FlowOptionsActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FlowReceiveError => write!(f, "error in flow receive channel"),
        }
    }
}

impl std::error::Error for FlowOptionsActorError {}

#[derive(Debug, Clone)]
pub struct FlowOptionsActorStats {
    received_flows: opentelemetry::metrics::Counter<u64>,
    send_error: opentelemetry::metrics::Counter<u64>,
}

impl FlowOptionsActorStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received_flows = meter
            .u64_counter("netgauze.collector.flows.handlers.options.received.flows")
            .with_description("Number of Received Flows")
            .build();
        let send_error = meter
            .u64_counter("netgauze.collector.flows.handlers.options.send_error")
            .with_description("Error sending the enrichment operation to the enrichment actor")
            .build();
        Self {
            received_flows,
            send_error,
        }
    }
}

#[derive(Debug, Clone)]
enum FlowOptionsRecordType {
    Sampling,
    Interface,
    Vrf,
    Unknown(u64),
}

impl FlowOptionsRecordType {
    fn from_record(record: &ipfix::DataRecord) -> Self {
        let field_ies: Vec<IE> = record.fields().iter().map(|field| field.ie()).collect();

        if Self::is_sampling_type(&field_ies) {
            return Self::Sampling;
        }

        if Self::is_interface_type(&field_ies) {
            return Self::Interface;
        }

        if Self::is_vrf_type(&field_ies) {
            return Self::Vrf;
        }

        // Create a deterministic hash from the IEs
        let ie_hash = Self::hash_ies(&field_ies);
        Self::Unknown(ie_hash)
    }

    fn hash_ies(ies: &[IE]) -> u64 {
        // Use BTreeSet to ensure consistent ordering regardless of input order
        let ordered_ies: BTreeSet<_> = ies.iter().collect();

        let mut hasher = DefaultHasher::new();
        for ie in ordered_ies {
            ie.hash(&mut hasher);
        }
        hasher.finish()
    }

    fn is_sampling_type(ies: &[IE]) -> bool {
        let has_sampling_interval = ies.iter().any(|ie| matches!(ie, IE::samplingInterval));
        let has_sampler_random_interval =
            ies.iter().any(|ie| matches!(ie, IE::samplerRandomInterval));
        let has_sampling_size = ies.iter().any(|ie| matches!(ie, IE::samplingSize));
        let has_sampling_population = ies.iter().any(|ie| matches!(ie, IE::samplingPopulation));

        // Sampling record if we have size+population OR interval OR sampler/selector related fields
        has_sampling_interval
            || has_sampler_random_interval
            || (has_sampling_size && has_sampling_population)
    }

    // TODO: add NetGauze new IEs for ingress(egress)InterfaceName etc
    fn is_interface_type(ies: &[IE]) -> bool {
        let has_interface_name = ies.iter().any(|ie| matches!(ie, IE::interfaceName));
        let has_interface_description = ies.iter().any(|ie| matches!(ie, IE::interfaceDescription));

        has_interface_name || has_interface_description
    }

    // TODO: add NetGauze new IEs for ingress(egress)VRFname and RD
    fn is_vrf_type(ies: &[IE]) -> bool {
        let has_vrf_name = ies.iter().any(|ie| matches!(ie, IE::VRFname));
        let has_rd = ies
            .iter()
            .any(|ie| matches!(ie, IE::mplsVpnRouteDistinguisher));

        has_vrf_name || has_rd // TODO: here check what we like?
    }

    fn process_options_record(
        &self,
        peer: SocketAddr,
        obs_domain_id: u32,
        record: &ipfix::DataRecord,
    ) -> EnrichmentOperation {
        let clean_record = match self {
            Self::Sampling => {
                debug!("Received sampling options record from peer {}", peer);
                record
            }
            Self::Interface => {
                debug!("Received interface options record from peer {}", peer);
                Self::handle_interface_record(peer, record)
            }
            Self::Vrf => {
                debug!("Processing VRF options record from peer {}", peer);
                Self::handle_vrf_record(peer, record)
            }
            Self::Unknown(hash) => {
                debug!(
                    "Unknown options record type with IEs hash {} from peer {}: {:?}",
                    *hash, peer, *record
                );
                record
            }
        };

        let scope = Scope::new(obs_domain_id, Some(clean_record.scope_fields().to_vec()));
        EnrichmentOperation::Upsert(peer.ip(), scope, 16, clean_record.fields().to_vec())
    }

    fn handle_interface_record(peer: SocketAddr, record: &ipfix::DataRecord) -> &ipfix::DataRecord {
        record
        // TODO: process s.t. it's ready for sending to enrichment
    }

    fn handle_vrf_record(peer: SocketAddr, record: &ipfix::DataRecord) -> &ipfix::DataRecord {
        record
        // TODO: process s.t. it's ready for sending to enrichment
    }
}

struct FlowOptionsActor {
    cmd_rx: mpsc::Receiver<FlowOptionsActorCommand>,
    // config: FlowOptionsActorConfig, // TODO: for specifying e.g disk location where to store the
    // option metadata
    flow_rx: async_channel::Receiver<Arc<FlowRequest>>, /* where we receive option data (for now
                                                         * not yet filtered) */
    enrichment_handles: Vec<EnrichmentActorHandle>,
    stats: FlowOptionsActorStats,
}

impl FlowOptionsActor {
    fn new(
        cmd_rx: mpsc::Receiver<FlowOptionsActorCommand>,
        flow_rx: async_channel::Receiver<Arc<FlowRequest>>,
        enrichment_handles: Vec<EnrichmentActorHandle>,
        stats: FlowOptionsActorStats,
    ) -> Self {
        Self {
            cmd_rx,
            flow_rx,
            enrichment_handles,
            stats,
        }
    }
    async fn run(mut self) -> anyhow::Result<String> {
        info!("Starting Flow Options Handler Actor");
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(FlowOptionsActorCommand::Shutdown) => {
                            info!("Flow options actor shutting down");
                            Ok("Flow options actor terminated after a shutdown command".to_string())
                        }
                        None => {
                            warn!("Flow options actor terminated due to empty command channel");
                            Ok("Flow options actor terminated due to empty command channel".to_string())
                        }
                    }
                }
                flow = self.flow_rx.recv() => {
                    match flow {
                        Ok(req) => {
                            let (peer, flow) = req.as_ref().clone();

                            let peer_tags = [
                                opentelemetry::KeyValue::new("network.peer.address", format!("{}", peer.ip())),
                                opentelemetry::KeyValue::new(
                                    "network.peer.port",
                                    opentelemetry::Value::I64(peer.port().into()),
                                ),
                            ];
                            self.stats.received_flows.add(1, &peer_tags);

                            // Process only Options Data Records
                            // TODO: discuss again how/where to implement the filtering
                            match flow {
                                FlowInfo::IPFIX(pkt) => {
                                    for set in pkt.sets() {

                                        let data_records = if let ipfix::Set::Data { id: _, records } = set {
                                            records
                                        } else {
                                            continue;
                                        };

                                        for record in data_records {
                                            if record.scope_fields().len() > 0 {
                                                // options data record found
                                                // println!("{}", serde_json::to_string(&record).unwrap());

                                                let record_type = FlowOptionsRecordType::from_record(record);
                                                let op = record_type.process_options_record(
                                                    peer,
                                                    pkt.observation_domain_id(),
                                                    record
                                                );
                                                debug!("Sending Enrichment Operation: \n{op}");

                                                for handle in &self.enrichment_handles {
                                                    if let Err(err) = handle.update_enrichment(op.clone()).await {
                                                        warn!("Failed to send enrichment operation: {err}");
                                                        let tags = [
                                                            opentelemetry::KeyValue::new("network.peer.address", format!("{}", peer.ip())),
                                                            opentelemetry::KeyValue::new(
                                                                "network.peer.port",
                                                                opentelemetry::Value::I64(peer.port().into()),
                                                            ),
                                                        ];
                                                        self.stats.send_error.add(1, &tags);
                                                    }
                                                }

                                            }
                                        }
                                    }
                                }
                                // TODO: handle NetFlowV9
                                _ => {
                                    info!("Unsupported flow version for peer {}", peer);
                                }
                            }

                        }
                        Err(err) => {
                            error!("Flow options shutting down due to flow receive error: {err}");
                            Err(FlowOptionsActorError::FlowReceiveError)?;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
enum FlowOptionsActorHandleError {
    SendError(String),
}

pub struct FlowOptionsActorHandle {
    cmd_send: mpsc::Sender<FlowOptionsActorCommand>,
}

impl FlowOptionsActorHandle {
    pub fn new(
        flow_rx: async_channel::Receiver<Arc<FlowRequest>>,
        enrichment_handles: Vec<EnrichmentActorHandle>,
        stats: either::Either<opentelemetry::metrics::Meter, FlowOptionsActorStats>,
    ) -> (JoinHandle<anyhow::Result<String>>, Self) {
        let (cmd_send, cmd_rx) = mpsc::channel::<FlowOptionsActorCommand>(1);
        let stats = match stats {
            either::Left(meter) => FlowOptionsActorStats::new(meter),
            either::Right(stats) => stats,
        };
        let actor = FlowOptionsActor::new(cmd_rx, flow_rx, enrichment_handles, stats);
        let join_handle = tokio::spawn(actor.run());
        let handle = Self { cmd_send };
        (join_handle, handle)
    }

    async fn shutdown(&self) -> Result<(), FlowOptionsActorHandleError> {
        self.cmd_send
            .send(FlowOptionsActorCommand::Shutdown)
            .await
            .map_err(|e| FlowOptionsActorHandleError::SendError(e.to_string()))
    }
}
