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

// TODO: naming revisit (types and functions) + documentation...

use crate::flow::enrichment::{cache::EnrichmentCache, EnrichmentOperation};
use netgauze_flow_pkt::{ipfix, FlowInfo};
use netgauze_flow_service::FlowRequest;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{error, info, warn};

struct EnrichmentActor {
    enrichment_cache: EnrichmentCache,
    cmd_rx: mpsc::Receiver<EnrichmentActorCommand>,
    enrichment_rx: async_channel::Receiver<EnrichmentOperation>,
    flow_rx: async_channel::Receiver<Arc<FlowRequest>>,
    enriched_tx: async_channel::Sender<(SocketAddr, FlowInfo)>,
    stats: EnrichmentStats,
    shard_id: usize,
}

impl EnrichmentActor {
    fn new(
        cmd_rx: mpsc::Receiver<EnrichmentActorCommand>,
        enrichment_rx: async_channel::Receiver<EnrichmentOperation>,
        flow_rx: async_channel::Receiver<Arc<FlowRequest>>,
        enriched_tx: async_channel::Sender<(SocketAddr, FlowInfo)>,
        stats: EnrichmentStats,
        shard_id: usize,
    ) -> Self {
        Self {
            enrichment_cache: EnrichmentCache::new(),
            cmd_rx,
            enrichment_rx,
            flow_rx,
            enriched_tx,
            stats,
            shard_id,
        }
    }

    // TODO: improve performance and add debug messages...
    // TODO: decide, result is vec<Flowinfo or full  flowinfo???)
    fn enrich(&self, peer_ip: IpAddr, flow: FlowInfo) -> Result<FlowInfo, EnrichmentActorError> {
        let enriched_flow = match flow {
            FlowInfo::IPFIX(pkt) => {
                let mut enriched_sets = Vec::new();
                for set in pkt.sets() {
                    let (id, data_records) = if let ipfix::Set::Data { id, records } = set {
                        (id, records)
                    } else {
                        continue;
                    };

                    // TODO: optimize the new FlowInfo/DataRecord creation....
                    let mut enriched_records = Vec::new();
                    for record in data_records {
                        if let Some(peer_metadata) = self.enrichment_cache.get(&peer_ip) {
                            enriched_records.push(record.clone().with_fields_added(
                                &peer_metadata.get_enrichment_fields(
                                    pkt.observation_domain_id(),
                                    record.fields(),
                                ),
                            ));
                        };
                    }
                    enriched_sets.push(ipfix::Set::Data {
                        id: *id,
                        records: enriched_records.into_boxed_slice(),
                    });
                }
                let ipfix_pkt = ipfix::IpfixPacket::new(
                    pkt.export_time(),
                    pkt.sequence_number(),
                    pkt.observation_domain_id(),
                    enriched_sets.into_boxed_slice(),
                );

                println!("{}", serde_json::to_string(&ipfix_pkt).unwrap()); // TODO: remove
                FlowInfo::IPFIX(ipfix_pkt)
            }
            // TODO: handle NetFlowV9
            // TODO: proper error message before finalizing the PR!
            _ => {
                todo!("Unsupported flow version for peer {}", peer_ip);
            }
        };

        Ok(enriched_flow) // TODO: error handling
    }

    async fn run(mut self) -> anyhow::Result<String> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(EnrichmentActorCommand::Shutdown) => {
                            info!("Shutting down flow enrichment actor");
                            Ok("Enrichment shutdown successfully".to_string())
                        }
                        None => {
                            warn!("Flow enrichment actor terminated due to command channel closing");
                            Ok("Enrichment shutdown successfully".to_string())
                        }
                    }
                }
                enrichment = self.enrichment_rx.recv() => {
                    match enrichment {
                        Ok(op) => {
                            self.stats.received_enrichment_ops.add(1, &[]);
                            self.enrichment_cache.apply_enrichment(op);
                        }
                        Err(err) => {
                            warn!("Enrichment channel closed, shutting down: {err:?}");
                            Err(EnrichmentActorError::EnrichmentChannelClosed)?;
                        }
                    }
                }
                flow = self.flow_rx.recv() => {
                    match flow {
                        Ok(req) => {
                            let (peer, flow) = req.as_ref().clone();

                            let peer_tags = [
                                opentelemetry::KeyValue::new(
                                    "shard_id",
                                    opentelemetry::Value::I64(self.shard_id as i64),
                                ),
                                opentelemetry::KeyValue::new("network.peer.address", format!("{}", peer.ip())),
                                opentelemetry::KeyValue::new(
                                    "network.peer.port",
                                    opentelemetry::Value::I64(peer.port().into()),
                                ),
                            ];
                            self.stats.received_flows.add(1, &peer_tags);

                            let enriched = match self.enrich(peer.ip(), flow) {
                                Ok(enriched) => enriched,
                                Err(err) => {
                                    error!("Failed to enrich flow from {}: {}", peer.ip(), err);
                                    self.stats.enrich_error.add(1, &peer_tags);
                                    continue;
                                }
                            };
                            if let Err(err) = self.enriched_tx.send((peer, enriched)).await {
                                error!("FlowEnrichment send error: {err}");
                                 self.stats.send_error.add(1, &peer_tags);
                            } else {
                                 self.stats.sent.add(1, &peer_tags);
                            }
                        }
                        Err(err) => {
                            error!("Shutting down due to FlowEnrichment recv error: {err}");
                            Err(EnrichmentActorError::FlowReceiveError)?;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EnrichmentActorCommand {
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum EnrichmentActorError {
    EnrichmentChannelClosed,
    FlowReceiveError,
}

impl std::fmt::Display for EnrichmentActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnrichmentChannelClosed => write!(f, "enrichment channel closed"),
            Self::FlowReceiveError => write!(f, "error in flow receive channel"),
        }
    }
}

impl std::error::Error for EnrichmentActorError {}

#[derive(Debug, Clone)]
pub struct EnrichmentStats {
    pub received_flows: opentelemetry::metrics::Counter<u64>,
    pub received_enrichment_ops: opentelemetry::metrics::Counter<u64>,
    pub sent: opentelemetry::metrics::Counter<u64>,
    pub send_error: opentelemetry::metrics::Counter<u64>,
    pub enrich_error: opentelemetry::metrics::Counter<u64>,
}

impl EnrichmentStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received_flows = meter
            .u64_counter("netgauze.collector.flows.enrichment.received.flows")
            .with_description("Number of flows received for enrichment")
            .build();
        let received_enrichment_ops = meter
            .u64_counter("netgauze.collector.flows.enrichment.received.enrichment.operations")
            .with_description("Number of enrichment updates received from SONATA")
            .build();
        let sent = meter
            .u64_counter("netgauze.collector.flows.enrichment.sent")
            .with_description("Number of enriched flows successfully sent upstream")
            .build();
        let send_error = meter
            .u64_counter("netgauze.collector.flows.enrichment.sent.error")
            .with_description("Number of enrichment updates sent upstream error")
            .build();
        let enrich_error = meter
            .u64_counter("netgauze.collector.flows.enrichment.enrich.error")
            .with_description("Number of enrichment updates sent upstream error")
            .build();
        Self {
            received_flows,
            received_enrichment_ops,
            sent,
            send_error,
            enrich_error,
        }
    }
}

#[derive(Debug)]
pub enum EnrichmentActorHandleError {
    SendError,
}
impl std::fmt::Display for EnrichmentActorHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrichmentActorHandleError::SendError => {
                write!(f, "Failed to send flow enrichment actor")
            }
        }
    }
}

impl std::error::Error for EnrichmentActorHandleError {}

#[derive(Debug, Clone)]
pub struct EnrichmentActorHandle {
    cmd_send: mpsc::Sender<EnrichmentActorCommand>,
    enrichment_tx: async_channel::Sender<EnrichmentOperation>,
    enriched_rx: async_channel::Receiver<(SocketAddr, FlowInfo)>,
}

impl EnrichmentActorHandle {
    pub fn new(
        buffer_size: usize,
        flow_rx: async_channel::Receiver<Arc<FlowRequest>>,
        stats: either::Either<opentelemetry::metrics::Meter, EnrichmentStats>,
        shard_id: usize,
    ) -> (JoinHandle<anyhow::Result<String>>, Self) {
        let (cmd_send, cmd_recv) = mpsc::channel(10);
        let (enrichment_tx, enrichment_rx) = async_channel::bounded(buffer_size);
        let (enriched_tx, enriched_rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            either::Either::Left(meter) => EnrichmentStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = EnrichmentActor::new(
            cmd_recv,
            enrichment_rx,
            flow_rx,
            enriched_tx,
            stats,
            shard_id,
        );
        let join_handle = tokio::spawn(actor.run());
        let handle = Self {
            cmd_send,
            enrichment_tx,
            enriched_rx,
        };
        (join_handle, handle)
    }

    pub async fn shutdown(&self) -> Result<(), EnrichmentActorHandleError> {
        self.cmd_send
            .send(EnrichmentActorCommand::Shutdown)
            .await
            .map_err(|_| EnrichmentActorHandleError::SendError)
    }

    pub async fn update_enrichment(
        &self,
        op: EnrichmentOperation,
    ) -> Result<(), EnrichmentActorHandleError> {
        self.enrichment_tx
            .send(op)
            .await
            .map_err(|_| EnrichmentActorHandleError::SendError)
    }

    pub fn subscribe(&self) -> async_channel::Receiver<(SocketAddr, FlowInfo)> {
        self.enriched_rx.clone()
    }
}
