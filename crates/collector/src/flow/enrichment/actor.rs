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

// TODO: naming revisit...

use netgauze_flow_pkt::{
    ie::{netgauze, Field, HasIE, IE},
    FlowInfo,
};
use netgauze_flow_service::FlowRequest;
use serde::{Deserialize, Serialize};
use std::{
    collections::{btree_map, hash_map, BTreeMap, HashMap},
    fmt::Display,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Copy)]
pub enum EnrichmentActorCommand {
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum EnrichmentActorError {
    EnrichmentChannelClosed,
    FlowReceiveError,
    FieldAdditionFailed(String),
}

impl std::fmt::Display for EnrichmentActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnrichmentChannelClosed => write!(f, "enrichment channel closed"),
            Self::FlowReceiveError => write!(f, "error in flow receive channel"),
            Self::FieldAdditionFailed(msg) => write!(f, "failed to add fields to flow: {msg}"),
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

/// Operations to update or delete enrichment data
#[derive(Debug, Clone)]
pub enum EnrichmentOperation {
    Upsert(IpAddr, Scope, Weight, Vec<Field>),
    Delete(IpAddr, Scope, Weight),
}

impl Display for EnrichmentOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upsert(ip, scope, weight, fields) => {
                write!(
                    f,
                    "Upsert(ip={}, scope={}, weight={}, fields={:?})",
                    ip, scope, weight, fields,
                )
            }
            Self::Delete(ip, scope, weight) => {
                write!(f, "Delete(ip={}, scope={}, weight={})", ip, scope, weight)
            }
        }
    }
}

// TODO: think more about data structures to use (we need a fast one to iterate
// through when data record arrives..) --> need to do lot of testing of edge
// cases... (separate file with this logic as well, e.g. cache.rs)
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct PeerMetadata {
    map: BTreeMap<Scope, HashMap<IE, MetadataField>>,
}
// TODO: start enriching from global scope then onwards (need a sorted map
// here), then only       replace conflicting entries if the scoped ones have
// weight >= global entry weight

// TODO: when upserting here and scope=global, don't replace the whole vec but
// instead append to it       (and check if IE already there only replace it
// based on weight)

// TODO: idea to remember: if we see systeminitTime being changed, issue a
// delete of everything for the peer before  adding the new incoming option
// data...

#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Scope {
    obs_domain_id: u32,
    scope_fields: Option<Vec<Field>>,
}

impl Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_global() {
            write!(f, "[SYSTEM]")
        } else if let Some(ref fields) = self.scope_fields {
            write!(f, "obs_domain_id({})+{:?}", self.obs_domain_id, fields)
        } else {
            write!(f, "[obs_domain_id={}]", self.obs_domain_id)
        }
    }
}

impl Scope {
    pub fn new(obs_domain_id: u32, scope_fields: Option<Vec<Field>>) -> Self {
        Self {
            obs_domain_id,
            scope_fields,
        }
    }
    fn is_global(&self) -> bool {
        self.obs_domain_id == 0 && self.scope_fields.is_none()
    }
}

pub type Weight = u8;
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
struct MetadataField {
    weight: Weight,
    field: Field,
}

// TODO: FxHashMap also here?
// TODO: define types for the cache key and value, for code readability...
struct EnrichmentActor {
    peer_metadata_cache: HashMap<IpAddr, PeerMetadata>,
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
            peer_metadata_cache: HashMap::new(),
            cmd_rx,
            enrichment_rx,
            flow_rx,
            enriched_tx,
            stats,
            shard_id,
        }
    }

    // TODO: remember to discuss if we are ok with this same logic for global &
    // non-global scope
    fn apply_enrichment(&mut self, op: EnrichmentOperation) {
        match op {
            EnrichmentOperation::Upsert(ip, scope, weight, incoming_fields) => {
                let peer_metadata = self.peer_metadata_cache.entry(ip).or_insert_with(|| {
                    debug!("Creating new peer metadata cache entry for ip={}", ip);
                    PeerMetadata {
                        map: BTreeMap::new(),
                    }
                });

                match peer_metadata.map.entry(scope.clone()) {
                    btree_map::Entry::Occupied(mut entry) => {
                        let curr_fields = entry.get_mut();

                        for field in incoming_fields {
                            let ie = field.ie();

                            let metadata_field = MetadataField { weight, field };

                            // Check if field with same IE already exists
                            match curr_fields.entry(ie) {
                                hash_map::Entry::Occupied(mut occupied) => {
                                    let curr_weight = occupied.get().weight;
                                    if weight >= curr_weight {
                                        debug!("Replacing field in metadata for ip={}, scope={}, weight {}->{}",
                                            ip,
                                            scope,
                                            curr_weight,
                                            weight,
                                        );
                                        occupied.insert(metadata_field);
                                    } else {
                                        debug!("Ignoring lower weight field for ip={}, scope={}, weight: {}<{}",
                                            ip,
                                            scope,
                                            curr_weight,
                                            weight,
                                    );
                                    }
                                }
                                hash_map::Entry::Vacant(vacant) => {
                                    debug!(
                                        "Adding new field in metadata for ip={}, scope={}, weight={}",
                                        ip, scope, weight
                                    );
                                    vacant.insert(metadata_field);
                                }
                            }
                        }
                    }
                    btree_map::Entry::Vacant(entry) => {
                        let metadata_fields: HashMap<IE, MetadataField> = incoming_fields
                            .into_iter()
                            .map(|field| (field.ie(), MetadataField { weight, field }))
                            .collect();

                        debug!(
                            "Adding new metadata for ip={}, scope={}, weight={}",
                            ip, scope, weight,
                        );

                        entry.insert(metadata_fields);
                    }
                }
            }
            EnrichmentOperation::Delete(ip, scope, weight) => {
                if let Some(peer_metadata) = self.peer_metadata_cache.get_mut(&ip) {
                    match peer_metadata.map.entry(scope.clone()) {
                        btree_map::Entry::Occupied(mut occupied) => {
                            let current_fields = occupied.get_mut();

                            current_fields.retain(|_ie, m_fld| {
                                if m_fld.weight < weight {
                                    debug!(
                                        "Removing field [{:?}] for ip={}, scope={}, weight: {}>{}",
                                        m_fld.field, ip, scope, weight, m_fld.weight
                                    );
                                    false
                                } else {
                                    true
                                }
                            });

                            if current_fields.is_empty() {
                                occupied.remove();
                                debug!(
                                    "Scope {:?} now empty for ip={}, removing scope entry...",
                                    scope, ip
                                );

                                if peer_metadata.map.is_empty() {
                                    debug!("Cache now empty for ip={}, cleaning up...", ip);
                                    self.peer_metadata_cache.remove(&ip);
                                }
                            }
                        }
                        btree_map::Entry::Vacant(_) => {
                            debug!(
                                "No entry matching ip={} and scope={}, nothing to delete",
                                ip, scope
                            );
                        }
                    }
                } else {
                    debug!("No cache entry for ip={}, nothing to delete", ip);
                }
            }
        }
        // TODO: remove this log (idea for the future, dump this cache as ipfix packet to kafka json periodically, different topic)
        debug!("Cache dump: \n{:#?}", self.peer_metadata_cache);
    }

    fn enrich(&self, peer_ip: IpAddr, flow: FlowInfo) -> Result<FlowInfo, EnrichmentActorError> {
        // TODO: extend (for now here dummy enrichment...)
        let add_fields = [];

        flow.with_fields_added(&add_fields)
            .map_err(|e| EnrichmentActorError::FieldAdditionFailed(e.to_string()))
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
                            self.apply_enrichment(op);
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
