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

// TODO: documentation here
// TODO: add tests for all the match arms and conditions below...
// TODO: fix error handling / log messages / otel counters...
// TODO: implement early return...

use crate::telemetry::{
    DataCollectionMetadata, FilterSpec, Label, LabelValue, Manifest, SessionProtocol,
    TelemetryMessage, TelemetryMessageMetadata, YangPushSubscriptionMetadata,
};
use either::Either;
use netgauze_udp_notif_pkt::{
    yang::notification::{
        Notification, NotificationEnvelope, NotificationVariant, SubscriptionId,
        SubscriptionStartedModified, SubscriptionTerminated, Transport,
    },
    UdpNotifPacket, UdpNotifPacketDecoded, UdpNotifPayload,
};
use serde_json::Value;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use chrono::Utc;
use colored::*;
use shadow_rs::shadow;
use sysinfo::System;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};

shadow!(build);

/// Cache for YangPush subscriptions metadata
pub type SubscriptionsCache = HashMap<SubscriptionId, TelemetryMessageMetadata>;

#[derive(Debug, Clone, Copy)]
pub enum YangPushEnrichmentActorCommand {
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum YangPushEnrichmentActorError {
    EnrichmentChannelClosed,
    YangPushReceiveError,
    UnknownPayload,
    UnknownNotificationVariant,
    UnsupportedNotificationVariant(NotificationVariant),
    NotificationSerializationError,
}

impl std::fmt::Display for YangPushEnrichmentActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnrichmentChannelClosed => write!(f, "enrichment channel closed"),
            Self::YangPushReceiveError => write!(f, "error in flow receive channel"),
            Self::UnknownPayload => {
                write!(f, "unknown udp-notif payload format")
            }
            Self::UnknownNotificationVariant => {
                write!(f, "unknown notification variant")
            }
            Self::UnsupportedNotificationVariant(notif) => {
                write!(f, "unsupported notification variant, type: {}", notif)
            }
            Self::NotificationSerializationError => {
                write!(f, "failed to serialize notification")
            }
        }
    }
}

impl std::error::Error for YangPushEnrichmentActorError {}

#[derive(Debug, Clone)]
pub struct YangPushEnrichmentStats {
    pub received_messages: opentelemetry::metrics::Counter<u64>,
    pub sent_messages: opentelemetry::metrics::Counter<u64>,
    pub send_error: opentelemetry::metrics::Counter<u64>,
    pub enrichment_error: opentelemetry::metrics::Counter<u64>,
}

impl YangPushEnrichmentStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received_messages = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.received.messages")
            .with_description("Number of Yang Push messages received for enrichment")
            .build();
        let sent_messages = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.sent")
            .with_description("Number of enriched Yang Push messages successfully sent upstream")
            .build();
        let send_error = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.sent.error")
            .with_description("Number of upstream sending errors")
            .build();
        let enrichment_error = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.error")
            .with_description("Number of Yang Push enrichment errors")
            .build();
        Self {
            received_messages,
            sent_messages,
            send_error,
            enrichment_error,
        }
    }
}

/// Fetches local system information into a Manifest object.
/// (host name, OS version, software version, build info, etc.)
fn fetch_sysinfo_manifest() -> Manifest {
    let mut sys = System::new_all();
    sys.refresh_all();

    Manifest {
        name: Some(format!(
            "{}@{}",
            build::PROJECT_NAME,
            System::host_name().unwrap_or_else(|| "unknown".to_string())
        )),
        vendor: Some("NetGauze".to_string()),
        vendor_pen: None,
        software_version: Some(format!("{} ({})", build::PKG_VERSION, build::SHORT_COMMIT)),
        software_flavor: Some(build::BUILD_RUST_CHANNEL.to_string()),
        os_version: System::os_version(),
        os_type: System::name(),
    }
}

/// Actor responsible for enriching Yang Push notifications.
/// Sends enriched TelemetryMessage objects.
struct YangPushEnrichmentActor {
    cmd_rx: mpsc::Receiver<YangPushEnrichmentActorCommand>,
    udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
    enriched_tx: async_channel::Sender<TelemetryMessage>,
    labels: HashMap<IpAddr, (u32, HashMap<String, String>)>,
    default_labels: (u32, HashMap<String, String>),
    subscriptions: HashMap<SocketAddr, SubscriptionsCache>,
    manifest: Manifest,
    stats: YangPushEnrichmentStats,
}

impl YangPushEnrichmentActor {
    fn new(
        cmd_rx: mpsc::Receiver<YangPushEnrichmentActorCommand>,
        udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
        enriched_tx: async_channel::Sender<TelemetryMessage>,
        stats: YangPushEnrichmentStats,
    ) -> Self {
        let default_labels = (
            0,
            HashMap::from([
                ("pkey".to_string(), "unknown".to_string()),
                ("nkey".to_string(), "unknown".to_string()),
            ]),
        );
        Self {
            cmd_rx,
            udp_notif_rx,
            enriched_tx,
            labels: HashMap::new(),
            default_labels,
            subscriptions: HashMap::new(),
            manifest: fetch_sysinfo_manifest(),
            stats,
        }
    }

    /// Caches metadata from SubscriptionStarted and SubscriptionModified
    /// messages.
    fn cache_subscription(
        &mut self,
        peer: SocketAddr,
        sub: &SubscriptionStartedModified,
    ) -> Result<TelemetryMessageMetadata, YangPushEnrichmentActorError> {
        let stream = sub.target().stream().map(|f| f.to_string());

        let datastore = sub.target().datastore().map(|f| f.to_string());

        let xpath_filter: Option<String> = sub
            .target()
            .datastore_xpath_filter()
            .map(|f| f.to_string())
            .or_else(|| sub.target().stream_xpath_filter().map(|f| f.to_string()));

        let subtree_filter: Option<Value> = sub
            .target()
            .datastore_subtree_filter()
            .cloned()
            .or_else(|| sub.target().stream_subtree_filter().cloned());

        let subscription_metadata = YangPushSubscriptionMetadata {
            id: Some(sub.id()),
            filter_spec: FilterSpec {
                stream,
                datastore,
                xpath_filter,
                subtree_filter,
            },
            stop_time: sub.stop_time().cloned(),
            transport: sub.transport().cloned(),
            encoding: sub.encoding().cloned(),
            purpose: sub.purpose().cloned(),
            update_trigger: sub.update_trigger().clone(),
            module_version: sub.module_version().cloned().unwrap_or_default(), /* TODO: add test
                                                                                * here for the
                                                                                * default... */
            yang_library_content_id: sub.yang_library_content_id().map(|id| id.to_string()),
        };

        let telemetry_message_metadata = TelemetryMessageMetadata {
            event_time: None,
            yang_push_subscription: Some(subscription_metadata),
        };

        // Insert the subscription metadata into the cache
        // TODO: counters / warnings here for cache misses?
        let peer_subscriptions = self.subscriptions.entry(peer).or_insert_with(HashMap::new);
        peer_subscriptions.insert(sub.id(), telemetry_message_metadata.clone());

        debug!(
            "Yang Push Subscription Cache: {}",
            serde_json::to_string(&self.subscriptions).unwrap().red()
        );

        Ok(telemetry_message_metadata)
    }

    /// Handles SubscriptionTerminated messages by removing subscription
    /// metadata from the cache.
    fn delete_subscription(
        &mut self,
        peer: SocketAddr,
        sub: &SubscriptionTerminated,
    ) -> Result<TelemetryMessageMetadata, YangPushEnrichmentActorError> {
        // Get and delete subscription information from the cache
        let telemetry_message_metadata = self
            .subscriptions
            .get_mut(&peer)
            .and_then(|subscriptions| subscriptions.remove(&sub.id()))
            .unwrap_or_default();

        debug!(
            "Yang Push Subscription Cache: {}",
            serde_json::to_string(&self.subscriptions).unwrap().red()
        );

        Ok(telemetry_message_metadata)
    }

    /// Retrieves subscription metadata from the cache based on the peer address
    /// and subscription ID.
    fn get_subscription(
        &self,
        peer: SocketAddr,
        subscription_id: &SubscriptionId,
    ) -> Result<TelemetryMessageMetadata, YangPushEnrichmentActorError> {
        // Get subscription information from the cache
        let telemetry_message_metadata = self
            .subscriptions
            .get(&peer)
            .and_then(|subscriptions| subscriptions.get(subscription_id))
            .cloned()
            .unwrap_or_default();

        Ok(telemetry_message_metadata)
    }

    /// Processes a Yang Push notification and produces a TelemetryMessage
    /// object.
    fn process_notification(
        &mut self,
        peer: SocketAddr,
        message: Either<&Notification, &NotificationEnvelope>,
    ) -> Result<TelemetryMessage, YangPushEnrichmentActorError> {
        let timestamp = Utc::now();
        let telemetry_message_metadata: TelemetryMessageMetadata;

        // Get sonata labels from the cache
        let (_, labels) = self.labels.get(&peer.ip()).unwrap_or(&self.default_labels);
        let labels: Vec<Label> = labels
            .iter()
            .map(|(key, value)| Label {
                name: key.clone(),
                value: Some(LabelValue::StringValue {
                    string_values: value.clone(),
                }),
            })
            .collect();

        // Closure to process the NotificationVariant
        let mut process_variant = |notification_variant: Option<&NotificationVariant>| -> Result<
            TelemetryMessageMetadata,
            YangPushEnrichmentActorError,
        > {
            match notification_variant {
                Some(NotificationVariant::SubscriptionStarted(sub_started)) => {
                    debug!(
                        "Received Subscription Started Message (peer: {}, id={})",
                        peer,
                        sub_started.id()
                    );
                    self.cache_subscription(peer, &sub_started)
                }
                Some(NotificationVariant::SubscriptionModified(sub_modified)) => {
                    debug!(
                        "Received Subscription Modified Message (peer: {}, id={})",
                        peer,
                        sub_modified.id()
                    );
                    self.cache_subscription(peer, &sub_modified)
                }
                Some(NotificationVariant::SubscriptionTerminated(sub_terminated)) => {
                    debug!(
                        "Received Subscription Terminated Message (peer: {}, id={})",
                        peer,
                        sub_terminated.id()
                    );
                    self.delete_subscription(peer, &sub_terminated)
                }
                Some(NotificationVariant::YangPushUpdate(push_update)) => {
                    debug!(
                        "Received Yang Push Update Message (peer: {}, id={})",
                        peer,
                        push_update.id()
                    );
                    self.get_subscription(peer, &push_update.id())
                }
                Some(notif) => {
                    warn!(
                    "YangPushEnrichmentActorError: UnsupportedNotificationVariant (peer: {}, type: {})",
                    peer,
                    notif
                );
                    Err(YangPushEnrichmentActorError::UnsupportedNotificationVariant(notif.clone()))
                }
                None => {
                    warn!(
                        "Receive Notification Message (peer: {}) with unknown/unsupported type",
                        peer
                    );
                    Err(YangPushEnrichmentActorError::UnknownNotificationVariant)
                }
            }
        };

        // Match on the wrapper and call the closure to process the notification content
        let payload = match message {
            Either::Left(notification) => {
                telemetry_message_metadata = process_variant(notification.notification())?;
                serde_json::to_value(&notification).map_err(|err| {
                    warn!("Failed to serialize Notification: {err}");
                    YangPushEnrichmentActorError::NotificationSerializationError
                })?
            }
            Either::Right(envelope) => {
                telemetry_message_metadata = process_variant(envelope.contents())?;
                serde_json::to_value(&envelope).map_err(|err| {
                    warn!("Failed to serialize NotificationEnvelope: {err}");
                    YangPushEnrichmentActorError::NotificationSerializationError
                })?
            }
        };

        // TODO: think here --> just set it to yang push so it also works when we didn't
        // yet recevie sub-started... Infer Session Protocol from Transport
        let mut session_protocol = SessionProtocol::default();
        if let Some(yang_push_subscription) = &telemetry_message_metadata.yang_push_subscription {
            session_protocol = match yang_push_subscription.transport {
                Some(Transport::UDPNotif) | Some(Transport::HTTPSNotif) => {
                    SessionProtocol::YangPush
                }
                _ => SessionProtocol::Unknown,
            };
        }

        // Populate metadata in a new TelemetryMessage
        Ok(TelemetryMessage {
            timestamp,
            session_protocol,
            network_node_manifest: Manifest::default(),
            data_collection_manifest: self.manifest.clone(),
            telemetry_message_metadata,
            data_collection_metadata: DataCollectionMetadata {
                remote_address: peer.ip(),
                remote_port: Some(peer.port()),
                local_address: None, //TODO: get from config?
                local_port: None,    //TODO: get from config?
                labels,
            },
            payload: Some(payload),
        })
    }

    /// Main loop for the actor: handling commands and incoming notification
    /// messages.
    async fn run(mut self) -> anyhow::Result<String> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(YangPushEnrichmentActorCommand::Shutdown) => {
                            info!("Shutting down Yang Push enrichment actor");
                            Ok("Enrichment shutdown successfully".to_string())
                        }
                        None => {
                            warn!("Yang Push enrichment actor terminated due to command channel closing");
                            Ok("Enrichment shutdown successfully".to_string())
                        }
                    }
                }
                msg = self.udp_notif_rx.recv() => {
                    match msg {
                        Ok(arc_tuple) => {
                            let (peer, udp_notif_pkt) = arc_tuple.as_ref();
                            let peer_tags = [
                                opentelemetry::KeyValue::new(
                                    "network.peer.address",
                                    format!("{}", peer.ip()),
                                ),
                                opentelemetry::KeyValue::new(
                                    "network.peer.port",
                                    opentelemetry::Value::I64(peer.port().into()),
                                ),
                            ];
                            self.stats.received_messages.add(1, &peer_tags);

                            // Decode the UdpNotifPacket into UdpNotifPacketDecoded
                            let udp_notif_pkt_decoded: UdpNotifPacketDecoded = match udp_notif_pkt.try_into() {
                              Ok(decoded) => decoded,
                              Err(err) => {
                                  warn!("Failed to decode UdpNotifPacket: {err}");
                                  self.stats.enrichment_error.add(1, &peer_tags);
                                  continue;
                              }
                            };

                            // TODO: also here implement closure to avoid code duplication!
                            //       also test with a 6wind pcap if it's working properly
                            // Process the notification
                            if let UdpNotifPayload::Notification(notification) = udp_notif_pkt_decoded.payload() {
                              match self.process_notification(*peer, Either::Left(notification)) {
                                  Ok(telemetry_message) => {

                                      // TEMP DEBUG STATEMENT
                                      info!("{}", serde_json::to_string(&telemetry_message).unwrap().purple());

                                      // Successfully processed and got a TelemetryMessage
                                      if let Err(err) = self.enriched_tx.send(telemetry_message).await {
                                          error!("YangPushEnrichmentActor send error: {err}");
                                          self.stats.send_error.add(1, &peer_tags);
                                      } else {
                                          self.stats.sent_messages.add(1, &peer_tags);
                                      }
                                  }
                                  Err(err) => {
                                      warn!("Error processing notification: {err}");
                                      self.stats.enrichment_error.add(1, &peer_tags);
                                  }
                              }
                          } else if let UdpNotifPayload::NotificationEnvelope(notification_envelope) = udp_notif_pkt_decoded.payload() {
                              match self.process_notification(*peer, Either::Right(notification_envelope)) {
                                  Ok(telemetry_message) => {

                                      // TEMP DEBUG STATEMENT
                                      info!("{}", serde_json::to_string(&telemetry_message).unwrap().purple());

                                      // Successfully processed and got a TelemetryMessage
                                      if let Err(err) = self.enriched_tx.send(telemetry_message).await {
                                          error!("YangPushEnrichmentActor send error: {err}");
                                          self.stats.send_error.add(1, &peer_tags);
                                      } else {
                                          self.stats.sent_messages.add(1, &peer_tags);
                                      }
                                  }
                                  Err(err) => {
                                      warn!("Error processing notification: {err}");
                                      self.stats.enrichment_error.add(1, &peer_tags);
                                  }
                              }
                          } else {
                              warn!("YangPushEnrichmentActorError: UnknownPayload");
                              Err(YangPushEnrichmentActorError::UnknownPayload)?;
                          }
                        }
                        Err(err) => {
                            error!("Shutting down due to FlowEnrichment recv error: {err}");
                            Err(YangPushEnrichmentActorError::YangPushReceiveError)?;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum YangPushEnrichmentActorHandleError {
    SendError,
}
impl std::fmt::Display for YangPushEnrichmentActorHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            YangPushEnrichmentActorHandleError::SendError => {
                write!(f, "Failed to send yang-push enrichment actor")
            }
        }
    }
}

impl std::error::Error for YangPushEnrichmentActorHandleError {}

/// Handle for interacting with the `YangPushEnrichmentActor`.
#[derive(Debug, Clone)]
pub struct YangPushEnrichmentActorHandle {
    cmd_send: mpsc::Sender<YangPushEnrichmentActorCommand>,
    enriched_rx: async_channel::Receiver<TelemetryMessage>,
}

impl YangPushEnrichmentActorHandle {
    pub fn new(
        buffer_size: usize,
        udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
        stats: either::Either<opentelemetry::metrics::Meter, YangPushEnrichmentStats>,
    ) -> (JoinHandle<anyhow::Result<String>>, Self) {
        let (cmd_send, cmd_recv) = mpsc::channel(10);
        let (enriched_tx, enriched_rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            either::Either::Left(meter) => YangPushEnrichmentStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = YangPushEnrichmentActor::new(cmd_recv, udp_notif_rx, enriched_tx, stats);
        let join_handle = tokio::spawn(actor.run());
        let handle = Self {
            cmd_send,
            enriched_rx,
        };
        (join_handle, handle)
    }

    pub async fn shutdown(&self) -> Result<(), YangPushEnrichmentActorHandleError> {
        self.cmd_send
            .send(YangPushEnrichmentActorCommand::Shutdown)
            .await
            .map_err(|_| YangPushEnrichmentActorHandleError::SendError)
    }

    pub fn subscribe(&self) -> async_channel::Receiver<TelemetryMessage> {
        self.enriched_rx.clone()
    }
}
