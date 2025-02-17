// TODO: discuss at what step do we integrate this (for getting messages from actor, then where to put the avro stuff...)
// TODO: avro message/schema construction

use std::collections::HashMap;
use std::hash::Hash;
use std::ops::Add;
use std::time::Duration;
use netgauze_analytics::aggregation::{AggregationWindowingExt, TimeSeriesData, Aggregator};
use netgauze_iana::tcp::*;
use chrono::{DateTime, Utc};
use std::fmt;
use std::fmt::Display;

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, Copy, Eq, Hash, Clone, PartialEq, Debug)]
pub enum IE {
    VMWare(VMWare_IE),
    OctetDeltaCount,
    PacketsDeltaCount,
    ProtocolIdentifier,
    TCPHeaderFlags,
    SourceTransportPort,
    SourceIPv4Address,
    DestinationTransportPort,
    DestinationIPv4Address,
    SourceIPv6Address,
    DestinationIPv6Address,
    ForwardingStatus,
    MinimumTTL,
    MaximumTTL,
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, Copy, Eq, Hash, Clone, PartialEq, Debug)]
pub enum VMWare_IE {
    TenantProtocol,
    TenantSourceIPv4,
    TenantDestIPv4,
    TenantSourceIPv6,
    TenantDestIPv6,
    TenantSourcePort,
    TenantDestPort,
}

// TODO: expand this and subsequent structs with all possibilities and then test e.g. with Option or template data to see how this behaves..
//       --> check we don't crash
#[derive(Debug, Clone, PartialEq)]
pub enum FlatFlowInfo {
    IPFIX(FlatIpfixPacket),
    // NetFlow(FlatIpfixPacket),
}

impl FlatFlowInfo {
  fn field_extract_as_key_str(&self, ie: &IE, idx: &usize) -> String {
      match self {
          FlatFlowInfo::IPFIX(packet) => packet.field_extract_as_key_str(ie, idx),
      }
  }

  fn field_set(&mut self, ie: &IE, idx: &usize, incoming: &FlatFlowInfo) {
      match self {
          FlatFlowInfo::IPFIX(packet) => {
              if let FlatFlowInfo::IPFIX(incoming_packet) = incoming {
                  packet.field_set(ie, idx, incoming_packet);
              }
          }
      }
  }

  fn field_addup(&mut self, ie: &IE, idx: &usize, incoming: &FlatFlowInfo) {
      match self {
          FlatFlowInfo::IPFIX(packet) => {
              if let FlatFlowInfo::IPFIX(incoming_packet) = incoming {
                  packet.field_addup(ie, idx, incoming_packet);
              }
          }
      }
  }

  fn field_minup(&mut self, ie: &IE, idx: &usize, incoming: &FlatFlowInfo) {
      match self {
          FlatFlowInfo::IPFIX(packet) => {
              if let FlatFlowInfo::IPFIX(incoming_packet) = incoming {
                  packet.field_minup(ie, idx, incoming_packet);
              }
          }
      }
  }

  fn field_maxup(&mut self, ie: &IE, idx: &usize, incoming: &FlatFlowInfo) {
      match self {
          FlatFlowInfo::IPFIX(packet) => {
              if let FlatFlowInfo::IPFIX(incoming_packet) = incoming {
                  packet.field_maxup(ie, idx, incoming_packet);
              }
          }
      }
  }

  fn field_bmoup(&mut self, ie: &IE, idx: &usize, incoming: &FlatFlowInfo) {
      match self {
          FlatFlowInfo::IPFIX(packet) => {
              if let FlatFlowInfo::IPFIX(incoming_packet) = incoming {
                  packet.field_bmoup(ie, idx, incoming_packet);
              }
          }
      }
  }
}


#[derive(Debug, Clone, PartialEq)]
pub struct FlatIpfixPacket {
    export_time: DateTime<Utc>,
    sequence_number: u32,
    observation_domain_id: u32,
    set: FlatSet,
}

impl FlatIpfixPacket {
  fn field_extract_as_key_str(&self, ie: &IE, idx: &usize) -> String {
      self.set.field_extract_as_key_str(ie, idx)
  }

  fn field_set(&mut self, ie: &IE, idx: &usize, incoming: &FlatIpfixPacket) {
      self.set.field_set(ie, idx, &incoming.set)
  }

  fn field_addup(&mut self, ie: &IE, idx: &usize, incoming: &FlatIpfixPacket) {
      self.set.field_addup(ie, idx, &incoming.set)
  }

  fn field_minup(&mut self, ie: &IE, idx: &usize, incoming: &FlatIpfixPacket) {
      self.set.field_minup(ie, idx, &incoming.set)
  }

  fn field_maxup(&mut self, ie: &IE, idx: &usize, incoming: &FlatIpfixPacket) {
      self.set.field_maxup(ie, idx, &incoming.set)
  }

  fn field_bmoup(&mut self, ie: &IE, idx: &usize, incoming: &FlatIpfixPacket) {
      self.set.field_bmoup(ie, idx, &incoming.set)
  }
}


#[derive(Debug, Clone, PartialEq)]
pub enum FlatSet {
    Data {
        id: u64,
        record: Box<FlatDataRecord>,
    },
}

impl FlatSet {
  fn field_extract_as_key_str(&self, ie: &IE, idx: &usize) -> String {
      match self {
          FlatSet::Data { record, .. } => record.field_extract_as_key_str(ie, idx),
      }
  }

  fn field_set(&mut self, ie: &IE, idx: &usize, incoming: &FlatSet) {
      match self {
          FlatSet::Data { record, .. } => {
              if let FlatSet::Data { record: incoming_record, .. } = incoming {
                  record.field_set(ie, idx, incoming_record)
              }
          }
      }
  }

  fn field_addup(&mut self, ie: &IE, idx: &usize, incoming: &FlatSet) {
      match self {
          FlatSet::Data { record, .. } => {
              if let FlatSet::Data { record: incoming_record, .. } = incoming {
                  record.field_addup(ie, idx, incoming_record)
              }
          }
      }
  }

  fn field_minup(&mut self, ie: &IE, idx: &usize, incoming: &FlatSet) {
    match self {
        FlatSet::Data { record, .. } => {
            if let FlatSet::Data { record: incoming_record, .. } = incoming {
                record.field_minup(ie, idx, incoming_record)
            }
        }
    }
  }

  fn field_maxup(&mut self, ie: &IE, idx: &usize, incoming: &FlatSet) {
      match self {
          FlatSet::Data { record, .. } => {
              if let FlatSet::Data { record: incoming_record, .. } = incoming {
                  record.field_maxup(ie, idx, incoming_record)
              }
          }
      }
  }

  fn field_bmoup(&mut self, ie: &IE, idx: &usize, incoming: &FlatSet) {
      match self {
          FlatSet::Data { record, .. } => {
              if let FlatSet::Data { record: incoming_record, .. } = incoming {
                  record.field_bmoup(ie, idx, incoming_record)
              }
          }
      }
  }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FlatDataRecord {
    fields: Fields,
}

impl FlatDataRecord {
  fn field_extract_as_key_str(&self, ie: &IE, idx: &usize) -> String {
      self.fields.field_extract_as_key_str(ie, idx)
  }

  fn field_set(&mut self, ie: &IE, idx: &usize, incoming: &FlatDataRecord) {
      self.fields.field_set(ie, idx, &incoming.fields)
  }

  fn field_addup(&mut self, ie: &IE, idx: &usize, incoming: &FlatDataRecord) {
      self.fields.field_addup(ie, idx, &incoming.fields)
  }

  fn field_minup(&mut self, ie: &IE, idx: &usize, incoming: &FlatDataRecord) {
    self.fields.field_minup(ie, idx, &incoming.fields)
  }

  fn field_maxup(&mut self, ie: &IE, idx: &usize, incoming: &FlatDataRecord) {
      self.fields.field_maxup(ie, idx, &incoming.fields)
  }

  fn field_bmoup(&mut self, ie: &IE, idx: &usize, incoming: &FlatDataRecord) {
      self.fields.field_bmoup(ie, idx, &incoming.fields)
  }
}

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Debug, Default)]
pub struct Fields {
        pub vmware: Option<VMWare_Fields>,
        pub octetDeltaCount: Option<Vec<u64>>,
        pub packetsDeltaCount: Option<Vec<u64>>,
        pub protocolIdentifier: Option<Vec<protocolIdentifier>>,
        pub tcpControlBits: Option<Vec<TCPHeaderFlags>>,
        pub sourceTransportPort: Option<Vec<u16>>,
        pub sourceIPv4Address: Option<Vec<std::net::Ipv4Addr>>,
        pub destinationTransportPort: Option<Vec<u16>>,
        pub destinationIPv4Address: Option<Vec<std::net::Ipv4Addr>>,
        pub sourceIPv6Address: Option<Vec<std::net::Ipv6Addr>>,
        pub destinationIPv6Address: Option<Vec<std::net::Ipv6Addr>>,
        pub forwardingStatus: Option<Vec<forwardingStatus>>,
        pub minimumTTL: Option<Vec<u8>>,
        pub maximumTTL: Option<Vec<u8>>,
}

impl Fields {

  fn field_extract_as_key_str(&self, ie: &IE, idx: &usize) -> String {
    match ie {
        IE::VMWare(vmware_ie) => self.vmware.as_ref()
            .map_or("None".to_string(), |vmware_fields| vmware_fields.field_extract_as_key_str(vmware_ie, idx)),
        IE::OctetDeltaCount => self.octetDeltaCount.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        IE::PacketsDeltaCount => self.packetsDeltaCount.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        IE::ProtocolIdentifier => self.protocolIdentifier.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        IE::TCPHeaderFlags => self.tcpControlBits.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        IE::SourceTransportPort => self.sourceTransportPort.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        IE::SourceIPv4Address => self.sourceIPv4Address.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        IE::DestinationTransportPort => self.destinationTransportPort.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        IE::DestinationIPv4Address => self.destinationIPv4Address.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        IE::SourceIPv6Address => self.sourceIPv6Address.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        IE::DestinationIPv6Address => self.destinationIPv6Address.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        IE::ForwardingStatus => self.forwardingStatus.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        IE::MinimumTTL => self.minimumTTL.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        IE::MaximumTTL => self.maximumTTL.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
    }
  }

  /// Copy the field from the incoming message at the selected idx in the Vec
  /// If None, the Vec<Fields> will be initialized with default values first
  fn field_set(&mut self, ie: &IE, idx: &usize, incoming: &Fields) {
      match ie {
                IE::VMWare(vmware_ie) => {
                    if self.vmware.is_none() {
                        self.vmware = Some(VMWare_Fields::default());
                    }
                    if let Some(vmware_fields) = self.vmware.as_mut() {
                        if let Some(vmware_incoming_fields) = &incoming.vmware {
                            vmware_fields.field_set(vmware_ie, idx, vmware_incoming_fields);
                        }
                    }
                }
                IE::OctetDeltaCount => {
                    set_u64_vec(&mut self.octetDeltaCount, &incoming.octetDeltaCount, idx);
                }
                IE::PacketsDeltaCount => {
                    set_u64_vec(&mut self.packetsDeltaCount, &incoming.packetsDeltaCount, idx);
                }
                IE::ProtocolIdentifier => {
                    set_protocolidentifier_vec(&mut self.protocolIdentifier, &incoming.protocolIdentifier, idx);
                }
                IE::TCPHeaderFlags => {
                    set_tcpheaderflags_vec(&mut self.tcpControlBits, &incoming.tcpControlBits, idx);
                }
                IE::SourceTransportPort => {
                    set_u16_vec(&mut self.sourceTransportPort, &incoming.sourceTransportPort, idx);
                }
                IE::SourceIPv4Address => {
                    set_ipv4address_vec(&mut self.sourceIPv4Address, &incoming.sourceIPv4Address, idx);
                }
                IE::DestinationTransportPort => {
                    set_u16_vec(&mut self.destinationTransportPort, &incoming.destinationTransportPort, idx);
                }
                IE::DestinationIPv4Address => {
                    set_ipv4address_vec(&mut self.destinationIPv4Address, &incoming.destinationIPv4Address, idx);
                }
                IE::SourceIPv6Address => {
                    set_ipv6address_vec(&mut self.sourceIPv6Address, &incoming.sourceIPv6Address, idx);
                }
                IE::DestinationIPv6Address => {
                    set_ipv6address_vec(&mut self.destinationIPv6Address, &incoming.destinationIPv6Address, idx);
                }
                IE::ForwardingStatus => {
                    set_forwardingstatus_vec(&mut self.forwardingStatus, &incoming.forwardingStatus, idx);
                }
                IE::MinimumTTL => {
                    set_u8_vec(&mut self.minimumTTL, &incoming.minimumTTL, idx);
                }
                IE::MaximumTTL => {
                    set_u8_vec(&mut self.maximumTTL, &incoming.maximumTTL, idx);
                }
      }
  }

  fn field_addup(&mut self, ie: &IE, idx: &usize, incoming: &Fields) {
      match ie {
          IE::OctetDeltaCount => {
              addup_u64_vec(&mut self.octetDeltaCount, &incoming.octetDeltaCount, idx);
          }
          IE::PacketsDeltaCount => {
              addup_u64_vec(&mut self.packetsDeltaCount, &incoming.packetsDeltaCount, idx);
          }
          _ => (),
      }
  }

  fn field_minup(&mut self, ie: &IE, idx: &usize, incoming: &Fields) {
    match ie {
        IE::MinimumTTL => {
            minup_u8_vec(&mut self.minimumTTL, &incoming.minimumTTL, idx);
        }
        _ => (),
    }
  }

  fn field_maxup(&mut self, ie: &IE, idx: &usize, incoming: &Fields) {
      match ie {
          IE::MaximumTTL => {
              maxup_u8_vec(&mut self.maximumTTL, &incoming.maximumTTL, idx);
          }
          _ => (),
      }
  }

  fn field_bmoup(&mut self, ie: &IE, idx: &usize, incoming: &Fields) {
    match ie {
        IE::TCPHeaderFlags => {
            bmoup_tcpheaderflags_vec(&mut self.tcpControlBits, &incoming.tcpControlBits, idx);
        }
        _ => (),
    }
  }
}



#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[derive(Eq, Hash, Clone, PartialEq, Debug)]
pub struct VMWare_Fields {
        pub tenantProtocol: Option<Vec<protocolIdentifier>>,
        pub tenantSourceIPv4: Option<Vec<std::net::Ipv4Addr>>,
        pub tenantDestIPv4: Option<Vec<std::net::Ipv4Addr>>,
        pub tenantSourceIPv6: Option<Vec<std::net::Ipv6Addr>>,
        pub tenantDestIPv6: Option<Vec<std::net::Ipv6Addr>>,
        pub tenantSourcePort: Option<Vec<u16>>,
        pub tenantDestPort: Option<Vec<u16>>,
}

impl Default for VMWare_Fields {
  fn default() -> Self {
      Self {
          tenantProtocol: None,
          tenantSourceIPv4: None,
          tenantDestIPv4: None,
          tenantSourceIPv6: None,
          tenantDestIPv6: None,
          tenantSourcePort: None,
          tenantDestPort: None,
      }
  }
}

impl VMWare_Fields {

  fn field_extract_as_key_str(&self, ie: &VMWare_IE, idx: &usize) -> String {
    match ie {
        VMWare_IE::TenantProtocol => self.tenantProtocol.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        VMWare_IE::TenantSourceIPv4 => self.tenantSourceIPv4.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        VMWare_IE::TenantDestIPv4 => self.tenantDestIPv4.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        VMWare_IE::TenantSourceIPv6 => self.tenantSourceIPv6.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        VMWare_IE::TenantDestIPv6 => self.tenantDestIPv6.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        VMWare_IE::TenantSourcePort => self.tenantSourcePort.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
        VMWare_IE::TenantDestPort => self.tenantDestPort.as_ref()
            .and_then(|v| v.get(*idx).map(|s| s.to_string()))
            .unwrap_or_else(|| "None".to_string()),
    }
  }

  fn field_set(&mut self, ie: &VMWare_IE, idx: &usize, incoming: &VMWare_Fields) {
      match ie {
          VMWare_IE::TenantProtocol => {
              set_protocolidentifier_vec(&mut self.tenantProtocol, &incoming.tenantProtocol, idx);
          }
          VMWare_IE::TenantSourceIPv4 => {
              set_ipv4address_vec(&mut self.tenantSourceIPv4, &incoming.tenantSourceIPv4, idx);
          }
          VMWare_IE::TenantDestIPv4 => {
              set_ipv4address_vec(&mut self.tenantDestIPv4, &incoming.tenantDestIPv4, idx);
          }
          VMWare_IE::TenantSourceIPv6 => {
              set_ipv6address_vec(&mut self.tenantSourceIPv6, &incoming.tenantSourceIPv6, idx);
          }
          VMWare_IE::TenantDestIPv6 => {
              set_ipv6address_vec(&mut self.tenantDestIPv6, &incoming.tenantDestIPv6, idx);
          }
          VMWare_IE::TenantSourcePort => {
              set_u16_vec(&mut self.tenantSourcePort, &incoming.tenantSourcePort, idx);
          }
          VMWare_IE::TenantDestPort => {
              set_u16_vec(&mut self.tenantDestPort, &incoming.tenantDestPort, idx);
          }
      }
  }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::FromRepr, strum_macros::Display, Copy, Eq, Hash, Clone, PartialEq, Debug)]
#[repr(u8)]
pub enum protocolIdentifier {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    Unassigned(u8),
}

impl Default for protocolIdentifier {
    fn default() -> Self {
        Self::Unassigned(255)
    }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Hash, Clone, PartialEq, Debug)]
#[repr(u32)]
pub enum forwardingStatus {
    Unknown(UnknownReason),
    Forward(ForwardReason),
    Dropped(DroppedReason),
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Hash, Clone, PartialEq, Debug)]
#[repr(u32)]
pub enum UnknownReason {
    Unassigned(u32),
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Hash, Clone, PartialEq, Debug)]
#[repr(u32)]
pub enum ForwardReason {
    ForwardReasonUnknown,
    ForwardReasonFragmented,
    ForwardReasonNotFragmented,
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Hash, Clone, PartialEq, Debug)]
#[repr(u32)]
pub enum DroppedReason {
    DropReasonUnknown,
    DropReasonACLdeny,
    DropReasonACLdrop,
    DropReasonUnroutable,
}

impl Default for forwardingStatus {
    fn default() -> Self {
        forwardingStatus::Unknown(UnknownReason::Unassigned(0))
    }
}

impl Display for forwardingStatus {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                    forwardingStatus::Unknown(UnknownReason::Unassigned(_)) => write!(f, "UnknownReasonUnassigned"),
                    forwardingStatus::Forward(ForwardReason::ForwardReasonUnknown) => write!(f, "ForwardReasonUnknown"),
                    forwardingStatus::Forward(ForwardReason::ForwardReasonFragmented) => write!(f, "ForwardReasonFragmented"),
                    forwardingStatus::Forward(ForwardReason::ForwardReasonNotFragmented) => write!(f, "ForwardReasonNotFragmented"),
                    forwardingStatus::Dropped(DroppedReason::DropReasonUnknown) => write!(f, "DropReasonUnknown"),
                    forwardingStatus::Dropped(DroppedReason::DropReasonACLdeny) => write!(f, "DropReasonACLdeny"),
                    forwardingStatus::Dropped(DroppedReason::DropReasonACLdrop) => write!(f, "DropReasonACLdrop"),
                    forwardingStatus::Dropped(DroppedReason::DropReasonUnroutable) => write!(f, "DropReasonUnroutable"),
            }
        }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum AggrOp {
    Key,
    Add,
    Min,
    Max,
    BoolMapOr,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InputMessage {
    pub ts: DateTime<Utc>, //use chrono::DateTime<Utc> instead but for output we need string
    pub peer_src: String,
    pub writer_id: String,
    pub payload: FlatFlowInfo,
}

impl TimeSeriesData<String> for InputMessage {
  fn get_key(&self) -> String {
      self.peer_src.clone()
  }

  fn get_ts(&self) -> chrono::DateTime<chrono::Utc> {
      self.ts
  }
}

impl TimeSeriesData<String> for &InputMessage {
  fn get_key(&self) -> String {
      self.peer_src.clone()
  }

  fn get_ts(&self) -> chrono::DateTime<chrono::Utc> {
      self.ts
  }
}

impl Default for InputMessage {
    // Also here cascade the defaulting to the other structs....
    fn default() -> Self {
        Self {
                ts: chrono::DateTime::from_timestamp_millis(0).unwrap().to_utc(),
                peer_src: String::new(),
                writer_id: String::new(),
                payload: FlatFlowInfo::IPFIX(FlatIpfixPacket {
                        export_time: chrono::DateTime::from_timestamp_millis(0).unwrap().to_utc(),
                        sequence_number: 0,
                        observation_domain_id: 0,
                        set: FlatSet::Data {
                        id: 0,
                        record: Box::new(FlatDataRecord { fields: Fields::default() }),
                        },
                }),
        }
    }
}

impl InputMessage {

    /// Extract field for the relevant IE as a string to be used as key
    fn field_extract_as_key_str(&self, ie: &IE, idx: &usize) -> String {
        self.payload.field_extract_as_key_str(ie, idx)
    }

    /// Sets field for the relevant ie from incoming message
    fn field_set(&mut self, ie: &IE, idx: &usize, incoming: &InputMessage) {
        self.payload.field_set(ie, idx, &incoming.payload)
    }

    fn field_addup(&mut self, ie: &IE, idx: &usize, incoming: &InputMessage) {
        self.payload.field_addup(ie, idx, &incoming.payload)
    }

    fn field_minup(&mut self, ie: &IE, idx: &usize, incoming: &InputMessage) {
        self.payload.field_minup(ie, idx, &incoming.payload)
    }

    fn field_maxup(&mut self, ie: &IE, idx: &usize, incoming: &InputMessage) {
        self.payload.field_maxup(ie, idx, &incoming.payload)
    }

    fn field_bmoup(&mut self, ie: &IE, idx: &usize, incoming: &InputMessage) {
        self.payload.field_bmoup(ie, idx, &incoming.payload)
    }

    // TODO: implement check on allowed Transforms then remove result return here...
    pub fn reduce(&mut self, incoming: &InputMessage, ie: &IE, idx: &usize, op: &AggrOp) -> Result<(), String> {
        match op {
            AggrOp::Key => {
                self.field_set(ie, idx, incoming);
                Ok(())
            }
            AggrOp::Add => {
                self.field_addup(ie, idx, incoming);
                Ok(())
            }
            AggrOp::Min => {
                self.field_minup(ie, idx, incoming);
                Ok(())
            }
            AggrOp::Max => {
                self.field_maxup(ie, idx, incoming);
                Ok(())
            }
            AggrOp::BoolMapOr => {
                self.field_bmoup(ie, idx, incoming);
                Ok(())
            }
        }
    }
}


// TODO: make it a hash map or hash set to avoid duplicated operations for the same field
// TODO: make sure impossible operations don't apply so we can remove the Result<> from the reduce function
// TODO: figure out if here we want to allow also for aggregation possibility of non-IE fields (e.g. fields in the FlatIpfixPacket header
//       --> alternative would be hardcoding a default behaviour like for peer_src, writer_id, ... )
// TODO: idx behaviour: discuss if we want to allow for multiple idxs aggregation
//       --> not supported at the moment (only one idx per IE&Aggr op, discuss if support or prevent it to be configured...)
#[derive(Clone, PartialEq, Debug)]
pub struct Transform {
    pub ie: IE,
    pub idx: usize,
    pub op: AggrOp,
}

#[derive(Clone, Debug, Default)]
pub struct FieldsAggregation {
    pub values: HashMap<String, InputMessage>,
    pub ops: Vec<Transform>,
}

impl Aggregator<HashMap<String, InputMessage>, InputMessage, HashMap<String, InputMessage>> for FieldsAggregation {
  fn init(init: HashMap<String, InputMessage>) -> Self {
      Self {
          values: init,
          ops: vec![
                  Transform {ie: IE::VMWare(VMWare_IE::TenantProtocol), idx: 0, op: AggrOp::Key},
                  Transform {ie: IE::ProtocolIdentifier, idx: 0, op: AggrOp::Key},
                  Transform {ie: IE::SourceIPv4Address, idx: 0, op: AggrOp::Key},
                  // Transform {ie: IE::DestinationIPv4Address, idx: 0, op: AggrOp::Key},
                  // Transform {ie: IE::DestinationIPv4Address, idx: 1, op: AggrOp::Key},
                  Transform {ie: IE::ForwardingStatus, idx: 0, op: AggrOp::Key},
                  Transform {ie: IE::OctetDeltaCount, idx: 0, op: AggrOp::Add},
                  // Transform {ie: IE::OctetDeltaCount, idx: 1, op: AggrOp::Add},
                  Transform {ie: IE::PacketsDeltaCount, idx: 0, op: AggrOp::Add},
                  Transform {ie: IE::TCPHeaderFlags, idx: 0, op: AggrOp::BoolMapOr},
                  Transform {ie: IE::MinimumTTL, idx: 0, op: AggrOp::Min},
                  Transform {ie: IE::MaximumTTL, idx: 0, op: AggrOp::Max},
                  Transform {ie: IE::SourceIPv6Address, idx: 0, op: AggrOp::Key},
                  Transform {ie: IE::DestinationIPv6Address, idx: 0, op: AggrOp::Key},
          ],
      }
  }

  fn push(&mut self, item: InputMessage) {
      let mut key = item.get_key();
      // Compute the "group by" keys
      for transform in self.ops.iter() {
          if let AggrOp::Key = transform.op {
              key.push_str(",");
              key.push_str(&item.field_extract_as_key_str(&transform.ie, &transform.idx));
          }
      }
      let accumulator = self.values
          .entry(key.clone())
          .or_insert(InputMessage {
              ts: item.ts,
              peer_src: item.peer_src.clone(),
              writer_id: item.writer_id.clone(),
              ..Default::default()
          });

      for transform in self.ops.iter() {
          accumulator.reduce(&item, &transform.ie, &transform.idx, &transform.op).unwrap();
      }
  }

  fn flush(self) -> HashMap<String, InputMessage> {
      self.values
  }
}

fn main() {
    let base_time = chrono::DateTime::from_timestamp_millis(1738671600000).unwrap();
    let inputs = vec![
        InputMessage {
            ts: base_time,
            peer_src: "router1".to_string(),
            writer_id: "writer1".to_string(),
            payload: FlatFlowInfo::IPFIX(FlatIpfixPacket {
                export_time: base_time,
                sequence_number: 1,
                observation_domain_id: 1,
                set: FlatSet::Data {
                    id: 256,
                    record: Box::new(FlatDataRecord {
                        fields: Fields {
                            vmware: Some(VMWare_Fields {
                                        tenantProtocol: Some(vec![protocolIdentifier::TCP]),
                                        tenantSourceIPv4: Some(vec![std::net::Ipv4Addr::new(192, 168, 1, 1)]),
                                        tenantDestIPv4: Some(vec![std::net::Ipv4Addr::new(192, 168, 1, 2)]),
                                        tenantSourceIPv6: None,
                                        tenantDestIPv6: None,
                                        tenantSourcePort: Some(vec![10000]),
                                        tenantDestPort: Some(vec![80]),
                                        }
                                    ),
                            octetDeltaCount: Some(vec![100]),
                            packetsDeltaCount: Some(vec![1]),
                            protocolIdentifier: Some(vec![protocolIdentifier::TCP]),
                            tcpControlBits: Some(vec![TCPHeaderFlags::new(true, false, false, false, false, false, false, false)]),
                            sourceTransportPort: Some(vec![10000]),
                            sourceIPv4Address: Some(vec![std::net::Ipv4Addr::new(192, 168, 1, 1)]),
                            destinationTransportPort: Some(vec![80]),
                            destinationIPv4Address: Some(vec![std::net::Ipv4Addr::new(192, 168, 1, 2)]),
                            sourceIPv6Address: None,
                            destinationIPv6Address: None,
                            forwardingStatus: Some(vec![forwardingStatus::Forward(ForwardReason::ForwardReasonUnknown)]),
                            maximumTTL: Some(vec![64]),
                            minimumTTL: Some(vec![5]),
                        },
                    }),
                },
                }),
        },
        InputMessage {
          ts: base_time.add(Duration::from_secs(30)),
          peer_src: "router1".to_string(),
          writer_id: "writer1".to_string(),
          payload: FlatFlowInfo::IPFIX(FlatIpfixPacket {
              export_time: base_time,
              sequence_number: 1,
              observation_domain_id: 1,
              set: FlatSet::Data {
                  id: 256,
                  record: Box::new(FlatDataRecord {
                      fields: Fields {
                          vmware: Some(VMWare_Fields {
                                  tenantProtocol: Some(vec![protocolIdentifier::UDP]),
                                  tenantSourceIPv4: Some(vec![std::net::Ipv4Addr::new(192, 168, 1, 1)]),
                                  tenantDestIPv4: Some(vec![std::net::Ipv4Addr::new(192, 168, 1, 2)]),
                                  tenantSourceIPv6: None,
                                  tenantDestIPv6: None,
                                  tenantSourcePort: Some(vec![10000]),
                                  tenantDestPort: Some(vec![80]),
                                  }
                              ),
                          octetDeltaCount: Some(vec![100, 200, 200]),
                          packetsDeltaCount: Some(vec![1]),
                          protocolIdentifier: Some(vec![protocolIdentifier::TCP]),
                          tcpControlBits: Some(vec![TCPHeaderFlags::new(false, true, false, false, false, false, false, false)]),
                          sourceTransportPort: Some(vec![10000]),
                          sourceIPv4Address: Some(vec![std::net::Ipv4Addr::new(192, 168, 1, 1), std::net::Ipv4Addr::new(10, 0, 0, 1)]),
                          destinationTransportPort: Some(vec![80]),
                          destinationIPv4Address: Some(vec![std::net::Ipv4Addr::new(192, 168, 1, 2), std::net::Ipv4Addr::new(10, 0, 0, 2)]),
                          sourceIPv6Address: None,
                          destinationIPv6Address: None,
                          forwardingStatus: Some(vec![forwardingStatus::Forward(ForwardReason::ForwardReasonUnknown)]),
                          maximumTTL: Some(vec![65]),
                          minimumTTL: Some(vec![1]),
                      },
                  }),
              },
              }),
      },
      InputMessage {
        ts: base_time.add(Duration::from_secs(45)),
        peer_src: "router1".to_string(),
        writer_id: "writer1".to_string(),
        payload: FlatFlowInfo::IPFIX(FlatIpfixPacket {
            export_time: base_time,
            sequence_number: 1,
            observation_domain_id: 1,
            set: FlatSet::Data {
                id: 256,
                record: Box::new(FlatDataRecord {
                    fields: Fields {
                        vmware: Some(VMWare_Fields {
                                tenantProtocol: Some(vec![protocolIdentifier::UDP]),
                                tenantSourceIPv4: Some(vec![std::net::Ipv4Addr::new(192, 168, 1, 1)]),
                                tenantDestIPv4: Some(vec![std::net::Ipv4Addr::new(192, 168, 1, 2)]),
                                tenantSourceIPv6: None,
                                tenantDestIPv6: None,
                                tenantSourcePort: Some(vec![10000]),
                                tenantDestPort: Some(vec![80]),
                                }
                            ),
                        octetDeltaCount: Some(vec![100, 200, 300, 400]),
                        packetsDeltaCount: Some(vec![1]),
                        protocolIdentifier: Some(vec![protocolIdentifier::TCP]),
                        tcpControlBits: Some(vec![TCPHeaderFlags::new(false, false, true, false, false, false, false, false)]),
                        sourceTransportPort: Some(vec![10000]),
                        sourceIPv4Address: Some(vec![std::net::Ipv4Addr::new(192, 168, 1, 1)]),
                        destinationTransportPort: Some(vec![80]),
                        destinationIPv4Address: Some(vec![std::net::Ipv4Addr::new(192, 168, 1, 2)]),
                        sourceIPv6Address: None,
                        destinationIPv6Address: None,
                        forwardingStatus: Some(vec![forwardingStatus::Forward(ForwardReason::ForwardReasonUnknown)]),
                        maximumTTL: Some(vec![66]),
                        minimumTTL: Some(vec![4]),
                    },
                }),
            },
            }),
      },
      InputMessage {
        ts: base_time.add(Duration::from_secs(90)),
        peer_src: "router1".to_string(),
        writer_id: "writer1".to_string(),
        payload: FlatFlowInfo::IPFIX(FlatIpfixPacket {
            export_time: base_time,
            sequence_number: 1,
            observation_domain_id: 1,
            set: FlatSet::Data {
                id: 256,
                record: Box::new(FlatDataRecord {
                    fields: Fields {
                        vmware: Some(VMWare_Fields {
                                tenantProtocol: Some(vec![protocolIdentifier::TCP]),
                                tenantSourceIPv4: Some(vec![std::net::Ipv4Addr::new(192, 168, 1, 1)]),
                                tenantDestIPv4: Some(vec![std::net::Ipv4Addr::new(192, 168, 1, 2)]),
                                tenantSourceIPv6: None,
                                tenantDestIPv6: None,
                                tenantSourcePort: Some(vec![10000]),
                                tenantDestPort: Some(vec![80]),
                                }
                            ),
                        octetDeltaCount: Some(vec![100]),
                        packetsDeltaCount: Some(vec![1]),
                        protocolIdentifier: Some(vec![protocolIdentifier::TCP]),
                        tcpControlBits: Some(vec![TCPHeaderFlags::new(false, false, false, true, false, false, false, false)]),
                        sourceTransportPort: Some(vec![10000]),
                        sourceIPv4Address: Some(vec![std::net::Ipv4Addr::new(192, 168, 1, 1)]),
                        destinationTransportPort: Some(vec![80]),
                        destinationIPv4Address: Some(vec![std::net::Ipv4Addr::new(192, 168, 1, 2)]),
                        sourceIPv6Address: None,
                        destinationIPv6Address: None,
                        forwardingStatus: Some(vec![forwardingStatus::Dropped(DroppedReason::DropReasonACLdrop)]),
                        maximumTTL: Some(vec![67]),
                        minimumTTL: Some(vec![3]),
                    },
                }),
            },
            }),
    },
    ];

    let results_with_late: Vec<_> = inputs
      .into_iter()
      .window_aggregate(
          Duration::from_secs(60),
          Duration::from_secs(10),
          HashMap::default(),
          FieldsAggregation::init(HashMap::default()),
        )
      .collect();

      for result in results_with_late {
        match result {
          either::Left(data) => {
            let ((window_start, window_end), hashmap) = data;
            for (key, value) in hashmap {
                println!("\n[{}, {}]: {} -> {:?}\n", window_start, window_end, key, value);
            }
          }
          // either::Right(late_data) => println!("\n******* We have some late data (discarded) - {:?} ********\n", late_data),
          either::Right(_late_data) => println!("\n******* We have some late data (discarded) ********\n"),
        }
      }

}

// Helper functions
#[inline]
fn set_u8_vec(lhs: &mut Option<Vec<u8>>, rhs: &Option<Vec<u8>>, idx: &usize) {

  //Previous implementation without idx (clone the whole option)
  //lhs = rhs.clone();

  if let Some(value) = rhs.as_ref().and_then(|v| v.get(*idx).copied()) {
    let octet_delta_count = lhs.get_or_insert_with(|| vec![u8::default(); *idx + 1]);

    // Resize if necessary
    if octet_delta_count.len() <= *idx {
            octet_delta_count.resize(*idx + 1, 0);
    }

    octet_delta_count[*idx] = value;
  }
}

#[inline]
fn set_u16_vec(lhs: &mut Option<Vec<u16>>, rhs: &Option<Vec<u16>>, idx: &usize) {

  //Previous implementation without idx (clone the whole option)
  //lhs = rhs.clone();

  if let Some(value) = rhs.as_ref().and_then(|v| v.get(*idx).copied()) {
    let octet_delta_count = lhs.get_or_insert_with(|| vec![u16::default(); *idx + 1]);

    // Resize if necessary
    if octet_delta_count.len() <= *idx {
            octet_delta_count.resize(*idx + 1, 0);
    }

    octet_delta_count[*idx] = value;
  }
}

#[inline]
fn set_u64_vec(lhs: &mut Option<Vec<u64>>, rhs: &Option<Vec<u64>>, idx: &usize) {

  //Previous implementation without idx (clone the whole option)
  //lhs = rhs.clone();

  if let Some(value) = rhs.as_ref().and_then(|v| v.get(*idx).copied()) {
    let octet_delta_count = lhs.get_or_insert_with(|| vec![u64::default(); *idx + 1]);

    // Resize if necessary
    if octet_delta_count.len() <= *idx {
            octet_delta_count.resize(*idx + 1, 0);
    }

    octet_delta_count[*idx] = value;
  }
}

#[inline]
fn set_protocolidentifier_vec(lhs: &mut Option<Vec<protocolIdentifier>>, rhs: &Option<Vec<protocolIdentifier>>, idx: &usize) {

  //Previous implementation without idx (clone the whole option)
  //lhs = rhs.clone();

  if let Some(value) = rhs.as_ref().and_then(|v| v.get(*idx).copied()) {
    let octet_delta_count = lhs.get_or_insert_with(|| vec![protocolIdentifier::default(); *idx + 1]);

    // Resize if necessary
    if octet_delta_count.len() <= *idx {
            octet_delta_count.resize(*idx + 1, protocolIdentifier::default());
    }

    octet_delta_count[*idx] = value;
  }
}

#[inline]
fn set_tcpheaderflags_vec(lhs: &mut Option<Vec<netgauze_iana::tcp::TCPHeaderFlags>>, rhs: &Option<Vec<netgauze_iana::tcp::TCPHeaderFlags>>, idx: &usize) {

  //Previous implementation without idx (clone the whole option)
  //lhs = rhs.clone();

  if let Some(value) = rhs.as_ref().and_then(|v| v.get(*idx).copied()) {
    let octet_delta_count = lhs.get_or_insert_with(|| vec![netgauze_iana::tcp::TCPHeaderFlags::default(); *idx + 1]);

    // Resize if necessary
    if octet_delta_count.len() <= *idx {
            octet_delta_count.resize(*idx + 1, netgauze_iana::tcp::TCPHeaderFlags::default());
    }

    octet_delta_count[*idx] = value;
  }
}

#[inline]
fn set_ipv4address_vec(lhs: &mut Option<Vec<std::net::Ipv4Addr>>, rhs: &Option<Vec<std::net::Ipv4Addr>>, idx: &usize) {

  //Previous implementation without idx (clone the whole option)
  //lhs = rhs.clone();

  if let Some(value) = rhs.as_ref().and_then(|v| v.get(*idx).copied()) {
    let octet_delta_count = lhs.get_or_insert_with(|| vec![std::net::Ipv4Addr::new(0, 0, 0, 0); *idx + 1]);

    // Resize if necessary
    if octet_delta_count.len() <= *idx {
            octet_delta_count.resize(*idx + 1, std::net::Ipv4Addr::new(0, 0, 0, 0));
    }

    octet_delta_count[*idx] = value;
  }
}

#[inline]
fn set_ipv6address_vec(lhs: &mut Option<Vec<std::net::Ipv6Addr>>, rhs: &Option<Vec<std::net::Ipv6Addr>>, idx: &usize) {

  //Previous implementation without idx (clone the whole option)
  //lhs = rhs.clone();

  if let Some(value) = rhs.as_ref().and_then(|v| v.get(*idx).copied()) {
    let octet_delta_count = lhs.get_or_insert_with(|| vec![std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0); *idx + 1]);

    // Resize if necessary
    if octet_delta_count.len() <= *idx {
            octet_delta_count.resize(*idx + 1, std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
    }

    octet_delta_count[*idx] = value;
  }
}

#[inline]
fn set_forwardingstatus_vec(lhs: &mut Option<Vec<forwardingStatus>>, rhs: &Option<Vec<forwardingStatus>>, idx: &usize) {

  //Previous implementation without idx (clone the whole option)
  //lhs = rhs.clone();

  if let Some(value) = rhs.as_ref().and_then(|v| v.get(*idx).copied()) {
    let octet_delta_count = lhs.get_or_insert_with(|| vec![forwardingStatus::default(); *idx + 1]);

    // Resize if necessary
    if octet_delta_count.len() <= *idx {
            octet_delta_count.resize(*idx + 1, forwardingStatus::default());
    }

    octet_delta_count[*idx] = value;
  }
}

/// Sums up two vectors of u64s, adding the values of the rhs vector to the lhs vector.
/// If the rhs vector is longer, just append the additional elements to the lhs vector.
#[inline]
fn addup_u64_vec(lhs: &mut Option<Vec<u64>>, rhs: &Option<Vec<u64>>, idx: &usize) {

    if let Some(lhs) = lhs {
        if let Some(rhs) = rhs {
            if let (Some(a), Some(b)) = (lhs.get_mut(*idx), rhs.get(*idx)) {
                *a += *b;
            }
        }
    }
    else {
        set_u64_vec(lhs, rhs, idx);
    }
}

// Previous logic
// fn addup_u64_vec(lhs: &mut Vec<u64>, rhs: &Vec<u64>) {
//   lhs.iter_mut().zip(rhs.iter()).for_each(|(a, b)| *a += *b);
//     if rhs.len() > lhs.len() {
//         for i in rhs[lhs.len()..].iter() {
//             lhs.push(*i);
//         }
//     }
// }

/// Sets the values of the lhs u8 vector to the min of the two u8 vectors.
/// If the rhs vector is longer, just append the additional elements to the lhs vector.
#[inline]
fn minup_u8_vec(lhs: &mut Option<Vec<u8>>, rhs: &Option<Vec<u8>>, idx: &usize) {
  if let Some(lhs) = lhs {
    if let Some(rhs) = rhs {
        if let (Some(a), Some(b)) = (lhs.get_mut(*idx), rhs.get(*idx)) {
            *a = std::cmp::min(*a,*b);
        }
      }
    }
    else {
        set_u8_vec(lhs, rhs, idx);
    }
}

/// Sets the values of the lhs u8 vector to the max of the two u8 vectors.
/// If the rhs vector is longer, just append the additional elements to the lhs vector.
#[inline]
fn maxup_u8_vec(lhs: &mut Option<Vec<u8>>, rhs: &Option<Vec<u8>>, idx: &usize) {
  if let Some(lhs) = lhs {
    if let Some(rhs) = rhs {
        if let (Some(a), Some(b)) = (lhs.get_mut(*idx), rhs.get(*idx)) {
            *a = std::cmp::max(*a,*b);
        }
      }
    }
  else {
      set_u8_vec(lhs, rhs, idx);
  }
}

/// Sets the values of the lhs TCPHeaderFlags vector to the element-bitwise-OR of the values of the two TCPHeaderFlags vectors.
/// If the rhs vector is longer, just append the additional elements to the lhs vector.
#[inline]
fn bmoup_tcpheaderflags_vec(lhs: &mut Option<Vec<netgauze_iana::tcp::TCPHeaderFlags>>, rhs: &Option<Vec<netgauze_iana::tcp::TCPHeaderFlags>>, idx: &usize) {
  if let Some(lhs) = lhs {
    if let Some(rhs) = rhs {
        if let (Some(a), Some(b)) = (lhs.get_mut(*idx), rhs.get(*idx)) {
            *a |= *b;
        }
      }
    }
  else {
      set_tcpheaderflags_vec(lhs, rhs, idx);
  }
}
