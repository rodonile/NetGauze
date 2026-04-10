// Copyright (C) 2026-present The NetGauze Authors.
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

use crate::bmp::pmacct_schema::{
    EventType, PmacctBmpConversionError, PmacctBmpMessage, PmacctConversionContext,
};
use crate::publishers::kafka_avro::{AvroConverter, KafkaAvroPublisherActorError};
use apache_avro::AvroSchema;
use apache_avro::types::Value as AvroValue;
use netgauze_bmp_service::BmpRequest;
use schema_registry_converter::avro_common::get_supplied_schema;
use schema_registry_converter::schema_registry_common::SubjectNameStrategy;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SeqStrategy {
    #[default]
    PerPeer,
    Global,
}

fn default_seq_global() -> Arc<AtomicU32> {
    Arc::new(AtomicU32::new(0))
}

// TODO: discuss workaround for having state in the converter...
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BmpAvroConfig {
    #[serde(default)]
    pub seq_strategy: SeqStrategy,

    // The following are runtime-only fields needed for enabling
    // some state in the converter (not part of the YAML config)
    #[serde(skip)]
    pub writer_id: String,

    #[serde(skip)]
    seq_per_peer: HashMap<SocketAddr, u32>,

    #[serde(skip, default = "default_seq_global")]
    seq_global: Arc<AtomicU32>,
}

#[derive(Debug, strum_macros::Display)]
pub enum BmpAvroConverterError {
    ConversionError(PmacctBmpConversionError),
    AvroError(apache_avro::Error),
    #[strum(to_string = "Serialization error: {0}")]
    SerializationError(serde_json::Error),
}

impl std::error::Error for BmpAvroConverterError {}

impl From<PmacctBmpConversionError> for BmpAvroConverterError {
    fn from(e: PmacctBmpConversionError) -> Self {
        Self::ConversionError(e)
    }
}

impl From<apache_avro::Error> for BmpAvroConverterError {
    fn from(e: apache_avro::Error) -> Self {
        Self::AvroError(e)
    }
}

impl From<BmpAvroConverterError> for KafkaAvroPublisherActorError {
    fn from(e: BmpAvroConverterError) -> Self {
        Self::TransformationError(e.to_string())
    }
}

impl From<serde_json::Error> for BmpAvroConverterError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerializationError(e)
    }
}

impl AvroConverter<Arc<BmpRequest>, BmpAvroConverterError> for BmpAvroConfig {
    fn get_avro_schema(&self) -> Result<String, BmpAvroConverterError> {
        serde_json::to_string(&PmacctBmpMessage::get_schema()).map_err(BmpAvroConverterError::from)
    }

    fn get_subject_name_strategy(
        &self,
        topic: &str,
    ) -> Result<SubjectNameStrategy, BmpAvroConverterError> {
        let schema = apache_avro::Schema::parse_str(&self.get_avro_schema()?)
            .map_err(BmpAvroConverterError::from)?;
        Ok(SubjectNameStrategy::TopicNameStrategyWithSchema(
            topic.to_string(),
            false, // is_key = false (this is for the value, not the key)
            get_supplied_schema(&schema),
        ))
    }

    fn get_key(&self, input: &Arc<BmpRequest>) -> Option<JsonValue> {
        let (addr_info, _) = input.as_ref();
        Some(JsonValue::String(
            addr_info.remote_socket().ip().to_string(),
        ))
    }

    type AvroValues = SmallVec<[AvroValue; 16]>; // TODO: check if enough

    fn get_avro_values(
        &mut self,
        input: Arc<BmpRequest>,
    ) -> Result<Self::AvroValues, BmpAvroConverterError> {
        let (addr_info, _) = input.as_ref();
        let peer = addr_info.remote_socket();

        let now = chrono::Utc::now();
        let timestamp = format!("{}.{:06}", now.timestamp(), now.timestamp_subsec_micros());

        // TODO: plan how labels can be fetch based on peer.ip() from sonata here???
        // TODO: plan PI 26-3 --> actor for enrichment sonata for BMP... + architecture redefinement of whole BMP/BGP

        let ctx = PmacctConversionContext {
            writer_id: self.writer_id.clone(),
            event_type: EventType::Log,
            timestamp_arrival: timestamp,
            label: None,
            tag: None,
        };

        // Convert into PmacctBmpMessages
        let msgs = PmacctBmpMessage::try_from_bmp_request(input.as_ref(), &ctx)?;

        // Claim sequence numbers
        let n = msgs.len() as u32;
        let seq_start = match &self.seq_strategy {
            SeqStrategy::PerPeer => {
                let seq = self.seq_per_peer.entry(peer).or_insert(0);
                let start = *seq;
                *seq = seq.wrapping_add(n);
                start
            }
            SeqStrategy::Global => self.seq_global.fetch_add(n, Ordering::Relaxed),
        };

        // Set sequence numbers and get avro value
        msgs.into_iter()
            .enumerate()
            .map(|(i, mut msg)| {
                msg.set_seq(seq_start.wrapping_add(i as u32));
                msg.get_avro_value().map_err(BmpAvroConverterError::from)
            })
            .collect()
    }
}
