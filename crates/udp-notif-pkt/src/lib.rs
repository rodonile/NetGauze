// Copyright (C) 2024-present The NetGauze Authors.
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

#[cfg(feature = "codec")]
pub mod codec;
#[cfg(feature = "serde")]
pub mod wire;
pub mod yang;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, convert::TryFrom};
use strum_macros::Display;

use yang::notification::{Notification, NotificationEnvelope};

const UDP_NOTIF_VERSION: u8 = 1;

#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, Eq, PartialEq, Hash, strum_macros::EnumDiscriminants,
)]
#[strum_discriminants(name(MediaTypeNames))]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum MediaType {
    Reserved,
    YangDataJson,
    YangDataXml,
    YangDataCbor,
    Unknown(u8),
}

impl From<u8> for MediaType {
    fn from(value: u8) -> Self {
        match value {
            0 => MediaType::Reserved,
            1 => MediaType::YangDataJson,
            2 => MediaType::YangDataXml,
            3 => MediaType::YangDataCbor,
            value => MediaType::Unknown(value),
        }
    }
}

impl From<MediaType> for u8 {
    fn from(value: MediaType) -> Self {
        match value {
            MediaType::Reserved => 0,
            MediaType::YangDataJson => 1,
            MediaType::YangDataXml => 2,
            MediaType::YangDataCbor => 3,
            MediaType::Unknown(value) => value,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum UdpNotifOptionCode {
    Segment = 1,
    PrivateEncoding = 2,
    Unknown(u8),
}

impl From<u8> for UdpNotifOptionCode {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Segment,
            2 => Self::PrivateEncoding,
            v => Self::Unknown(v),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum UdpNotifOption {
    Segment { number: u16, last: bool },
    PrivateEncoding(Vec<u8>),
    Unknown { typ: u8, value: Vec<u8> },
}

impl UdpNotifOption {
    pub const fn code(&self) -> UdpNotifOptionCode {
        match self {
            Self::Segment { .. } => UdpNotifOptionCode::Segment,
            Self::PrivateEncoding(_) => UdpNotifOptionCode::PrivateEncoding,
            Self::Unknown { typ, .. } => UdpNotifOptionCode::Unknown(*typ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UdpNotifPacket {
    media_type: MediaType,
    publisher_id: u32,
    message_id: u32,
    options: HashMap<UdpNotifOptionCode, UdpNotifOption>,
    #[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_bytes))]
    payload: Bytes,
}

impl UdpNotifPacket {
    pub const fn new(
        media_type: MediaType,
        publisher_id: u32,
        message_id: u32,
        options: HashMap<UdpNotifOptionCode, UdpNotifOption>,
        payload: Bytes,
    ) -> Self {
        Self {
            media_type,
            publisher_id,
            message_id,
            options,
            payload,
        }
    }

    pub const fn version(&self) -> u8 {
        UDP_NOTIF_VERSION
    }

    pub const fn media_type(&self) -> MediaType {
        self.media_type
    }

    pub const fn publisher_id(&self) -> u32 {
        self.publisher_id
    }

    pub const fn message_id(&self) -> u32 {
        self.message_id
    }

    pub const fn options(&self) -> &HashMap<UdpNotifOptionCode, UdpNotifOption> {
        &self.options
    }

    pub const fn payload(&self) -> &Bytes {
        &self.payload
    }
}

#[cfg(feature = "fuzz")]
pub(crate) fn arbitrary_bytes(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Bytes> {
    let value: Vec<u8> = u.arbitrary()?;
    Ok(Bytes::from(value))
}

// TODO: keep here or move to a separate file?
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct UdpNotifPacketDecoded {
    media_type: MediaType,
    publisher_id: u32,
    message_id: u32,
    options: HashMap<UdpNotifOptionCode, UdpNotifOption>,
    payload: UdpNotifPayload,
}

impl UdpNotifPacketDecoded {
    pub const fn new(
        media_type: MediaType,
        publisher_id: u32,
        message_id: u32,
        options: HashMap<UdpNotifOptionCode, UdpNotifOption>,
        payload: UdpNotifPayload,
    ) -> Self {
        Self {
            media_type,
            publisher_id,
            message_id,
            options,
            payload,
        }
    }
    pub const fn version(&self) -> u8 {
        UDP_NOTIF_VERSION
    }
    pub const fn media_type(&self) -> MediaType {
        self.media_type
    }
    pub const fn publisher_id(&self) -> u32 {
        self.publisher_id
    }
    pub const fn message_id(&self) -> u32 {
        self.message_id
    }
    pub const fn options(&self) -> &HashMap<UdpNotifOptionCode, UdpNotifOption> {
        &self.options
    }
    pub const fn payload(&self) -> &UdpNotifPayload {
        &self.payload
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum UdpNotifPayload {
    //TODO: rename to old version s.t. it's clear this is the deprecated version
    #[serde(rename = "ietf-notification:notification")]
    Notification(Notification),

    #[serde(rename = "ietf-yp-notification:envelope")]
    NotificationEnvelope(NotificationEnvelope),
    // TODO: fix this how to handle unknown payloads (error or forward the message?)
    // --> remove this, if it's unknown we just ignore it and give error...
    // #[serde(other)]
    // Unknown,
    // Unknown(Bytes),
}

#[derive(Debug, Display)]
pub enum UdpNotifPayloadConversionError {
    InvalidPayload,
    UnsupportedMediaType(MediaType),
    JsonError(serde_json::Error),
    CborError(ciborium::de::Error<std::io::Error>),
}

impl From<serde_json::Error> for UdpNotifPayloadConversionError {
    fn from(err: serde_json::Error) -> Self {
        UdpNotifPayloadConversionError::JsonError(err)
    }
}

impl From<ciborium::de::Error<std::io::Error>> for UdpNotifPayloadConversionError {
    fn from(err: ciborium::de::Error<std::io::Error>) -> Self {
        UdpNotifPayloadConversionError::CborError(err)
    }
}

impl TryFrom<&UdpNotifPacket> for UdpNotifPacketDecoded {
    type Error = UdpNotifPayloadConversionError;

    fn try_from(pkt: &UdpNotifPacket) -> Result<Self, UdpNotifPayloadConversionError> {
        let payload: UdpNotifPayload;
        match pkt.media_type() {
            MediaType::YangDataJson => {
                payload = serde_json::from_slice(pkt.payload())?;
            }
            MediaType::YangDataCbor => {
                let val: Value = ciborium::de::from_reader(std::io::Cursor::new(pkt.payload()))?;
                payload = serde_json::from_value(val)?;
            }
            media_type => {
                return Err(UdpNotifPayloadConversionError::UnsupportedMediaType(
                    media_type,
                ));
            }
        }

        Ok(UdpNotifPacketDecoded {
            media_type: pkt.media_type,
            publisher_id: pkt.publisher_id,
            message_id: pkt.message_id,
            options: pkt.options.clone(),
            payload,
        })
    }
}
