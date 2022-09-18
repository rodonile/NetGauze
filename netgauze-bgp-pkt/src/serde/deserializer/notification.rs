// Copyright (C) 2022-present The NetGauze Authors.
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

//! Deserializer for BGP Notification message

use crate::{
    iana::{
        BGPErrorNotificationCode, MessageHeaderErrorSubCode, OpenMessageErrorSubCode,
        UndefinedBGPErrorNotificationCode, UndefinedMessageHeaderErrorSubCode,
        UndefinedOpenMessageErrorSubCode, UndefinedUpdateMessageErrorSubCode,
        UpdateMessageErrorSubCode,
    },
    notification::{MessageHeaderError, OpenMessageError, UpdateMessageError},
    serde::deserializer::{BGPMessageParsingError, LocatedBGPMessageParsingError},
    BGPNotificationMessage,
};
use netgauze_parse_utils::{
    parse_into_located, IntoLocatedError, LocatedParsingError, ReadablePDU, Span,
};
use nom::{
    error::{ErrorKind, FromExternalError},
    number::complete::be_u8,
    IResult,
};

/// BGP Notification Message Parsing errors
#[derive(Eq, PartialEq, Clone, Debug)]
pub enum BGPNotificationMessageParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    UndefinedBGPErrorNotificationCode(UndefinedBGPErrorNotificationCode),
    MessageHeaderError(MessageHeaderErrorParsingError),
    OpenMessageError(OpenMessageErrorParsingError),
    UpdateMessageError(UpdateMessageErrorParsingError),
}

/// BGP Notification Message Parsing errors  with the input location of where it
/// occurred in the input byte stream being parsed
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedBGPNotificationMessageParsingError<'a> {
    span: Span<'a>,
    error: BGPNotificationMessageParsingError,
}

impl<'a> LocatedBGPNotificationMessageParsingError<'a> {
    pub const fn new(span: Span<'a>, error: BGPNotificationMessageParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError<'a, BGPNotificationMessageParsingError>
    for LocatedBGPNotificationMessageParsingError<'a>
{
    fn span(&self) -> &Span<'a> {
        &self.span
    }

    fn error(&self) -> &BGPNotificationMessageParsingError {
        &self.error
    }
}

impl<'a> IntoLocatedError<'a, BGPMessageParsingError, LocatedBGPMessageParsingError<'a>>
    for LocatedBGPNotificationMessageParsingError<'a>
{
    fn into_located(self) -> LocatedBGPMessageParsingError<'a> {
        LocatedBGPMessageParsingError::new(
            self.span,
            BGPMessageParsingError::BGPNotificationMessageParsingError(self.error),
        )
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedBGPNotificationMessageParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedBGPNotificationMessageParsingError::new(
            input,
            BGPNotificationMessageParsingError::NomError(kind),
        )
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, BGPNotificationMessageParsingError>
    for LocatedBGPNotificationMessageParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: BGPNotificationMessageParsingError,
    ) -> Self {
        LocatedBGPNotificationMessageParsingError::new(input, error)
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedBGPErrorNotificationCode>
    for LocatedBGPNotificationMessageParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        e: UndefinedBGPErrorNotificationCode,
    ) -> Self {
        LocatedBGPNotificationMessageParsingError::new(
            input,
            BGPNotificationMessageParsingError::UndefinedBGPErrorNotificationCode(e),
        )
    }
}

impl<'a> ReadablePDU<'a, LocatedBGPNotificationMessageParsingError<'a>> for BGPNotificationMessage {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedBGPNotificationMessageParsingError<'a>> {
        let (buf, notification_type) =
            nom::combinator::map_res(be_u8, BGPErrorNotificationCode::try_from)(buf)?;
        match notification_type {
            BGPErrorNotificationCode::MessageHeaderError => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BGPNotificationMessage::MessageHeaderError(value)))
            }
            BGPErrorNotificationCode::OpenMessageError => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BGPNotificationMessage::OpenMessageError(value)))
            }
            BGPErrorNotificationCode::UpdateMessageError => {
                let (buf, value) = parse_into_located(buf)?;
                Ok((buf, BGPNotificationMessage::UpdateMessageError(value)))
            }
            BGPErrorNotificationCode::HoldTimerExpired => todo!(),
            BGPErrorNotificationCode::FiniteStateMachineError => todo!(),
            BGPErrorNotificationCode::Cease => todo!(),
            BGPErrorNotificationCode::RouteRefreshMessageError => todo!(),
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum MessageHeaderErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    UndefinedMessageHeaderErrorType(UndefinedMessageHeaderErrorSubCode),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedMessageHeaderErrorParsingError<'a> {
    span: Span<'a>,
    error: MessageHeaderErrorParsingError,
}

impl<'a> LocatedMessageHeaderErrorParsingError<'a> {
    pub const fn new(span: Span<'a>, error: MessageHeaderErrorParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError<'a, MessageHeaderErrorParsingError>
    for LocatedMessageHeaderErrorParsingError<'a>
{
    fn span(&self) -> &Span<'a> {
        &self.span
    }

    fn error(&self) -> &MessageHeaderErrorParsingError {
        &self.error
    }
}

impl<'a>
    IntoLocatedError<
        'a,
        BGPNotificationMessageParsingError,
        LocatedBGPNotificationMessageParsingError<'a>,
    > for LocatedMessageHeaderErrorParsingError<'a>
{
    fn into_located(self) -> LocatedBGPNotificationMessageParsingError<'a> {
        LocatedBGPNotificationMessageParsingError::new(
            self.span,
            BGPNotificationMessageParsingError::MessageHeaderError(self.error),
        )
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedMessageHeaderErrorParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedMessageHeaderErrorParsingError::new(
            input,
            MessageHeaderErrorParsingError::NomError(kind),
        )
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, MessageHeaderErrorParsingError>
    for LocatedMessageHeaderErrorParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: MessageHeaderErrorParsingError,
    ) -> Self {
        LocatedMessageHeaderErrorParsingError::new(input, error)
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedMessageHeaderErrorSubCode>
    for LocatedMessageHeaderErrorParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        e: UndefinedMessageHeaderErrorSubCode,
    ) -> Self {
        LocatedMessageHeaderErrorParsingError::new(
            input,
            MessageHeaderErrorParsingError::UndefinedMessageHeaderErrorType(e),
        )
    }
}

impl<'a> ReadablePDU<'a, LocatedMessageHeaderErrorParsingError<'a>> for MessageHeaderError {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedMessageHeaderErrorParsingError<'a>> {
        let (buf, sub_code) =
            nom::combinator::map_res(be_u8, MessageHeaderErrorSubCode::try_from)(buf)?;
        let (buf, value) = nom::bytes::complete::take(buf.len())(buf)?;

        match sub_code {
            MessageHeaderErrorSubCode::Unspecific => Ok((
                buf,
                MessageHeaderError::Unspecific {
                    value: (*value.fragment()).into(),
                },
            )),
            MessageHeaderErrorSubCode::ConnectionNotSynchronized => Ok((
                buf,
                MessageHeaderError::ConnectionNotSynchronized {
                    value: (*value.fragment()).into(),
                },
            )),
            MessageHeaderErrorSubCode::BadMessageLength => Ok((
                buf,
                MessageHeaderError::BadMessageLength {
                    value: (*value.fragment()).into(),
                },
            )),
            MessageHeaderErrorSubCode::BadMessageType => Ok((
                buf,
                MessageHeaderError::BadMessageType {
                    value: (*value.fragment()).into(),
                },
            )),
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum OpenMessageErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    UndefinedOpenMessageErrorSubCode(UndefinedOpenMessageErrorSubCode),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedOpenMessageErrorParsingError<'a> {
    span: Span<'a>,
    error: OpenMessageErrorParsingError,
}

impl<'a> LocatedOpenMessageErrorParsingError<'a> {
    pub const fn new(span: Span<'a>, error: OpenMessageErrorParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError<'a, OpenMessageErrorParsingError>
    for LocatedOpenMessageErrorParsingError<'a>
{
    fn span(&self) -> &Span<'a> {
        &self.span
    }

    fn error(&self) -> &OpenMessageErrorParsingError {
        &self.error
    }
}

impl<'a>
    IntoLocatedError<
        'a,
        BGPNotificationMessageParsingError,
        LocatedBGPNotificationMessageParsingError<'a>,
    > for LocatedOpenMessageErrorParsingError<'a>
{
    fn into_located(self) -> LocatedBGPNotificationMessageParsingError<'a> {
        LocatedBGPNotificationMessageParsingError::new(
            self.span,
            BGPNotificationMessageParsingError::OpenMessageError(self.error),
        )
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedOpenMessageErrorParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedOpenMessageErrorParsingError::new(
            input,
            OpenMessageErrorParsingError::NomError(kind),
        )
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, OpenMessageErrorParsingError>
    for LocatedOpenMessageErrorParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: OpenMessageErrorParsingError,
    ) -> Self {
        LocatedOpenMessageErrorParsingError::new(input, error)
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedOpenMessageErrorSubCode>
    for LocatedOpenMessageErrorParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        e: UndefinedOpenMessageErrorSubCode,
    ) -> Self {
        LocatedOpenMessageErrorParsingError::new(
            input,
            OpenMessageErrorParsingError::UndefinedOpenMessageErrorSubCode(e),
        )
    }
}

impl<'a> ReadablePDU<'a, LocatedOpenMessageErrorParsingError<'a>> for OpenMessageError {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedOpenMessageErrorParsingError<'a>> {
        let (buf, sub_code) =
            nom::combinator::map_res(be_u8, OpenMessageErrorSubCode::try_from)(buf)?;
        let (buf, value) = nom::bytes::complete::take(buf.len())(buf)?;

        match sub_code {
            OpenMessageErrorSubCode::Unspecific => Ok((
                buf,
                OpenMessageError::Unspecific {
                    value: (*value.fragment()).into(),
                },
            )),
            OpenMessageErrorSubCode::UnsupportedVersionNumber => Ok((
                buf,
                OpenMessageError::UnsupportedVersionNumber {
                    value: (*value.fragment()).into(),
                },
            )),
            OpenMessageErrorSubCode::BadPeerAS => Ok((
                buf,
                OpenMessageError::BadPeerAS {
                    value: (*value.fragment()).into(),
                },
            )),
            OpenMessageErrorSubCode::BadBGPIdentifier => Ok((
                buf,
                OpenMessageError::BadBGPIdentifier {
                    value: (*value.fragment()).into(),
                },
            )),
            OpenMessageErrorSubCode::UnsupportedOptionalParameter => Ok((
                buf,
                OpenMessageError::UnsupportedOptionalParameter {
                    value: (*value.fragment()).into(),
                },
            )),
            OpenMessageErrorSubCode::UnacceptableHoldTime => Ok((
                buf,
                OpenMessageError::UnacceptableHoldTime {
                    value: (*value.fragment()).into(),
                },
            )),
            OpenMessageErrorSubCode::UnsupportedCapability => Ok((
                buf,
                OpenMessageError::UnsupportedCapability {
                    value: (*value.fragment()).into(),
                },
            )),
            OpenMessageErrorSubCode::RoleMismatch => Ok((
                buf,
                OpenMessageError::RoleMismatch {
                    value: (*value.fragment()).into(),
                },
            )),
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum UpdateMessageErrorParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    NomError(ErrorKind),
    UndefinedUpdateMessageErrorSubCode(UndefinedUpdateMessageErrorSubCode),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LocatedUpdateMessageErrorParsingError<'a> {
    span: Span<'a>,
    error: UpdateMessageErrorParsingError,
}

impl<'a> LocatedUpdateMessageErrorParsingError<'a> {
    pub const fn new(span: Span<'a>, error: UpdateMessageErrorParsingError) -> Self {
        Self { span, error }
    }
}

impl<'a> LocatedParsingError<'a, UpdateMessageErrorParsingError>
    for LocatedUpdateMessageErrorParsingError<'a>
{
    fn span(&self) -> &Span<'a> {
        &self.span
    }

    fn error(&self) -> &UpdateMessageErrorParsingError {
        &self.error
    }
}

impl<'a>
    IntoLocatedError<
        'a,
        BGPNotificationMessageParsingError,
        LocatedBGPNotificationMessageParsingError<'a>,
    > for LocatedUpdateMessageErrorParsingError<'a>
{
    fn into_located(self) -> LocatedBGPNotificationMessageParsingError<'a> {
        LocatedBGPNotificationMessageParsingError::new(
            self.span,
            BGPNotificationMessageParsingError::UpdateMessageError(self.error),
        )
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for LocatedUpdateMessageErrorParsingError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        LocatedUpdateMessageErrorParsingError::new(
            input,
            UpdateMessageErrorParsingError::NomError(kind),
        )
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> FromExternalError<Span<'a>, UpdateMessageErrorParsingError>
    for LocatedUpdateMessageErrorParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        error: UpdateMessageErrorParsingError,
    ) -> Self {
        LocatedUpdateMessageErrorParsingError::new(input, error)
    }
}

impl<'a> FromExternalError<Span<'a>, UndefinedUpdateMessageErrorSubCode>
    for LocatedUpdateMessageErrorParsingError<'a>
{
    fn from_external_error(
        input: Span<'a>,
        _kind: ErrorKind,
        e: UndefinedUpdateMessageErrorSubCode,
    ) -> Self {
        LocatedUpdateMessageErrorParsingError::new(
            input,
            UpdateMessageErrorParsingError::UndefinedUpdateMessageErrorSubCode(e),
        )
    }
}

impl<'a> ReadablePDU<'a, LocatedUpdateMessageErrorParsingError<'a>> for UpdateMessageError {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedUpdateMessageErrorParsingError<'a>> {
        let (buf, sub_code) =
            nom::combinator::map_res(be_u8, UpdateMessageErrorSubCode::try_from)(buf)?;
        let (buf, value) = nom::bytes::complete::take(buf.len())(buf)?;

        match sub_code {
            UpdateMessageErrorSubCode::Unspecific => Ok((
                buf,
                Self::Unspecific {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::MalformedAttributeList => Ok((
                buf,
                Self::MalformedAttributeList {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::UnrecognizedWellKnownAttribute => Ok((
                buf,
                Self::UnrecognizedWellKnownAttribute {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::MissingWellKnownAttribute => Ok((
                buf,
                Self::MissingWellKnownAttribute {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::AttributeFlagsError => Ok((
                buf,
                Self::AttributeFlagsError {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::AttributeLengthError => Ok((
                buf,
                Self::AttributeLengthError {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::InvalidOriginAttribute => Ok((
                buf,
                Self::InvalidOriginAttribute {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::InvalidNextHopAttribute => Ok((
                buf,
                Self::InvalidNextHopAttribute {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::OptionalAttributeError => Ok((
                buf,
                Self::OptionalAttributeError {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::InvalidNetworkField => Ok((
                buf,
                Self::InvalidNetworkField {
                    value: (*value.fragment()).into(),
                },
            )),
            UpdateMessageErrorSubCode::MalformedASPath => Ok((
                buf,
                Self::MalformedASPath {
                    value: (*value.fragment()).into(),
                },
            )),
        }
    }
}
