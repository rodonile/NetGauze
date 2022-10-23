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

pub mod ie;

use crate::{
    ie::InformationElementTemplate, Field, InformationElementId, InformationElementIdError,
};
use netgauze_parse_utils::{ErrorKindSerdeDeref, ReadablePDU, Span};
use nom::{
    error::ErrorKind,
    number::complete::{be_u16, be_u32},
    IResult,
};

#[allow(non_camel_case_types)]
#[derive(
    netgauze_serde_macros::LocatedError,
    Eq,
    PartialEq,
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum FieldParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InformationElementIdError(InformationElementIdError),
    InvalidLength(u16),
}

impl<'a> ReadablePDU<'a, LocatedFieldParsingError<'a>> for Field {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedFieldParsingError<'a>> {
        let input = buf;
        let (buf, code) = be_u16(buf)?;
        let is_enterprise = code & 0x8000u16 != 0;
        let (buf, length) = be_u16(buf)?;
        let (buf, pen) = if is_enterprise {
            be_u32(buf)?
        } else {
            (buf, 0)
        };
        let ie = match InformationElementId::try_from((pen, code)) {
            Ok(ie) => ie,
            Err(err) => {
                return Err(nom::Err::Error(LocatedFieldParsingError::new(
                    input,
                    FieldParsingError::InformationElementIdError(err),
                )));
            }
        };
        if !ie
            .length_range()
            .as_ref()
            .map(|x| x.contains(&length))
            .unwrap_or(true)
        {
            return Err(nom::Err::Error(LocatedFieldParsingError::new(
                input,
                FieldParsingError::InvalidLength(length),
            )));
        }
        Ok((buf, Field::new(ie, length)))
    }
}
