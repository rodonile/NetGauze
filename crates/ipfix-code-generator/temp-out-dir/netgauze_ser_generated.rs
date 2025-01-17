use byteorder::WriteBytesExt;
use crate::ie::netgauze::*;

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum timestampArrivalWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for timestampArrivalWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for timestampArrivalWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, timestampArrivalWritingError> for timestampArrival {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), timestampArrivalWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum isRenormalizedWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for isRenormalizedWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for isRenormalizedWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, isRenormalizedWritingError> for isRenormalized {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), isRenormalizedWritingError> {
         writer.write_u8(self.0.into())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum samplingInfoOriginWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for samplingInfoOriginWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for samplingInfoOriginWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, samplingInfoOriginWritingError> for samplingInfoOrigin {
    const BASE_LENGTH: usize = 0;

    fn len(&self, length: Option<u16>) -> usize {
        match length {
            None => self.0.len(),
            Some(len) => if len == u16::MAX {
                if self.0.len() < u8::MAX as usize {
                    // One octet for the length field
                    self.0.len() + 1
                } else {
                    // 4 octets for the length field, first is 255 and other three carries the len
                    self.0.len() + 4
                }
            } else {
                len as usize
            },
        }
    }

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), samplingInfoOriginWritingError> {
        match length {
            Some(u16::MAX) | None => {
                let bytes = self.0.as_bytes();
                if bytes.len() < u8::MAX as usize {
                    writer.write_u8(bytes.len() as u8)?;
                } else {
                    writer.write_u8(u8::MAX)?;
                    writer.write_all(&bytes.len().to_be_bytes()[1..])?;
                }
                writer.write_all(self.0.as_bytes())?;
            }
            Some(len) => {
                writer.write_all(self.0.as_bytes())?;
                // fill the rest with zeros
                for _ in self.0.as_bytes().len()..(len as usize) {
                    writer.write_u8(0)?
                }
            }
        }
        Ok(())
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum FieldWritingError {
    StdIOError(#[from_std_io_error] String),
    timestampArrivalError(#[from] timestampArrivalWritingError),
    isRenormalizedError(#[from] isRenormalizedWritingError),
    samplingInfoOriginError(#[from] samplingInfoOriginWritingError),
}

impl std::fmt::Display for FieldWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::timestampArrivalError(err) => write!(f, "{err}"),
            Self::isRenormalizedError(err) => write!(f, "{err}"),
            Self::samplingInfoOriginError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for FieldWritingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StdIOError(_) => None,
            Self::timestampArrivalError(err) => Some(err),
            Self::isRenormalizedError(err) => Some(err),
            Self::samplingInfoOriginError(err) => Some(err),
        }    }}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, FieldWritingError> for Field {
    const BASE_LENGTH: usize = 0;

    fn len(&self, length: Option<u16>) -> usize {
        match self {
            Self::timestampArrival(value) => value.len(length),
            Self::isRenormalized(value) => value.len(length),
            Self::samplingInfoOrigin(value) => value.len(length),
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), FieldWritingError> {
        match self {
           Self::timestampArrival(value) => value.write(writer, length)?,
           Self::isRenormalized(value) => value.write(writer, length)?,
           Self::samplingInfoOrigin(value) => value.write(writer, length)?,
        }
        Ok(())
    }
}

