use byteorder::WriteBytesExt;
use crate::ie::cisco::*;

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum connectionIdWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for connectionIdWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for connectionIdWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, connectionIdWritingError> for connectionId {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), connectionIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 if usize::from(len) > be_bytes.len() {
                     return Err(connectionIdWritingError::InvalidLength(len));
                 }
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum applicationHttpUriStatisticsWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for applicationHttpUriStatisticsWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for applicationHttpUriStatisticsWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, applicationHttpUriStatisticsWritingError> for applicationHttpUriStatistics {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), applicationHttpUriStatisticsWritingError> {
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
pub enum applicationHttpHostWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for applicationHttpHostWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for applicationHttpHostWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, applicationHttpHostWritingError> for applicationHttpHost {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), applicationHttpHostWritingError> {
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
    connectionIdError(#[from] connectionIdWritingError),
    applicationHttpUriStatisticsError(#[from] applicationHttpUriStatisticsWritingError),
    applicationHttpHostError(#[from] applicationHttpHostWritingError),
}

impl std::fmt::Display for FieldWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::connectionIdError(err) => write!(f, "{err}"),
            Self::applicationHttpUriStatisticsError(err) => write!(f, "{err}"),
            Self::applicationHttpHostError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for FieldWritingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StdIOError(_) => None,
            Self::connectionIdError(err) => Some(err),
            Self::applicationHttpUriStatisticsError(err) => Some(err),
            Self::applicationHttpHostError(err) => Some(err),
        }    }}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, FieldWritingError> for Field {
    const BASE_LENGTH: usize = 0;

    fn len(&self, length: Option<u16>) -> usize {
        match self {
            Self::connectionId(value) => value.len(length),
            Self::applicationHttpUriStatistics(value) => value.len(length),
            Self::applicationHttpHost(value) => value.len(length),
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), FieldWritingError> {
        match self {
           Self::connectionId(value) => value.write(writer, length)?,
           Self::applicationHttpUriStatistics(value) => value.write(writer, length)?,
           Self::applicationHttpHost(value) => value.write(writer, length)?,
        }
        Ok(())
    }
}

