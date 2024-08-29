#[allow(non_camel_case_types)]
#[repr(u16)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub enum IE {
    /// The absolute timestamp of arrival of this flow record at the NetGauze collector.
    ///
    /// Reference: [https://github.com/NetGauze/NetGauze](https://github.com/NetGauze/NetGauze)
    timestampArrival = 1,
    /// Flag to signal whether octetDeltaCount and packetDeltaCount have been renormalized.
    ///
    /// Reference: [https://github.com/NetGauze/NetGauze](https://github.com/NetGauze/NetGauze)
    isRenormalized = 2,
    /// The value representing the origin where the sampling data is coming from.
    /// Example: flow_record: from Flow Data Record
    /// flow_option: from Option Data Record
    /// map: from static maps
    ///
    /// Reference: [https://github.com/NetGauze/NetGauze](https://github.com/NetGauze/NetGauze)
    samplingInfoOrigin = 3,
}

impl super::InformationElementTemplate for IE {
    fn semantics(&self) -> Option<super::InformationElementSemantics> {
        match self {
            Self::timestampArrival => Some(super::InformationElementSemantics::default),
            Self::isRenormalized => Some(super::InformationElementSemantics::default),
            Self::samplingInfoOrigin => Some(super::InformationElementSemantics::default),
        }
    }

    fn data_type(&self) -> super::InformationElementDataType {
        match self {
            Self::timestampArrival => super::InformationElementDataType::dateTimeSeconds,
            Self::isRenormalized => super::InformationElementDataType::boolean,
            Self::samplingInfoOrigin => super::InformationElementDataType::string,
        }
    }

    fn units(&self) -> Option<super::InformationElementUnits> {
        match self {
            Self::timestampArrival => Some(super::InformationElementUnits::seconds),
            Self::isRenormalized => None,
            Self::samplingInfoOrigin => None,
        }
    }

    fn value_range(&self) -> Option<std::ops::Range<u64>> {
        match self {
            Self::timestampArrival => None,
            Self::isRenormalized => None,
            Self::samplingInfoOrigin => None,
        }
    }

    fn id(&self) -> u16 {
        (*self) as u16
    }

    fn pen(&self) -> u32 {
        3746
    }

}
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct UndefinedIE(pub u16);
impl From<IE> for u16 {
    fn from(value: IE) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for IE {
    type Error = UndefinedIE;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
       // Remove Enterprise bit
       let value = value & 0x7FFF;
       match Self::from_repr(value) {
           Some(val) => Ok(val),
           None => Err(UndefinedIE(value)),
       }
    }
}



#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct timestampArrival(pub chrono::DateTime<chrono::Utc>);

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct isRenormalized(pub bool);

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct samplingInfoOrigin(pub String);

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub enum Field {
    timestampArrival(timestampArrival),
    isRenormalized(isRenormalized),
    samplingInfoOrigin(samplingInfoOrigin),
}
