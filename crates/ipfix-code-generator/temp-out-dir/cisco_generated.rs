#[allow(non_camel_case_types)]
#[repr(u16)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum IE {
    /// Connection Id.
    ///
    /// Reference: [https://ask.wireshark.org/question/9801/how-to-add-some-field-to-decode-netflow/](https://ask.wireshark.org/question/9801/how-to-add-some-field-to-decode-netflow/)
    connectionId = 12242,
    /// Application Http URI Statistics.
    ///
    /// Reference: [https://ask.wireshark.org/question/9801/how-to-add-some-field-to-decode-netflow/](https://ask.wireshark.org/question/9801/how-to-add-some-field-to-decode-netflow/)
    applicationHttpUriStatistics = 9357,
    /// Application Http Host.
    ///
    /// Reference: [https://ask.wireshark.org/question/9801/how-to-add-some-field-to-decode-netflow/](https://ask.wireshark.org/question/9801/how-to-add-some-field-to-decode-netflow/)
    applicationHttpHost = 12235,
}

impl super::InformationElementTemplate for IE {
    fn semantics(&self) -> Option<super::InformationElementSemantics> {
        match self {
            Self::connectionId => Some(super::InformationElementSemantics::default),
            Self::applicationHttpUriStatistics => Some(super::InformationElementSemantics::default),
            Self::applicationHttpHost => Some(super::InformationElementSemantics::default),
        }
    }

    fn data_type(&self) -> super::InformationElementDataType {
        match self {
            Self::connectionId => super::InformationElementDataType::unsigned32,
            Self::applicationHttpUriStatistics => super::InformationElementDataType::string,
            Self::applicationHttpHost => super::InformationElementDataType::string,
        }
    }

    fn units(&self) -> Option<super::InformationElementUnits> {
        match self {
            Self::connectionId => None,
            Self::applicationHttpUriStatistics => None,
            Self::applicationHttpHost => None,
        }
    }

    fn value_range(&self) -> Option<std::ops::Range<u64>> {
        match self {
            Self::connectionId => None,
            Self::applicationHttpUriStatistics => None,
            Self::applicationHttpHost => None,
        }
    }

    fn id(&self) -> u16 {
        (*self) as u16
    }

    fn pen(&self) -> u32 {
        9
    }

}
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct connectionId(pub u32);

impl crate::HasIE for connectionId {
    fn ie(&self) -> crate::IE {
        crate::IE::Cisco(IE::connectionId)
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct applicationHttpUriStatistics(pub String);

impl crate::HasIE for applicationHttpUriStatistics {
    fn ie(&self) -> crate::IE {
        crate::IE::Cisco(IE::applicationHttpUriStatistics)
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct applicationHttpHost(pub String);

impl crate::HasIE for applicationHttpHost {
    fn ie(&self) -> crate::IE {
        crate::IE::Cisco(IE::applicationHttpHost)
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Field {
    connectionId(connectionId),
    applicationHttpUriStatistics(applicationHttpUriStatistics),
    applicationHttpHost(applicationHttpHost),
}

impl Field {
    /// Get the [IE] element for a given field
    pub const fn ie(&self) -> IE {
        match self {
            Self::connectionId(_) => IE::connectionId,
            Self::applicationHttpUriStatistics(_) => IE::applicationHttpUriStatistics,
            Self::applicationHttpHost(_) => IE::applicationHttpHost,
        }

    }

}

