use std::fmt;

use miden_protocol::utils::serde::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};

pub const PRIVATE_TX_VERSION: u16 = 1;

macro_rules! string_id {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
                let value = value.into();
                if value.is_empty() {
                    return Err(IdentifierError::Empty($label));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl Serializable for $name {
            fn write_into<W: ByteWriter>(&self, target: &mut W) {
                self.0.write_into(target);
            }

            fn get_size_hint(&self) -> usize {
                self.0.get_size_hint()
            }
        }

        impl Deserializable for $name {
            fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
                let value = String::read_from(source)?;
                Self::new(value).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
            }

            fn min_serialized_size() -> usize {
                String::min_serialized_size()
            }
        }
    };
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum IdentifierError {
    #[error("{0} cannot be empty")]
    Empty(&'static str),
}

string_id!(ChainId, "chain id");
string_id!(ValidatorId, "validator id");
string_id!(ViewingPartyId, "viewing party id");

macro_rules! scheme_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u16);

        impl $name {
            pub const fn new(value: u16) -> Self {
                Self(value)
            }

            pub const fn as_u16(self) -> u16 {
                self.0
            }
        }

        impl Serializable for $name {
            fn write_into<W: ByteWriter>(&self, target: &mut W) {
                target.write_u16(self.0);
            }

            fn get_size_hint(&self) -> usize {
                core::mem::size_of::<u16>()
            }
        }

        impl Deserializable for $name {
            fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
                source.read::<u16>().map(Self)
            }

            fn min_serialized_size() -> usize {
                core::mem::size_of::<u16>()
            }
        }
    };
}

scheme_id!(EncryptionSchemeId);
scheme_id!(ThresholdSchemeId);
scheme_id!(TeeSchemeId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_ids_reject_empty_values() {
        assert_eq!(ChainId::new("").unwrap_err(), IdentifierError::Empty("chain id"));
        assert_eq!(ValidatorId::new("").unwrap_err(), IdentifierError::Empty("validator id"));
        assert_eq!(
            ViewingPartyId::new("").unwrap_err(),
            IdentifierError::Empty("viewing party id")
        );
    }

    #[test]
    fn string_ids_roundtrip_through_miden_serialization() {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let bytes = chain_id.to_bytes();
        assert_eq!(ChainId::read_from_bytes(&bytes).unwrap(), chain_id);
    }
}
