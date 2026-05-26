use miden_protocol::Word;
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::{Deserializable, Serializable};

pub(crate) fn word(seed: u32) -> Word {
    Word::from([seed, seed + 1, seed + 2, seed + 3])
}

pub(crate) fn tx_id(seed: u32) -> TransactionId {
    TransactionId::read_from_bytes(&word(seed).to_bytes()).unwrap()
}
