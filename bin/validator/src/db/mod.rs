mod migrations;
mod models;
mod schema;

use std::num::NonZeroUsize;
use std::path::PathBuf;

use diesel::SqliteConnection;
use diesel::dsl::{count_star, exists};
use diesel::prelude::*;
use miden_node_db::{DatabaseError, Db, SqlTypeConvert};
use miden_node_private_tx::EncryptedPrivateTxRecord;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use tracing::instrument;

use crate::COMPONENT;
use crate::db::migrations::apply_migrations;
use crate::db::models::{
    BlockHeaderRowInsert,
    PrivateTxArchiveRecordRowInsert,
    ValidatedTransactionRowInsert,
};
use crate::tx_validation::ValidatedTransaction;

/// Open a connection to the DB and apply any pending migrations.
#[instrument(target = COMPONENT, skip_all)]
pub async fn load(database_filepath: PathBuf) -> Result<Db, DatabaseError> {
    load_with_pool_size(database_filepath, miden_node_db::default_connection_pool_size()).await
}

/// Open a connection to the DB with a specific pool size and apply any pending migrations.
#[instrument(target = COMPONENT, skip_all)]
pub async fn load_with_pool_size(
    database_filepath: PathBuf,
    connection_pool_size: NonZeroUsize,
) -> Result<Db, DatabaseError> {
    apply_migrations(&database_filepath)?;

    let db = Db::new_with_pool_size(&database_filepath, connection_pool_size)?;
    tracing::info!(
        target: COMPONENT,
        sqlite= %database_filepath.display(),
        connection_pool_size = %connection_pool_size,
        "Connected to the database"
    );
    Ok(db)
}

/// Inserts a new validated transaction into the database.
#[instrument(target = COMPONENT, skip_all, fields(tx_id = %tx_info.tx_id()), err)]
pub(crate) fn insert_transaction(
    conn: &mut SqliteConnection,
    tx_info: &ValidatedTransaction,
) -> Result<usize, DatabaseError> {
    let row = ValidatedTransactionRowInsert::new(tx_info);
    let count = diesel::insert_into(schema::validated_transactions::table)
        .values(row)
        .on_conflict_do_nothing()
        .execute(conn)?;
    Ok(count)
}

/// Inserts an encrypted private transaction archive record.
///
/// Existing records are left unchanged so repeated transaction submission stays idempotent.
#[instrument(target = COMPONENT, skip_all, fields(tx_id = %record.tx_id), err)]
pub(crate) fn insert_private_tx_archive_record(
    conn: &mut SqliteConnection,
    record: &EncryptedPrivateTxRecord,
) -> Result<usize, DatabaseError> {
    let row = PrivateTxArchiveRecordRowInsert::new(record);
    let count = diesel::insert_into(schema::private_tx_archive_records::table)
        .values(row)
        .on_conflict_do_nothing()
        .execute(conn)?;
    Ok(count)
}

/// Loads an encrypted private transaction archive record by transaction id.
#[allow(dead_code)] // Used once the audit fetch path is wired.
#[instrument(target = COMPONENT, skip(conn), fields(tx_id = %tx_id), err)]
pub(crate) fn load_private_tx_archive_record(
    conn: &mut SqliteConnection,
    tx_id: TransactionId,
) -> Result<Option<EncryptedPrivateTxRecord>, DatabaseError> {
    let row = schema::private_tx_archive_records::table
        .filter(schema::private_tx_archive_records::tx_id.eq(tx_id.to_bytes()))
        .select(schema::private_tx_archive_records::record)
        .first::<Vec<u8>>(conn)
        .optional()?;

    row.map(|bytes| {
        EncryptedPrivateTxRecord::read_from_bytes(&bytes)
            .map_err(|err| DatabaseError::deserialization("EncryptedPrivateTxRecord", err))
    })
    .transpose()
}

/// Scans the database for transaction Ids that do not exist.
///
/// If the resulting vector is empty, all supplied transaction ids have been validated in the past.
///
/// # Raw SQL
///
/// ```sql
/// SELECT EXISTS(
///   SELECT 1
///   FROM validated_transactions
///   WHERE id = ?
/// );
/// ```
#[instrument(target = COMPONENT, skip(conn), err)]
pub(crate) fn find_unvalidated_transactions(
    conn: &mut SqliteConnection,
    tx_ids: &[TransactionId],
) -> Result<Vec<TransactionId>, DatabaseError> {
    let mut unvalidated_tx_ids = Vec::new();
    for tx_id in tx_ids {
        // Check whether each transaction id exists in the database.
        let exists = diesel::select(exists(
            schema::validated_transactions::table
                .filter(schema::validated_transactions::id.eq(tx_id.to_bytes())),
        ))
        .get_result::<bool>(conn)?;
        // Record any transaction ids that do not exist.
        if !exists {
            unvalidated_tx_ids.push(*tx_id);
        }
    }
    Ok(unvalidated_tx_ids)
}

/// Upserts a block header into the database.
///
/// Inserts a new row if no block header exists at the given block number, or replaces the
/// existing block header if one already exists.
#[instrument(target = COMPONENT, skip(conn, header), err)]
pub fn upsert_block_header(
    conn: &mut SqliteConnection,
    header: &BlockHeader,
) -> Result<(), DatabaseError> {
    let row = BlockHeaderRowInsert {
        block_num: header.block_num().to_raw_sql(),
        block_header: header.to_bytes(),
    };
    diesel::replace_into(schema::block_headers::table).values(row).execute(conn)?;
    Ok(())
}

/// Loads the chain tip (block header with the highest block number) from the database.
///
/// Returns `None` if no block headers have been persisted (i.e. bootstrap has not been run).
#[instrument(target = COMPONENT, skip(conn), err)]
pub fn load_chain_tip(conn: &mut SqliteConnection) -> Result<Option<BlockHeader>, DatabaseError> {
    let row = schema::block_headers::table
        .order(schema::block_headers::block_num.desc())
        .select(schema::block_headers::block_header)
        .first::<Vec<u8>>(conn)
        .optional()?;

    row.map(|bytes| {
        BlockHeader::read_from_bytes(&bytes)
            .map_err(|err| DatabaseError::deserialization("BlockHeader", err))
    })
    .transpose()
}

/// Loads a block header by its block number.
///
/// Returns `None` if no block header exists at the given block number.
#[instrument(target = COMPONENT, skip(conn), err)]
pub fn load_block_header(
    conn: &mut SqliteConnection,
    block_num: BlockNumber,
) -> Result<Option<BlockHeader>, DatabaseError> {
    let row = schema::block_headers::table
        .filter(schema::block_headers::block_num.eq(block_num.to_raw_sql()))
        .select(schema::block_headers::block_header)
        .first::<Vec<u8>>(conn)
        .optional()?;

    row.map(|bytes| {
        BlockHeader::read_from_bytes(&bytes)
            .map_err(|err| DatabaseError::deserialization("BlockHeader", err))
    })
    .transpose()
}

/// Returns the total number of validated transactions in the database.
#[instrument(target = COMPONENT, skip(conn), err)]
pub fn count_validated_transactions(conn: &mut SqliteConnection) -> Result<i64, DatabaseError> {
    let count = schema::validated_transactions::table.select(count_star()).first::<i64>(conn)?;
    Ok(count)
}

/// Returns the total number of signed blocks in the database.
#[instrument(target = COMPONENT, skip(conn), err)]
pub fn count_signed_blocks(conn: &mut SqliteConnection) -> Result<i64, DatabaseError> {
    let count = schema::block_headers::table.select(count_star()).first::<i64>(conn)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use diesel::Connection;
    use miden_node_private_tx::{
        ChainId,
        DataKeyProtection,
        EncryptedPrivateTxRecord,
        PRIVATE_TX_VERSION,
        ThresholdSchemeId,
        ValidatorId,
        private_tx_record_identity,
    };
    use miden_protocol::Word;
    use miden_protocol::transaction::TransactionId;

    use super::*;

    #[test]
    fn private_tx_archive_record_roundtrips() -> anyhow::Result<()> {
        let (_temp_dir, mut conn) = test_connection()?;
        let record = archive_record(1);

        assert_eq!(insert_private_tx_archive_record(&mut conn, &record)?, 1);
        assert_eq!(
            load_private_tx_archive_record(&mut conn, record.tx_id)?,
            Some(record.clone())
        );
        assert_eq!(insert_private_tx_archive_record(&mut conn, &record)?, 0);
        assert!(load_private_tx_archive_record(&mut conn, tx_id(9))?.is_none());

        Ok(())
    }

    fn test_connection() -> anyhow::Result<(tempfile::TempDir, SqliteConnection)> {
        let temp_dir = tempfile::tempdir()?;
        let database_filepath = temp_dir.path().join("validator.sqlite3");
        apply_migrations(&database_filepath)?;
        let conn = SqliteConnection::establish(database_filepath.to_str().unwrap())?;
        Ok((temp_dir, conn))
    }

    fn archive_record(seed: u32) -> EncryptedPrivateTxRecord {
        let chain_id = ChainId::new("miden-devnet").unwrap();
        let tx_id = tx_id(seed);
        let identity = private_tx_record_identity(&chain_id, tx_id);

        EncryptedPrivateTxRecord {
            version: PRIVATE_TX_VERSION,
            chain_id,
            tx_id,
            viewing_group_id: word(seed + 10),
            identity,
            validator_id: ValidatorId::new("validator-1").unwrap(),
            validator_encryption_key_id: word(seed + 20),
            tee_attestation_id: word(seed + 30),
            record_ciphertext: vec![1, 2, 3, seed as u8],
            data_key_protection: DataKeyProtection::ThresholdWrappedKey {
                scheme_id: ThresholdSchemeId::new(7),
                wrapped_key: vec![4, 5, 6, seed as u8],
            },
        }
    }

    fn tx_id(seed: u32) -> TransactionId {
        TransactionId::read_from_bytes(&word(seed).to_bytes()).unwrap()
    }

    fn word(seed: u32) -> Word {
        Word::from([seed, seed + 1, seed + 2, seed + 3])
    }
}
