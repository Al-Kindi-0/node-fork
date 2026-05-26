CREATE TABLE private_tx_archive_records (
    tx_id      BLOB NOT NULL,
    -- PoC storage keeps the full serialized archive record. Production should bound this at
    -- validation time or with a CHECK constraint once payload size policy is set.
    record     BLOB NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (tx_id)
) WITHOUT ROWID;
