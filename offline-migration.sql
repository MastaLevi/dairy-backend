-- Run once in phpMyAdmin with dairy_company selected before using offline sync.
-- collector_id is VARCHAR so it matches workers.worker_id, including letter IDs.
ALTER TABLE milk_collections
    MODIFY COLUMN collector_id VARCHAR(50) NULL,
    ADD COLUMN client_record_id VARCHAR(64) NULL;

CREATE UNIQUE INDEX uq_milk_collections_client_record_id
    ON milk_collections (client_record_id);
