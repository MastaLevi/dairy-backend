-- Apply only after milk_collections exists and has its primary key on id.
-- This migration does not store SMS bodies or farmer phone numbers.
CREATE TABLE IF NOT EXISTS sms_delivery_attempts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    collection_id INT NOT NULL,
    provider VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    provider_status_code VARCHAR(32) NULL,
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_sms_attempted_at (attempted_at),
    INDEX idx_sms_collection (collection_id),
    CONSTRAINT fk_sms_attempt_collection FOREIGN KEY (collection_id)
        REFERENCES milk_collections(id) ON DELETE CASCADE
);
