-- Run after a verified database backup and before deploying the hardened API.
-- Existing tokens without a session version will be invalidated when this column is added.
SET @has_session_version = (
    SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'workers' AND column_name = 'session_version'
);
SET @session_version_ddl = IF(
    @has_session_version = 0,
    'ALTER TABLE workers ADD COLUMN session_version INT NOT NULL DEFAULT 1',
    'SELECT 1'
);
PREPARE session_version_stmt FROM @session_version_ddl;
EXECUTE session_version_stmt;
DEALLOCATE PREPARE session_version_stmt;

CREATE TABLE IF NOT EXISTS security_audit_events (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    actor_id VARCHAR(50) NOT NULL,
    action VARCHAR(60) NOT NULL,
    target_type VARCHAR(30) NOT NULL,
    target_id VARCHAR(80) NOT NULL,
    details JSON NULL,
    source_ip VARCHAR(45) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_security_audit_target (target_type, target_id, created_at),
    INDEX idx_security_audit_actor (actor_id, created_at)
);

-- Assign null-route workers only after the office confirms their correct route.
-- Do not mass-assign routes by guesswork: unassigned workers will be blocked from farmer data.
