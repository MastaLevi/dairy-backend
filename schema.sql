-- Run this in phpMyAdmin after selecting the dairy_company database.
CREATE TABLE IF NOT EXISTS collection_routes (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    route_name VARCHAR(80) NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS workers (
    worker_id VARCHAR(50) NOT NULL PRIMARY KEY,
    password_hash VARCHAR(200) NOT NULL,
    route_id INT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    session_version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_workers_route (route_id),
    CONSTRAINT fk_workers_route FOREIGN KEY (route_id)
        REFERENCES collection_routes(id) ON DELETE SET NULL
);

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

CREATE TABLE IF NOT EXISTS worker_passkeys (
    credential_id VARCHAR(512) NOT NULL PRIMARY KEY,
    worker_id VARCHAR(50) NOT NULL,
    public_key_jwk JSON NOT NULL,
    signature_counter BIGINT UNSIGNED NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_worker_passkeys_worker (worker_id),
    CONSTRAINT fk_worker_passkeys_worker FOREIGN KEY (worker_id)
        REFERENCES workers(worker_id) ON DELETE CASCADE
);
