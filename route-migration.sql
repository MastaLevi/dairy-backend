-- Run once in phpMyAdmin with dairy_company selected.
CREATE TABLE IF NOT EXISTS collection_routes (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    route_name VARCHAR(80) NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE workers
    ADD COLUMN route_id INT NULL,
    ADD INDEX idx_workers_route (route_id),
    ADD CONSTRAINT fk_workers_route FOREIGN KEY (route_id)
        REFERENCES collection_routes(id) ON DELETE SET NULL;
