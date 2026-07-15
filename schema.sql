CREATE DATABASE IF NOT EXISTS wireguard_stats;
USE wireguard_stats;

-- Interface configuration table
CREATE TABLE IF NOT EXISTS interfaces (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    public_key VARCHAR(64),
    listen_port INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Peer statistics table
CREATE TABLE IF NOT EXISTS peer_stats (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    interface_name VARCHAR(50) NOT NULL,
    peer_public_key VARCHAR(64) NOT NULL,
    endpoint VARCHAR(50),
    allowed_ips TEXT,
    rx_bytes BIGINT DEFAULT 0,
    tx_bytes BIGINT DEFAULT 0,
    last_handshake DATETIME,
    persistent_keepalive INT DEFAULT 0,
    is_connected BOOLEAN DEFAULT FALSE,
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_peer_time (peer_public_key, collected_at),
    INDEX idx_interface_time (interface_name, collected_at)
);

-- Daily aggregated statistics
CREATE TABLE IF NOT EXISTS daily_peer_stats (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    interface_name VARCHAR(50) NOT NULL,
    peer_public_key VARCHAR(64) NOT NULL,
    stat_date DATE NOT NULL,
    total_rx_bytes BIGINT DEFAULT 0,
    total_tx_bytes BIGINT DEFAULT 0,
    avg_rx_bytes_per_hour BIGINT DEFAULT 0,
    avg_tx_bytes_per_hour BIGINT DEFAULT 0,
    max_rx_bytes BIGINT DEFAULT 0,
    max_tx_bytes BIGINT DEFAULT 0,
    connection_hours INT DEFAULT 0,
    handshake_count INT DEFAULT 0,
    UNIQUE KEY unique_daily (interface_name, peer_public_key, stat_date)
);