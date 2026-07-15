package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
)

// Config structure
type Config struct {
	Database struct {
		Driver   string `yaml:"driver"`
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		Name     string `yaml:"name"`
		TLS      struct {
			Enabled            bool   `yaml:"enabled"`
			CACert             string `yaml:"ca_cert"`
			ClientCert         string `yaml:"client_cert"`
			ClientKey          string `yaml:"client_key"`
			ServerName         string `yaml:"server_name"`
			InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
		} `yaml:"tls"`
	} `yaml:"database"`

	WireGuard struct {
		Interfaces []string `yaml:"interfaces"`
	} `yaml:"wireguard"`

	Collection struct {
		Interval               int  `yaml:"interval"`
		EnableDailyAggregation bool `yaml:"enable_daily_aggregation"`
	} `yaml:"collection"`
}

// PeerStat represents a single peer's statistics
type PeerStat struct {
	InterfaceName       string
	PublicKey           string
	Endpoint            string
	AllowedIPs          string
	RxBytes             int64
	TxBytes             int64
	LastHandshake       *time.Time
	PersistentKeepalive int
	IsConnected         bool
}

// StatsCollector manages data collection
type StatsCollector struct {
	db       *sql.DB
	config   *Config
	mu       sync.Mutex
	wgClient *wgctrl.Client
}

func main() {
	log.Println("Starting WireGuard Statistics Collector...")

	// Load configuration
	config, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database
	db, err := initDatabase(config)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Create WireGuard client
	wgClient, err := wgctrl.New()
	if err != nil {
		log.Fatalf("Failed to create WireGuard client: %v", err)
	}
	defer wgClient.Close()

	collector := &StatsCollector{
		db:       db,
		config:   config,
		wgClient: wgClient,
	}

	// Create schema if not exists
	if err := collector.createSchema(); err != nil {
		log.Fatalf("Failed to create schema: %v", err)
	}

	// Setup graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// Start collection loop
	ticker := time.NewTicker(time.Duration(config.Collection.Interval) * time.Second)
	defer ticker.Stop()

	log.Printf("Collection started. Interval: %d seconds", config.Collection.Interval)

	// Initial collection
	collector.collectAndStore()

	// Daily aggregation ticker (run at midnight)
	var dailyTicker *time.Ticker
	if config.Collection.EnableDailyAggregation {
		dailyTicker = scheduleDailyTask()
		defer dailyTicker.Stop()
	}

	for {
		select {
		case <-ticker.C:
			collector.collectAndStore()

		case <-dailyTicker.C:
			if config.Collection.EnableDailyAggregation {
				collector.performDailyAggregation()
			}

		case <-stop:
			log.Println("Shutting down...")
			return
		}
	}
}

// loadConfig reads and parses the YAML configuration
func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error parsing config: %w", err)
	}

	return &config, nil
}

// initDatabase creates the MySQL connection with x509 certificate support
func initDatabase(config *Config) (*sql.DB, error) {
	if config.Database.Driver != "mysql" {
		return nil, fmt.Errorf("unsupported driver: %s", config.Database.Driver)
	}

	// Build DSN with TLS configuration
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
		config.Database.User,
		config.Database.Password,
		config.Database.Host,
		config.Database.Port,
		config.Database.Name,
	)

	// Register custom TLS configuration if enabled
	if config.Database.TLS.Enabled {
		tlsConfig, err := createTLSConfig(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}

		// Register the TLS config with a custom name
		tlsConfigName := "custom-mysql-tls"
		if err := mysql.RegisterTLSConfig(tlsConfigName, tlsConfig); err != nil {
			// If already registered, that's fine
			if !strings.Contains(err.Error(), "already registered") {
				return nil, fmt.Errorf("failed to register TLS config: %w", err)
			}
		}

		// Append TLS parameter to DSN
		dsn += fmt.Sprintf("&tls=%s", tlsConfigName)

		log.Printf("TLS enabled for MySQL connection (cert: %s)", config.Database.TLS.ClientCert)
	}

	// Additional DSN parameters for reliability
	dsn += "&timeout=10s&readTimeout=30s&writeTimeout=30s&maxAllowedPacket=0"

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("error opening database: %w", err)
	}

	// Connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("error connecting to database: %w", err)
	}

	log.Println("MySQL database connection established successfully")
	return db, nil
}

// createTLSConfig creates a TLS configuration for MySQL x509 authentication
func createTLSConfig(config *Config) (*tls.Config, error) {
	// Load CA certificate
	caCert, err := os.ReadFile(config.Database.TLS.CACert)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Load client certificate and key
	clientCert, err := tls.LoadX509KeyPair(
		config.Database.TLS.ClientCert,
		config.Database.TLS.ClientKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate/key pair: %w", err)
	}

	// Determine server name for verification
	serverName := config.Database.TLS.ServerName
	if serverName == "" {
		serverName = config.Database.Host
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,

		// Custom verification to handle legacy certificates
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// If standard verification passed, we're good
			if len(verifiedChains) > 0 {
				return nil
			}

			// Manual verification for legacy certificates
			opts := x509.VerifyOptions{
				Roots:         caCertPool,
				CurrentTime:   time.Now(),
				Intermediates: x509.NewCertPool(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}

			// Parse the server certificate
			if len(rawCerts) == 0 {
				return fmt.Errorf("no server certificate provided")
			}

			serverCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("failed to parse server certificate: %w", err)
			}

			// Add intermediate certificates if any
			for _, rawCert := range rawCerts[1:] {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					continue
				}
				opts.Intermediates.AddCert(cert)
			}

			// If ServerName is set, verify it matches CommonName
			if serverName != "" && serverCert.Subject.CommonName == serverName {
				// Bypass SAN check for legacy certificates
				opts.DNSName = "" // Clear DNS name to skip SAN check
			}

			// Manual verification
			_, err = serverCert.Verify(opts)
			return err
		},
	}

	log.Printf("TLS configuration created (legacy certificate support enabled)")
	return tlsConfig, nil
}

// Alternative: Direct registration approach (simpler but less flexible)
func initDatabaseSimple(config *Config) (*sql.DB, error) {
	// Register TLS config using MySQL's built-in registration
	if config.Database.TLS.Enabled {
		// MySQL driver supports direct PEM file paths
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&tls=custom",
			config.Database.User,
			config.Database.Password,
			config.Database.Host,
			config.Database.Port,
			config.Database.Name,
		)

		// Set MySQL TLS variables via connection parameters
		// Note: This requires MySQL 8.0+ with caching_sha2_password or mysql_native_password
		dsn += "&allowCleartextPasswords=true" // Required for some x509 auth methods

		db, err := sql.Open("mysql", dsn)
		if err != nil {
			return nil, err
		}

		// Execute SET statements to configure SSL
		_, err = db.Exec("SET @@global.mysqlx_ssl_ca = ?", config.Database.TLS.CACert)
		return db, err
	}

	// Fallback to standard connection
	return initDatabase(config)
}

// createSchema creates the database schema if it doesn't exist
// createSchema ensures all required tables exist
func (sc *StatsCollector) createSchema() error {
	// Split into separate CREATE statements
	statements := []string{
		`CREATE TABLE IF NOT EXISTS interfaces (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(50) NOT NULL UNIQUE,
            public_key VARCHAR(64),
            listen_port INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,

		`CREATE TABLE IF NOT EXISTS peer_stats (
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
        )`,

		`CREATE TABLE IF NOT EXISTS daily_peer_stats (
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
        )`,
	}

	// Execute each statement separately
	for i, stmt := range statements {
		if _, err := sc.db.Exec(stmt); err != nil {
			return fmt.Errorf("error executing statement %d: %w\nSQL: %s", i+1, err, stmt)
		}
	}

	log.Println("Database schema created/verified successfully")
	return nil
}

// collectStats retrieves WireGuard statistics
func (sc *StatsCollector) collectStats() ([]PeerStat, error) {
	var stats []PeerStat

	devices, err := sc.wgClient.Devices()
	if err != nil {
		return nil, fmt.Errorf("error getting WireGuard devices: %w", err)
	}

	// Filter interfaces if specified in config
	interfaceFilter := make(map[string]bool)
	for _, iface := range sc.config.WireGuard.Interfaces {
		interfaceFilter[iface] = true
	}

	for _, device := range devices {
		// Skip if not in configured interfaces (when filter is set)
		if len(interfaceFilter) > 0 && !interfaceFilter[device.Name] {
			continue
		}

		// Store interface info
		sc.storeInterface(device)

		// Collect peer statistics
		for _, peer := range device.Peers {
			stat := PeerStat{
				InterfaceName:       device.Name,
				PublicKey:           peer.PublicKey.String(),
				Endpoint:            peer.Endpoint.String(),
				AllowedIPs:          formatAllowedIPs(peer.AllowedIPs),
				RxBytes:             peer.ReceiveBytes,
				TxBytes:             peer.TransmitBytes,
				PersistentKeepalive: int(peer.PersistentKeepaliveInterval.Seconds()),
			}

			// Handle last handshake
			if !peer.LastHandshakeTime.IsZero() {
				stat.LastHandshake = &peer.LastHandshakeTime
				// Consider connected if handshake was less than 3 minutes ago
				stat.IsConnected = time.Since(peer.LastHandshakeTime) < 3*time.Minute
			}

			stats = append(stats, stat)
		}
	}

	return stats, nil
}

// storeInterface saves interface information
func (sc *StatsCollector) storeInterface(device *wgtypes.Device) {
	query := `
        INSERT INTO interfaces (name, public_key, listen_port) 
        VALUES (?, ?, ?) 
        ON DUPLICATE KEY UPDATE 
            public_key = VALUES(public_key),
            listen_port = VALUES(listen_port)
    `

	_, err := sc.db.Exec(query, device.Name, device.PublicKey.String(), device.ListenPort)
	if err != nil {
		log.Printf("Error storing interface %s: %v", device.Name, err)
	}
}

// storePeerStats saves peer statistics to database
func (sc *StatsCollector) storePeerStats(stats []PeerStat) error {
	query := `
        INSERT INTO peer_stats (
            interface_name, peer_public_key, endpoint, allowed_ips,
            rx_bytes, tx_bytes, last_handshake, persistent_keepalive, is_connected
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `

	tx, err := sc.db.Begin()
	if err != nil {
		return fmt.Errorf("error beginning transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("error preparing statement: %w", err)
	}
	defer stmt.Close()

	for _, stat := range stats {
		_, err := stmt.Exec(
			stat.InterfaceName,
			stat.PublicKey,
			stat.Endpoint,
			stat.AllowedIPs,
			stat.RxBytes,
			stat.TxBytes,
			stat.LastHandshake,
			stat.PersistentKeepalive,
			stat.IsConnected,
		)

		if err != nil {
			return fmt.Errorf("error inserting peer stat: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}

	log.Printf("Stored %d peer statistics", len(stats))
	return nil
}

// collectAndStore is the main collection routine
func (sc *StatsCollector) collectAndStore() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	stats, err := sc.collectStats()
	if err != nil {
		log.Printf("Error collecting stats: %v", err)
		return
	}

	if err := sc.storePeerStats(stats); err != nil {
		log.Printf("Error storing stats: %v", err)
	}

	// Print summary
	for _, stat := range stats {
		log.Printf("[%s] Peer: %s, RX: %d bytes, TX: %d bytes, Connected: %v",
			stat.InterfaceName,
			stat.PublicKey[:16]+"...",
			stat.RxBytes,
			stat.TxBytes,
			stat.IsConnected,
		)
	}
}

// performDailyAggregation calculates daily statistics
func (sc *StatsCollector) performDailyAggregation() {
	log.Println("Performing daily aggregation...")

	query := `
        INSERT INTO daily_peer_stats (
            interface_name, peer_public_key, stat_date,
            total_rx_bytes, total_tx_bytes,
            avg_rx_bytes_per_hour, avg_tx_bytes_per_hour,
            max_rx_bytes, max_tx_bytes,
            connection_hours, handshake_count
        )
        SELECT 
            t.interface_name,
            t.peer_public_key,
            DATE(t.collected_at) as stat_date,
            SUM(t.rx_bytes - COALESCE(t.prev_rx, 0)) as total_rx,
            SUM(t.tx_bytes - COALESCE(t.prev_tx, 0)) as total_tx,
            AVG(t.rx_bytes - COALESCE(t.prev_rx, 0)) as avg_rx,
            AVG(t.tx_bytes - COALESCE(t.prev_tx, 0)) as avg_tx,
            MAX(t.rx_bytes - COALESCE(t.prev_rx, 0)) as max_rx,
            MAX(t.tx_bytes - COALESCE(t.prev_tx, 0)) as max_tx,
            COUNT(DISTINCT HOUR(t.collected_at)) as conn_hours,
            SUM(CASE WHEN t.is_connected = 1 THEN 1 ELSE 0 END) as handshake_count
        FROM (
            SELECT 
                p.interface_name,
                p.peer_public_key,
                p.collected_at,
                p.rx_bytes,
                p.tx_bytes,
                p.is_connected,
                LAG(p.rx_bytes) OVER (
                    PARTITION BY p.peer_public_key, p.interface_name 
                    ORDER BY p.collected_at
                ) as prev_rx,
                LAG(p.tx_bytes) OVER (
                    PARTITION BY p.peer_public_key, p.interface_name 
                    ORDER BY p.collected_at
                ) as prev_tx
            FROM peer_stats p
            WHERE DATE(p.collected_at) = DATE_SUB(CURDATE(), INTERVAL 1 DAY)
        ) t
        GROUP BY t.interface_name, t.peer_public_key, DATE(t.collected_at)
        ON DUPLICATE KEY UPDATE
            total_rx_bytes = VALUES(total_rx_bytes),
            total_tx_bytes = VALUES(total_tx_bytes),
            avg_rx_bytes_per_hour = VALUES(avg_rx_bytes_per_hour),
            avg_tx_bytes_per_hour = VALUES(avg_tx_bytes_per_hour),
            max_rx_bytes = VALUES(max_rx_bytes),
            max_tx_bytes = VALUES(max_tx_bytes),
            connection_hours = VALUES(connection_hours),
            handshake_count = VALUES(handshake_count)
    `

	result, err := sc.db.Exec(query)
	if err != nil {
		log.Printf("Error performing daily aggregation: %v", err)
		return
	}

	rows, _ := result.RowsAffected()
	log.Printf("Daily aggregation complete. %d rows updated", rows)
}

// Helper functions

func formatAllowedIPs(ips []net.IPNet) string {
	if len(ips) == 0 {
		return ""
	}

	var parts []string
	for _, ip := range ips {
		parts = append(parts, ip.String())
	}
	return strings.Join(parts, ", ")
}

func scheduleDailyTask() *time.Ticker {
	now := time.Now()
	next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
	duration := next.Sub(now)

	return time.NewTicker(duration)
}
