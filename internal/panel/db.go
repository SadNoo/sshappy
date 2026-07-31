package panel

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

var processStartedAt = time.Now()

const (
	trafficSQLBatchSize = 50
	aliveIPSQLBatchSize = 500
)

type Database struct {
	db     *sql.DB
	config Config
}

// ErrNodeNotAuthorized marks node state that is authoritative and must not be
// treated like a temporary database failure. Keeping the previous node active
// after this error would bypass a panel-side revoke or bandwidth limit.
var ErrNodeNotAuthorized = errors.New("node is not authorized to serve traffic")

func OpenDatabase(config Config) (*Database, error) {
	tlsMode, err := mysqlTLSMode(config)
	if err != nil {
		return nil, err
	}
	driverConfig := mysqlDriverConfig(config, tlsMode)
	db, err := sql.Open("mysql", driverConfig.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(3 * time.Minute)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureTrafficBatchTable(db, config.MySQLDB); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Database{db: db, config: config}, nil
}

func mysqlDriverConfig(config Config, tlsMode string) *mysql.Config {
	driverConfig := mysql.NewConfig()
	driverConfig.User = config.MySQLUser
	driverConfig.Passwd = config.MySQLPassword
	driverConfig.Net = "tcp"
	driverConfig.Addr = net.JoinHostPort(config.MySQLHost, strconv.Itoa(config.MySQLPort))
	driverConfig.DBName = config.MySQLDB
	driverConfig.Params = map[string]string{"charset": "utf8mb4"}
	driverConfig.ParseTime = true
	driverConfig.Loc = time.Local
	driverConfig.TLSConfig = tlsMode
	driverConfig.Timeout = time.Duration(config.MySQLConnectTimeoutSeconds) * time.Second
	driverConfig.ReadTimeout = time.Duration(config.MySQLIOTimeoutSeconds) * time.Second
	driverConfig.WriteTimeout = time.Duration(config.MySQLIOTimeoutSeconds) * time.Second
	return driverConfig
}

func ensureTrafficBatchTable(db *sql.DB, schema string) error {
	var tableCount int
	if err := db.QueryRow(`
		SELECT COUNT(*)
		FROM information_schema.tables
		WHERE table_schema = ? AND table_name = 'sshappy_traffic_batch'
	`, schema).Scan(&tableCount); err != nil {
		return fmt.Errorf("failed to inspect traffic batch table: %w", err)
	}
	if tableCount > 0 {
		return nil
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS sshappy_traffic_batch (
			batch_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
			node_id INT NOT NULL,
			created_at BIGINT NOT NULL,
			PRIMARY KEY (batch_id),
			KEY node_created_at (node_id, created_at)
		) ENGINE=InnoDB
	`); err != nil {
		return fmt.Errorf("failed to initialize traffic batch table: %w", err)
	}
	return nil
}

const mysqlTLSConfigName = "sshappy-panel-mysql"

func mysqlTLSMode(config Config) (string, error) {
	mode := strings.ToLower(config.MySQLTLSMode)
	if mode == "" || mode == "auto" {
		if strings.EqualFold(config.MySQLHost, "localhost") {
			return "false", nil
		}
		if ip := net.ParseIP(config.MySQLHost); ip != nil && ip.IsLoopback() {
			return "false", nil
		}
		mode = "required"
	}

	switch mode {
	case "disabled":
		return "false", nil
	case "preferred":
		return mode, nil
	case "required":
		return "true", nil
	case "verify":
		data, err := os.ReadFile(config.MySQLTLSCA)
		if err != nil {
			return "", fmt.Errorf("failed to read MYSQL_TLS_CA: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return "", fmt.Errorf("MYSQL_TLS_CA does not contain a valid certificate")
		}
		if err := mysql.RegisterTLSConfig(mysqlTLSConfigName, &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
			ServerName: config.MySQLHost,
		}); err != nil {
			return "", fmt.Errorf("failed to register MySQL TLS config: %w", err)
		}
		return mysqlTLSConfigName, nil
	default:
		return "", fmt.Errorf("unsupported MySQL TLS mode %q", config.MySQLTLSMode)
	}
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) Stats() sql.DBStats {
	return d.db.Stats()
}

func (d *Database) LoadNode() (Node, error) {
	var node Node
	var bandwidth, bandwidthLimit int64
	err := d.db.QueryRow(`
		SELECT id, node_group, node_class, node_speedlimit, traffic_rate, sort, server,
		       node_bandwidth, node_bandwidth_limit
		FROM ss_node
		WHERE id = ?
	`, d.config.NodeID).Scan(
		&node.ID,
		&node.Group,
		&node.Class,
		&node.SpeedLimit,
		&node.TrafficRate,
		&node.Sort,
		&node.Server,
		&bandwidth,
		&bandwidthLimit,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return node, fmt.Errorf("%w: node %d does not exist", ErrNodeNotAuthorized, d.config.NodeID)
		}
		return node, err
	}
	return validateLoadedNode(node, bandwidth, bandwidthLimit)
}

func validateLoadedNode(node Node, bandwidth, bandwidthLimit int64) (Node, error) {
	if bandwidthLimit != 0 && bandwidth >= bandwidthLimit {
		return node, fmt.Errorf("%w: node %d exceeded its bandwidth limit", ErrNodeNotAuthorized, node.ID)
	}
	if node.Sort != 14 {
		return node, fmt.Errorf("%w: node %d must be sort=14", ErrNodeNotAuthorized, node.ID)
	}
	_, port, serverKeyB64, err := parseSSSinglePort(node.Server)
	if err != nil {
		return node, fmt.Errorf("%w: %v", ErrNodeNotAuthorized, err)
	}
	serverKey, err := decodePSK(serverKeyB64)
	if err != nil {
		return node, fmt.Errorf("%w: node %d has an invalid server key", ErrNodeNotAuthorized, node.ID)
	}
	node.ListenPort = port
	node.ServerKeyB64 = serverKeyB64
	node.ServerKey = serverKey
	if node.TrafficRate == 0 {
		node.TrafficRate = 1
	}
	if node.TrafficRate < 0 || math.IsNaN(node.TrafficRate) || math.IsInf(node.TrafficRate, 0) {
		return node, fmt.Errorf("%w: node %d has invalid traffic rate", ErrNodeNotAuthorized, node.ID)
	}
	return node, nil
}

func (d *Database) LoadUsers(node Node) ([]User, error) {
	conditions := []string{"enable = 1", "expire_in > NOW()", "transfer_enable > u + d"}
	var args []any
	if node.Group == 0 {
		conditions = append(conditions, "(class >= ? OR is_admin = 1)")
		args = append(args, node.Class)
	} else {
		conditions = append(conditions, "((class >= ? AND node_group = ?) OR is_admin = 1)")
		args = append(args, node.Class, node.Group)
	}
	rows, err := d.db.Query(`
		SELECT id, email, passwd, forbidden_ip, forbidden_port, disconnect_ip, node_speedlimit
		FROM user
		WHERE `+strings.Join(conditions, " AND "), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]User, 0, 1024)
	for rows.Next() {
		var user User
		var forbiddenIP, forbiddenPort, disconnectIP sql.NullString
		if err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Passwd,
			&forbiddenIP,
			&forbiddenPort,
			&disconnectIP,
			&user.NodeSpeedLimit,
		); err != nil {
			return nil, err
		}
		user.ForbiddenIP = forbiddenIP.String
		user.ForbiddenPort = forbiddenPort.String
		user.DisconnectIP = disconnectIP.String
		user.UserKey, user.UserKeyB64 = deriveUserKey(user.ID, user.Passwd, node.ID, node.ServerKeyB64)
		users = append(users, user)
	}
	return users, rows.Err()
}

func (d *Database) ReportTraffic(node Node, batchID string, traffic []TrafficDelta) (err error) {
	if len(traffic) == 0 {
		return nil
	}
	conn, release, err := d.acquireTrafficBatchLock(node.ID, batchID)
	if err != nil {
		return err
	}
	defer func() {
		if releaseErr := release(); err == nil && releaseErr != nil {
			err = releaseErr
		}
	}()

	committed, err := d.trafficBatchCommitted(conn, node.ID, batchID)
	if err != nil {
		return err
	}
	if committed {
		return nil
	}

	traffic = mergeTrafficDeltas(traffic)
	sort.Slice(traffic, func(i, j int) bool {
		return traffic[i].UserID < traffic[j].UserID
	})
	billed := make([]billedTrafficDelta, 0, len(traffic))
	for _, delta := range traffic {
		if delta.UserID <= 0 || delta.Upload < 0 || delta.Download < 0 {
			return fmt.Errorf("invalid traffic delta for user %d", delta.UserID)
		}
		billedUpload := int64(float64(delta.Upload) * node.TrafficRate)
		billedDownload := int64(float64(delta.Download) * node.TrafficRate)
		billed = append(billed, billedTrafficDelta{
			TrafficDelta:   delta,
			BilledUpload:   billedUpload,
			BilledDownload: billedDownload,
			TrafficText:    flowAutoShow(int64(float64(delta.Upload+delta.Download) * node.TrafficRate)),
		})
	}
	now := time.Now().Unix()
	chunkIDs := make([]string, 0, (len(billed)+trafficSQLBatchSize-1)/trafficSQLBatchSize)
	for start := 0; start < len(billed); start += trafficSQLBatchSize {
		end := min(start+trafficSQLBatchSize, len(billed))
		chunkID := trafficChunkID(batchID, node.ID, len(chunkIDs))
		chunkIDs = append(chunkIDs, chunkID)
		if err := d.reportTrafficChunk(conn, node, chunkID, billed[start:end], now); err != nil {
			return fmt.Errorf("traffic chunk %d/%d failed: %w", len(chunkIDs), (len(billed)+trafficSQLBatchSize-1)/trafficSQLBatchSize, err)
		}
	}
	return d.finalizeTrafficBatch(conn, node.ID, batchID, chunkIDs, now)
}

func (d *Database) acquireTrafficBatchLock(nodeID int, batchID string) (*sql.Conn, func() error, error) {
	timeoutSeconds := d.config.MySQLIOTimeoutSeconds
	if timeoutSeconds < 1 {
		timeoutSeconds = 30
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds+1)*time.Second)
	defer cancel()
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to reserve traffic reporting connection: %w", err)
	}
	lockName := trafficBatchLockName(nodeID, batchID)
	var acquired sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", lockName, timeoutSeconds).Scan(&acquired); err != nil {
		// The server may have granted the lock before the response was lost.
		// Discard the physical connection instead of returning it to the pool.
		discardSQLConn(conn)
		return nil, nil, fmt.Errorf("failed to acquire traffic batch lock: %w", err)
	}
	if !acquired.Valid || acquired.Int64 != 1 {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("timed out acquiring traffic batch lock")
	}
	release := func() error {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer releaseCancel()
		var released sql.NullInt64
		releaseErr := conn.QueryRowContext(releaseCtx, "SELECT RELEASE_LOCK(?)", lockName).Scan(&released)
		if releaseErr != nil || !released.Valid || released.Int64 != 1 {
			// A sql.Conn.Close returns the underlying connection to the pool. Mark it
			// bad instead so an ambiguously held advisory lock cannot leak into the
			// pool after a failed RELEASE_LOCK.
			discardSQLConn(conn)
			if releaseErr != nil {
				return fmt.Errorf("failed to release traffic batch lock: %w", releaseErr)
			}
			return errors.New("traffic batch lock was not owned at release")
		}
		return conn.Close()
	}
	return conn, release, nil
}

func discardSQLConn(conn *sql.Conn) {
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = conn.Close()
}

func trafficBatchLockName(nodeID int, batchID string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%s", nodeID, batchID)))
	return "sshappy:traffic:" + hex.EncodeToString(sum[:16])
}

func (d *Database) trafficBatchCommitted(conn *sql.Conn, nodeID int, batchID string) (bool, error) {
	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		return false, err
	}
	result, err := tx.Exec(
		"INSERT IGNORE INTO sshappy_traffic_batch (batch_id, node_id, created_at) VALUES (?, ?, ?)",
		batchID,
		nodeID,
		time.Now().Unix(),
	)
	if err != nil {
		_ = tx.Rollback()
		return false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		return false, err
	}
	if err := tx.Rollback(); err != nil {
		return false, err
	}
	return inserted == 0, nil
}

func (d *Database) reportTrafficChunk(conn *sql.Conn, node Node, chunkID string, batch []billedTrafficDelta, now int64) error {
	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(
		"INSERT IGNORE INTO sshappy_traffic_batch (batch_id, node_id, created_at) VALUES (?, ?, ?)",
		chunkID,
		node.ID,
		now,
	)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		return nil
	}
	query, args := userTrafficUpdateStatement(batch, now)
	if _, err := tx.Exec(query, args...); err != nil {
		return err
	}
	query, args = trafficLogInsertStatement(batch, node, now)
	if _, err := tx.Exec(query, args...); err != nil {
		return err
	}
	var total int64
	for _, delta := range batch {
		total += delta.Upload + delta.Download
	}
	if _, err := tx.Exec(`
		UPDATE ss_node
		SET node_heartbeat = ?, node_bandwidth = node_bandwidth + ?
		WHERE id = ?
	`, now, total, node.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *Database) finalizeTrafficBatch(conn *sql.Conn, nodeID int, batchID string, chunkIDs []string, now int64) error {
	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		"INSERT IGNORE INTO sshappy_traffic_batch (batch_id, node_id, created_at) VALUES (?, ?, ?)",
		batchID,
		nodeID,
		now,
	); err != nil {
		return err
	}
	if len(chunkIDs) > 0 {
		var query strings.Builder
		query.WriteString("DELETE FROM sshappy_traffic_batch WHERE node_id = ? AND batch_id IN (")
		appendSQLPlaceholders(&query, len(chunkIDs), 1)
		query.WriteByte(')')
		args := make([]any, 0, len(chunkIDs)+1)
		args = append(args, nodeID)
		for _, chunkID := range chunkIDs {
			args = append(args, chunkID)
		}
		if _, err := tx.Exec(query.String(), args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func trafficChunkID(batchID string, nodeID, index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", batchID, nodeID, index)))
	return hex.EncodeToString(sum[:16])
}

type billedTrafficDelta struct {
	TrafficDelta
	BilledUpload   int64
	BilledDownload int64
	TrafficText    string
}

func userTrafficUpdateStatement(batch []billedTrafficDelta, now int64) (string, []any) {
	var query strings.Builder
	args := make([]any, 0, len(batch)*5+1)
	query.WriteString("UPDATE user SET u = u + CASE id")
	for _, delta := range batch {
		query.WriteString(" WHEN ? THEN ?")
		args = append(args, delta.UserID, delta.BilledUpload)
	}
	query.WriteString(" ELSE 0 END, d = d + CASE id")
	for _, delta := range batch {
		query.WriteString(" WHEN ? THEN ?")
		args = append(args, delta.UserID, delta.BilledDownload)
	}
	query.WriteString(" ELSE 0 END, t = ? WHERE id IN (")
	args = append(args, now)
	appendSQLPlaceholders(&query, len(batch), 1)
	query.WriteByte(')')
	for _, delta := range batch {
		args = append(args, delta.UserID)
	}
	return query.String(), args
}

func trafficLogInsertStatement(batch []billedTrafficDelta, node Node, now int64) (string, []any) {
	var query strings.Builder
	args := make([]any, 0, len(batch)*7)
	query.WriteString("INSERT INTO user_traffic_log (user_id, u, d, node_id, rate, traffic, log_time) VALUES ")
	appendSQLPlaceholders(&query, len(batch), 7)
	for _, delta := range batch {
		args = append(args, delta.UserID, delta.Upload, delta.Download, node.ID, node.TrafficRate, delta.TrafficText, now)
	}
	return query.String(), args
}

func appendSQLPlaceholders(builder *strings.Builder, rows, columns int) {
	for row := 0; row < rows; row++ {
		if row > 0 {
			builder.WriteByte(',')
		}
		if columns > 1 {
			builder.WriteByte('(')
		}
		for column := 0; column < columns; column++ {
			if column > 0 {
				builder.WriteByte(',')
			}
			builder.WriteByte('?')
		}
		if columns > 1 {
			builder.WriteByte(')')
		}
	}
}

func (d *Database) CleanupTrafficBatches(nodeID, retentionDays int) (int64, error) {
	if retentionDays == 0 {
		return 0, nil
	}
	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour).Unix()
	const deleteBatchSize = 5000
	var deletedTotal int64
	for {
		result, err := d.db.Exec(`
			DELETE FROM sshappy_traffic_batch
			WHERE node_id = ? AND created_at < ?
			LIMIT ?
		`, nodeID, cutoff, deleteBatchSize)
		if err != nil {
			return deletedTotal, err
		}
		deleted, err := result.RowsAffected()
		if err != nil {
			return deletedTotal, err
		}
		deletedTotal += deleted
		if deleted < deleteBatchSize {
			return deletedTotal, nil
		}
	}
}

func (d *Database) ReportAliveIPs(node Node, alive map[int]map[string]struct{}) error {
	if len(alive) == 0 {
		return nil
	}
	now := time.Now().Unix()
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	records := make([]aliveIPRecord, 0)
	for userID, ips := range alive {
		for ip := range ips {
			records = append(records, aliveIPRecord{UserID: userID, IP: ip})
		}
	}
	for start := 0; start < len(records); start += aliveIPSQLBatchSize {
		end := min(start+aliveIPSQLBatchSize, len(records))
		query, args := aliveIPInsertStatement(records[start:end], node.ID, now)
		if _, err := tx.Exec(query, args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type aliveIPRecord struct {
	UserID int
	IP     string
}

func aliveIPInsertStatement(records []aliveIPRecord, nodeID int, now int64) (string, []any) {
	var query strings.Builder
	args := make([]any, 0, len(records)*4)
	query.WriteString("INSERT INTO alive_ip (nodeid, userid, ip, datetime) VALUES ")
	appendSQLPlaceholders(&query, len(records), 4)
	for _, record := range records {
		args = append(args, nodeID, record.UserID, record.IP, now)
	}
	return query.String(), args
}

func (d *Database) ReportNodeStatus(node Node, online int) error {
	now := time.Now().Unix()
	uptime := int64(time.Since(processStartedAt).Seconds())
	load := "0.00"
	if raw, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) > 0 {
			load = fields[0]
		}
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		"INSERT INTO ss_node_online_log (node_id, online_user, log_time) VALUES (?, ?, ?)",
		node.ID,
		online,
		now,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(
		"INSERT INTO ss_node_info (node_id, uptime, `load`, log_time) VALUES (?, ?, ?, ?)",
		node.ID,
		uptime,
		load,
		now,
	); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE ss_node SET node_heartbeat = ? WHERE id = ?", now, node.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func parseSSSinglePort(value string) (host string, port int, key string, err error) {
	parts := strings.Split(value, ";")
	if len(parts) > 0 {
		host = parts[0]
	}
	port = 443
	if len(parts) >= 2 && parts[1] != "" && parts[1] != "0" {
		port, err = strconv.Atoi(parts[1])
		if err != nil {
			return
		}
	}
	if len(parts) >= 3 {
		key = parts[2]
	}
	switch {
	case host == "":
		err = fmt.Errorf("ss_node.server host is empty")
	case port < 1 || port > 65535:
		err = fmt.Errorf("ss_node.server port must be between 1 and 65535")
	case key == "":
		err = fmt.Errorf("ss_node.server server_key is empty")
	}
	return
}

func flowAutoShow(value int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	amount := float64(value)
	for i, unit := range units {
		if amount < 1024 || i == len(units)-1 {
			return fmt.Sprintf("%.2f%s", math.Round(amount*100)/100, unit)
		}
		amount /= 1024
	}
	return fmt.Sprintf("%.2fPB", amount)
}
