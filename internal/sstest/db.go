package sstest

import (
	"database/sql"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type Database struct {
	db     *sql.DB
	config Config
}

func OpenDatabase(config Config) (*Database, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=true&loc=Local",
		config.MySQLUser,
		config.MySQLPassword,
		config.MySQLHost,
		config.MySQLPort,
		config.MySQLDB,
	)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(3 * time.Minute)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &Database{db: db, config: config}, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) LoadNode() (NodeInfo, error) {
	var node NodeInfo
	var serverKeyB64 string
	err := d.db.QueryRow(`
		SELECT id, node_group, node_class, node_speedlimit, traffic_rate, sort,
		       server
		FROM ss_node
		WHERE id = ?
		  AND (node_bandwidth < node_bandwidth_limit OR node_bandwidth_limit = 0)
	`, d.config.NodeID).Scan(
		&node.ID,
		&node.Group,
		&node.Class,
		&node.SpeedLimit,
		&node.TrafficRate,
		&node.Sort,
		&node.Server,
	)
	if err != nil {
		return node, err
	}
	if node.Sort != 14 {
		return node, fmt.Errorf("node %d must be sort=14", node.ID)
	}
	_, port, key, err := parseSSSinglePort(node.Server)
	if err != nil {
		return node, err
	}
	serverKeyB64 = key
	serverKey, err := decodePSK(serverKeyB64)
	if err != nil {
		return node, err
	}
	node.ListenPort = port
	node.ServerKeyB64 = serverKeyB64
	node.ServerKey = serverKey
	if node.TrafficRate == 0 {
		node.TrafficRate = 1
	}
	return node, nil
}

func (d *Database) LoadUsers(node NodeInfo) ([]User, error) {
	conditions := []string{"enable = 1", "expire_in > NOW()", "transfer_enable > u + d"}
	args := []any{}
	if node.Group == 0 {
		conditions = append(conditions, "(class >= ? OR is_admin = 1)")
		args = append(args, node.Class)
	} else {
		conditions = append(conditions, "((class >= ? AND node_group = ?) OR is_admin = 1)")
		args = append(args, node.Class, node.Group)
	}
	query := `
		SELECT id, email, passwd, forbidden_ip, forbidden_port, disconnect_ip,
		       node_speedlimit
		FROM user
		WHERE ` + strings.Join(conditions, " AND ")
	rows, err := d.db.Query(query, args...)
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
		user.UserKeyB64 = deriveUserKeyB64(user.ID, user.Passwd, node.ID, node.ServerKeyB64)
		key, err := decodePSK(user.UserKeyB64)
		if err != nil {
			return nil, err
		}
		user.UserKey = key
		user.IdentityHash = identityHash(key)
		users = append(users, user)
	}
	return users, rows.Err()
}

func (d *Database) ReportTraffic(node NodeInfo, traffic []TrafficDelta) error {
	if len(traffic) == 0 {
		return nil
	}
	now := time.Now().Unix()
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var total int64
	for _, delta := range traffic {
		billedU := int64(float64(delta.Upload) * node.TrafficRate)
		billedD := int64(float64(delta.Download) * node.TrafficRate)
		if _, err := tx.Exec("UPDATE user SET u = u + ?, d = d + ?, t = ? WHERE id = ?", billedU, billedD, now, delta.UserID); err != nil {
			return err
		}
		trafficText := flowAutoShow(int64(float64(delta.Upload+delta.Download) * node.TrafficRate))
		if _, err := tx.Exec(`
			INSERT INTO user_traffic_log
			  (user_id, u, d, node_id, rate, traffic, log_time)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, delta.UserID, delta.Upload, delta.Download, node.ID, node.TrafficRate, trafficText, now); err != nil {
			return err
		}
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

func (d *Database) ReportAliveIPs(node NodeInfo, alive map[int]map[string]struct{}) error {
	if len(alive) == 0 {
		return nil
	}
	now := time.Now().Unix()
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for userID, ips := range alive {
		for ip := range ips {
			if _, err := tx.Exec("INSERT INTO alive_ip (nodeid, userid, ip, datetime) VALUES (?, ?, ?, ?)", node.ID, userID, ip, now); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (d *Database) ReportNodeStatus(node NodeInfo, online int) error {
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
	if _, err := tx.Exec("INSERT INTO ss_node_online_log (node_id, online_user, log_time) VALUES (?, ?, ?)", node.ID, online, now); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO ss_node_info (node_id, uptime, `load`, log_time) VALUES (?, ?, ?, ?)", node.ID, uptime, load, now); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE ss_node SET node_heartbeat = ? WHERE id = ?", now, node.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func parseSSSinglePort(value string) (string, int, string, error) {
	parts := strings.Split(value, ";")
	host := ""
	if len(parts) > 0 {
		host = parts[0]
	}
	port := 443
	if len(parts) >= 2 && parts[1] != "" && parts[1] != "0" {
		parsed, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", 0, "", err
		}
		port = parsed
	}
	key := ""
	if len(parts) >= 3 {
		key = parts[2]
	}
	if host == "" {
		return "", 0, "", fmt.Errorf("ss_node.server host is empty")
	}
	if key == "" {
		return "", 0, "", fmt.Errorf("ss_node.server server_key is empty")
	}
	return host, port, key, nil
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
