package panel

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"
	"time"
)

func TestMySQLChunkedTrafficRecoveryAndIdempotency(t *testing.T) {
	dsn := os.Getenv("SSHAPPY_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("SSHAPPY_TEST_MYSQL_DSN is not set")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range []string{
		"CREATE TABLE user (id INT PRIMARY KEY, u BIGINT NOT NULL DEFAULT 0, d BIGINT NOT NULL DEFAULT 0, t BIGINT NOT NULL DEFAULT 0) ENGINE=InnoDB",
		"CREATE TABLE user_traffic_log (user_id INT, u BIGINT, d BIGINT, node_id INT, rate DOUBLE, traffic VARCHAR(32), log_time BIGINT) ENGINE=InnoDB",
		"CREATE TABLE ss_node (id INT PRIMARY KEY, node_heartbeat BIGINT NOT NULL DEFAULT 0, node_bandwidth BIGINT NOT NULL DEFAULT 0) ENGINE=InnoDB",
		"CREATE TABLE sshappy_traffic_batch (batch_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY, node_id INT NOT NULL, created_at BIGINT NOT NULL, KEY node_created_at (node_id, created_at)) ENGINE=InnoDB",
		"INSERT INTO ss_node (id) VALUES (116)",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	traffic := make([]TrafficDelta, 120)
	billed := make([]billedTrafficDelta, 120)
	for index := range traffic {
		userID := index + 1
		if _, err := db.Exec("INSERT INTO user (id) VALUES (?)", userID); err != nil {
			t.Fatal(err)
		}
		traffic[index] = TrafficDelta{UserID: userID, Upload: 10, Download: 20}
		billed[index] = billedTrafficDelta{
			TrafficDelta:   traffic[index],
			BilledUpload:   10,
			BilledDownload: 20,
			TrafficText:    "30.00B",
		}
	}
	database := &Database{db: db}
	node := Node{ID: 116, TrafficRate: 1}
	batchID := "0123456789abcdef0123456789abcdef"
	partialConn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := database.reportTrafficChunk(partialConn, node, trafficChunkID(batchID, node.ID, 0), billed[:trafficSQLBatchSize], time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := partialConn.Close(); err != nil {
		t.Fatal(err)
	}

	var waitGroup sync.WaitGroup
	errors := make(chan error, 4)
	for range 4 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			errors <- database.ReportTraffic(node, batchID, traffic)
		}()
	}
	waitGroup.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}

	var upload, download, logs, nodeBandwidth, markers int64
	if err := db.QueryRow("SELECT SUM(u), SUM(d) FROM user").Scan(&upload, &download); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM user_traffic_log").Scan(&logs); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT node_bandwidth FROM ss_node WHERE id = 116").Scan(&nodeBandwidth); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sshappy_traffic_batch").Scan(&markers); err != nil {
		t.Fatal(err)
	}
	if upload != 1200 || download != 2400 || logs != 120 || nodeBandwidth != 3600 || markers != 1 {
		t.Fatalf("upload=%d download=%d logs=%d nodeBandwidth=%d markers=%d", upload, download, logs, nodeBandwidth, markers)
	}
}
