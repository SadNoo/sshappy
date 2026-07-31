package panel

import (
	"errors"
	"sort"
	"strings"
	"testing"
)

func TestTrafficBatchStatements(t *testing.T) {
	batch := []billedTrafficDelta{
		{TrafficDelta: TrafficDelta{UserID: 7, Upload: 10, Download: 20}, BilledUpload: 15, BilledDownload: 30, TrafficText: "45.00B"},
		{TrafficDelta: TrafficDelta{UserID: 9, Upload: 30, Download: 40}, BilledUpload: 45, BilledDownload: 60, TrafficText: "105.00B"},
	}
	updateQuery, updateArgs := userTrafficUpdateStatement(batch, 123)
	if strings.Count(updateQuery, "?") != len(updateArgs) || len(updateArgs) != 11 {
		t.Fatalf("update placeholders=%d args=%d query=%q", strings.Count(updateQuery, "?"), len(updateArgs), updateQuery)
	}
	if !strings.Contains(updateQuery, "CASE id") || !strings.Contains(updateQuery, "WHERE id IN (?,?)") {
		t.Fatalf("unexpected update query: %s", updateQuery)
	}

	logQuery, logArgs := trafficLogInsertStatement(batch, Node{ID: 3, TrafficRate: 1.5}, 123)
	if strings.Count(logQuery, "?") != len(logArgs) || len(logArgs) != 14 {
		t.Fatalf("log placeholders=%d args=%d query=%q", strings.Count(logQuery, "?"), len(logArgs), logQuery)
	}
}

func TestNodeAuthorizationErrorsAreClassified(t *testing.T) {
	_, err := validateLoadedNode(Node{ID: 116, Sort: 14}, 100, 100)
	if !errors.Is(err, ErrNodeNotAuthorized) {
		t.Fatalf("bandwidth limit error was not authoritative: %v", err)
	}
	_, err = validateLoadedNode(Node{ID: 116, Sort: 13}, 0, 0)
	if !errors.Is(err, ErrNodeNotAuthorized) {
		t.Fatalf("invalid node type error was not authoritative: %v", err)
	}
	_, err = validateLoadedNode(Node{ID: 116, Sort: 14, Server: "example.com;443;sensitive-server-key"}, 0, 0)
	if !errors.Is(err, ErrNodeNotAuthorized) || strings.Contains(err.Error(), "sensitive-server-key") {
		t.Fatalf("invalid server key error was not safely classified: %v", err)
	}
}

func TestParseSSSinglePortRejectsInvalidPorts(t *testing.T) {
	for _, value := range []string{"example.com;-1;key", "example.com;65536;key"} {
		if _, _, _, err := parseSSSinglePort(value); err == nil {
			t.Fatalf("parseSSSinglePort(%q) accepted an invalid port", value)
		}
	}
}

func TestTrafficChunkIDsAreStableAndDistinct(t *testing.T) {
	first := trafficChunkID("0123456789abcdef0123456789abcdef", 116, 0)
	again := trafficChunkID("0123456789abcdef0123456789abcdef", 116, 0)
	second := trafficChunkID("0123456789abcdef0123456789abcdef", 116, 1)
	if len(first) != 32 || first != again || first == second {
		t.Fatalf("chunk IDs first=%q again=%q second=%q", first, again, second)
	}
}

func TestTrafficBatchLockNamesAreStableAndDistinct(t *testing.T) {
	first := trafficBatchLockName(116, "0123456789abcdef0123456789abcdef")
	again := trafficBatchLockName(116, "0123456789abcdef0123456789abcdef")
	otherNode := trafficBatchLockName(117, "0123456789abcdef0123456789abcdef")
	if len(first) > 64 || first != again || first == otherNode {
		t.Fatalf("lock names first=%q again=%q otherNode=%q", first, again, otherNode)
	}
}

func TestTrafficBatchSortOrder(t *testing.T) {
	traffic := mergeTrafficDeltas([]TrafficDelta{{UserID: 9}, {UserID: 3}, {UserID: 7}})
	sort.Slice(traffic, func(i, j int) bool { return traffic[i].UserID < traffic[j].UserID })
	for index, want := range []int{3, 7, 9} {
		if traffic[index].UserID != want {
			t.Fatalf("traffic[%d].UserID = %d, want %d", index, traffic[index].UserID, want)
		}
	}
}

func TestAliveIPBatchStatement(t *testing.T) {
	records := []aliveIPRecord{{UserID: 7, IP: "192.0.2.1"}, {UserID: 9, IP: "2001:db8::1"}}
	query, args := aliveIPInsertStatement(records, 3, 123)
	if strings.Count(query, "?") != len(args) || len(args) != 8 {
		t.Fatalf("placeholders=%d args=%d query=%q", strings.Count(query, "?"), len(args), query)
	}
	if !strings.HasSuffix(query, "(?,?,?,?),(?,?,?,?)") {
		t.Fatalf("unexpected alive IP query: %s", query)
	}
}
