package sstest

import (
	"context"
	"fmt"
	"log"
	"time"
)

var processStartedAt = time.Now()

func Run(ctx context.Context, config Config) error {
	if config.NodeID <= 0 {
		return fmt.Errorf("node_id/NODE_ID must be set")
	}
	db, err := OpenDatabase(config)
	if err != nil {
		return err
	}
	defer db.Close()

	state := NewRuntimeState()
	server := NewServer(config, state)
	node, err := syncOnce(db, server, state, config, true)
	if err != nil {
		return err
	}
	go func() {
		if err := server.Serve(ctx); err != nil && ctx.Err() == nil {
			log.Printf("server stopped: %v", err)
		}
	}()

	syncTicker := time.NewTicker(time.Duration(config.SyncIntervalSeconds) * time.Second)
	defer syncTicker.Stop()
	trafficTicker := time.NewTicker(time.Duration(config.TrafficReportSeconds) * time.Second)
	defer trafficTicker.Stop()
	nodeTicker := time.NewTicker(time.Duration(config.NodeReportSeconds) * time.Second)
	defer nodeTicker.Stop()
	aliveTicker := time.NewTicker(time.Duration(config.AliveIPReportSeconds) * time.Second)
	defer aliveTicker.Stop()
	onlineWindow := onlineCountWindow(config)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-syncTicker.C:
			loaded, err := db.LoadNode()
			if err != nil {
				log.Printf("sync load node failed: %v", err)
				continue
			}
			users, err := db.LoadUsers(loaded)
			if err != nil {
				log.Printf("sync load users failed: %v", err)
				continue
			}
			if err := server.Apply(loaded, users); err != nil {
				log.Printf("apply runtime failed: %v", err)
				continue
			}
			node = loaded
		case <-trafficTicker.C:
			traffic := state.SnapshotTraffic()
			if err := db.ReportTraffic(node, traffic); err != nil {
				log.Printf("traffic report failed: %v", err)
			} else {
				log.Printf("traffic reported: users=%d", len(traffic))
			}
		case <-nodeTicker.C:
			online := state.OnlineUserCount(onlineWindow)
			if err := db.ReportNodeStatus(node, online); err != nil {
				log.Printf("node status report failed: %v", err)
			} else {
				log.Printf("node status reported: online=%d", online)
			}
		case <-aliveTicker.C:
			alive := state.SnapshotAliveIPs()
			records := 0
			for _, ips := range alive {
				records += len(ips)
			}
			if err := db.ReportAliveIPs(node, alive); err != nil {
				log.Printf("alive ips report failed: %v", err)
			} else {
				log.Printf("alive ips reported: users=%d records=%d", len(alive), records)
			}
		}
	}
}

func syncOnce(db *Database, server *Server, state *RuntimeState, config Config, report bool) (NodeInfo, error) {
	node, err := db.LoadNode()
	if err != nil {
		return node, err
	}
	users, err := db.LoadUsers(node)
	if err != nil {
		return node, err
	}
	if err := server.Apply(node, users); err != nil {
		return node, err
	}
	if report {
		traffic := state.SnapshotTraffic()
		if err := db.ReportTraffic(node, traffic); err != nil {
			return node, err
		}
		log.Printf("traffic reported: users=%d", len(traffic))
		online := state.OnlineUserCount(onlineCountWindow(config))
		if err := db.ReportNodeStatus(node, online); err != nil {
			return node, err
		}
		log.Printf("node status reported: online=%d", online)
		alive := state.SnapshotAliveIPs()
		if err := db.ReportAliveIPs(node, alive); err != nil {
			return node, err
		}
		log.Printf("alive ips reported: users=%d records=0", len(alive))
	}
	return node, nil
}

func onlineCountWindow(config Config) time.Duration {
	seconds := config.NodeReportSeconds
	if config.AliveIPReportSeconds > seconds {
		seconds = config.AliveIPReportSeconds
	}
	if config.SyncIntervalSeconds > seconds {
		seconds = config.SyncIntervalSeconds
	}
	return time.Duration(seconds*2+30) * time.Second
}
