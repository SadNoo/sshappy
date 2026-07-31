package service

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	shadowsocks "github.com/database64128/shadowsocks-go"
	"go.uber.org/zap"
)

type managerTestService struct {
	name  string
	start func(context.Context) error
	stop  func() error
}

func (s managerTestService) ZapField() zap.Field {
	return zap.String("testService", s.name)
}

func (s managerTestService) Start(ctx context.Context) error {
	return s.start(ctx)
}

func (s managerTestService) Stop() error {
	return s.stop()
}

func TestManagerStopsServicesInReverseOrderAndReportsStopErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	started := 0
	allStarted := make(chan struct{})
	stopped := make([]string, 0, 3)
	services := make([]managerTestService, 0, 3)
	for _, name := range []string{"first", "second", "third"} {
		name := name
		services = append(services, managerTestService{
			name: name,
			start: func(context.Context) error {
				mu.Lock()
				defer mu.Unlock()
				started++
				if started == 3 {
					close(allStarted)
				}
				return nil
			},
			stop: func() error {
				mu.Lock()
				stopped = append(stopped, name)
				mu.Unlock()
				if name == "second" {
					return errors.New("stop failed")
				}
				return nil
			},
		})
	}

	manager := &Manager{
		services: []shadowsocks.Service{services[0], services[1], services[2]},
		logger:   zap.NewNop(),
	}
	result := make(chan bool, 1)
	go func() { result <- manager.Run(ctx) }()
	<-allStarted
	cancel()
	if ok := <-result; ok {
		t.Fatal("Run returned true after a service Stop failure")
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"third", "second", "first"}
	if !slices.Equal(stopped, want) {
		t.Fatalf("stop order = %v, want %v", stopped, want)
	}
}
