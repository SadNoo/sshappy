package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	shadowsocks "github.com/database64128/shadowsocks-go"
	"go.uber.org/zap"
)

type runtimeFailureTestService struct {
	started         chan struct{}
	failures        chan error
	startContext    context.Context
	stopCalls       atomic.Int64
	stopSawCanceled atomic.Bool
}

func newRuntimeFailureTestService() *runtimeFailureTestService {
	return &runtimeFailureTestService{
		started:  make(chan struct{}),
		failures: make(chan error, 1),
	}
}

func (*runtimeFailureTestService) ZapField() zap.Field {
	return zap.String("testService", "runtime-failure")
}

func (s *runtimeFailureTestService) Start(ctx context.Context) error {
	s.startContext = ctx
	close(s.started)
	return nil
}

func (s *runtimeFailureTestService) Stop() error {
	s.stopCalls.Add(1)
	s.stopSawCanceled.Store(s.startContext.Err() != nil)
	return nil
}

func (s *runtimeFailureTestService) runtimeFailures() <-chan error {
	return s.failures
}

func TestManagerStopsAllServicesOnRuntimeFailure(t *testing.T) {
	failingService := newRuntimeFailureTestService()
	siblingService := newRuntimeFailureTestService()
	manager := &Manager{
		services: []shadowsocks.Service{failingService, siblingService},
		logger:   zap.NewNop(),
	}
	result := make(chan bool, 1)
	go func() {
		result <- manager.Run(context.Background())
	}()

	for index, service := range []*runtimeFailureTestService{failingService, siblingService} {
		select {
		case <-service.started:
		case <-time.After(time.Second):
			t.Fatalf("service %d did not start", index)
		}
	}

	errRuntime := errors.New("listener failed after startup")
	failingService.failures <- errRuntime

	select {
	case ok := <-result:
		if ok {
			t.Fatal("Manager.Run returned true after a runtime failure")
		}
	case <-time.After(time.Second):
		t.Fatal("Manager.Run did not stop after a runtime failure")
	}
	for index, service := range []*runtimeFailureTestService{failingService, siblingService} {
		if got := service.stopCalls.Load(); got != 1 {
			t.Fatalf("service %d Stop calls = %d, want 1", index, got)
		}
		if !service.stopSawCanceled.Load() {
			t.Fatalf("service %d context was not canceled before Stop", index)
		}
	}
}

func TestManagerNormalCancellationRemainsSuccessful(t *testing.T) {
	service := newRuntimeFailureTestService()
	manager := &Manager{
		services: []shadowsocks.Service{service},
		logger:   zap.NewNop(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan bool, 1)
	go func() {
		result <- manager.Run(ctx)
	}()

	select {
	case <-service.started:
	case <-time.After(time.Second):
		t.Fatal("service did not start")
	}
	cancel()

	select {
	case ok := <-result:
		if !ok {
			t.Fatal("Manager.Run returned false after normal cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("Manager.Run did not stop after cancellation")
	}
	if got := service.stopCalls.Load(); got != 1 {
		t.Fatalf("Stop calls = %d, want 1", got)
	}
	if !service.stopSawCanceled.Load() {
		t.Fatal("service context was not canceled before Stop")
	}
}
