package panel

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
)

var runtimeSessionTestSource = netip.MustParseAddrPort("203.0.113.1:12345")
var runtimeSessionTestTarget = conn.AddrFromIPAndPort(netip.MustParseAddr("203.0.113.2"), 1023)

func beginTestRuntimeSession(t *testing.T, runtime *Runtime) (context.Context, func()) {
	t.Helper()
	ctx, end, accepted := runtime.BeginSession(t.Context(), "tcp", "7", runtimeSessionTestSource, runtimeSessionTestTarget)
	if !accepted || end == nil {
		t.Fatal("authorized session registration was rejected")
	}
	return ctx, end
}

func assertSessionCanceled(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("session context was not canceled synchronously")
	}
}

func TestRuntimeSessionSurvivesEquivalentPolicyRefresh(t *testing.T) {
	runtime := NewRuntime(NewState())
	user := User{ID: 7, ForbiddenPort: "25", UserKey: []byte{1, 2, 3}}
	runtime.ReplaceUsers([]User{user})
	ctx, end := beginTestRuntimeSession(t, runtime)
	defer end()

	runtime.ReplaceUsers([]User{user})
	select {
	case <-ctx.Done():
		t.Fatal("equivalent policy refresh canceled the session")
	default:
	}
}

func TestRuntimeSessionCanceledOnAuthorizationChanges(t *testing.T) {
	tests := []struct {
		name string
		next []User
	}{
		{name: "user removed"},
		{name: "policy changed", next: []User{{ID: 7, ForbiddenPort: "25,53", UserKey: []byte{1}}}},
		{name: "key changed", next: []User{{ID: 7, ForbiddenPort: "25", UserKey: []byte{2}}}},
		{name: "policy became invalid", next: []User{{ID: 7, ForbiddenPort: "bad", UserKey: []byte{1}}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := NewRuntime(NewState())
			runtime.ReplaceUsers([]User{{ID: 7, ForbiddenPort: "25", UserKey: []byte{1}}})
			ctx, end := beginTestRuntimeSession(t, runtime)
			defer end()

			runtime.ReplaceUsers(test.next)
			assertSessionCanceled(t, ctx)
		})
	}
}

func TestRuntimeBeginSessionRejectsCurrentPolicy(t *testing.T) {
	runtime := NewRuntime(NewState())
	runtime.ReplaceUsers([]User{{ID: 7, ForbiddenPort: "1023"}})
	_, end, accepted := runtime.BeginSession(t.Context(), "tcp", "7", runtimeSessionTestSource, runtimeSessionTestTarget)
	if accepted || end != nil {
		t.Fatalf("forbidden session registration = (accepted=%v, end=%v)", accepted, end != nil)
	}

	runtime.ReplaceUsers(nil)
	_, end, accepted = runtime.BeginSession(t.Context(), "tcp", "7", runtimeSessionTestSource, runtimeSessionTestTarget)
	if accepted || end != nil {
		t.Fatalf("removed user registration = (accepted=%v, end=%v)", accepted, end != nil)
	}
}

func TestRuntimeBeginSessionReplaceRace(t *testing.T) {
	for range 500 {
		runtime := NewRuntime(NewState())
		runtime.ReplaceUsers([]User{{ID: 7, UserKey: []byte{1}}})
		start := make(chan struct{})
		var sessionCtx context.Context
		var end func()
		var accepted bool
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			sessionCtx, end, accepted = runtime.BeginSession(t.Context(), "tcp", "7", runtimeSessionTestSource, runtimeSessionTestTarget)
		}()
		go func() {
			defer wg.Done()
			<-start
			runtime.ReplaceUsers(nil)
		}()
		close(start)
		wg.Wait()
		if accepted {
			assertSessionCanceled(t, sessionCtx)
			end()
		} else if end != nil {
			t.Fatal("rejected registration returned an end function")
		}
	}
}
