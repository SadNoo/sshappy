package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerAuthMiddleware(t *testing.T) {
	handler := newBearerAuthMiddleware("test-token")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	tests := []struct {
		name   string
		header string
		status int
	}{
		{name: "missing", status: http.StatusUnauthorized},
		{name: "wrong scheme", header: "Basic test-token", status: http.StatusUnauthorized},
		{name: "wrong token", header: "Bearer wrong-token", status: http.StatusUnauthorized},
		{name: "valid", header: "Bearer test-token", status: http.StatusNoContent},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if test.header != "" {
				req.Header.Set("Authorization", test.header)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != test.status {
				t.Fatalf("status = %d, want %d", rr.Code, test.status)
			}
		})
	}
}

func TestJoinPatternPath(t *testing.T) {
	for _, c := range []struct {
		elem []string
		want string
	}{
		{[]string{}, ""},
		{[]string{""}, ""},
		{[]string{"a"}, "a"},
		{[]string{"/"}, "/"},
		{[]string{"/a"}, "/a"},
		{[]string{"a/"}, "a/"},
		{[]string{"/a/"}, "/a/"},
		{[]string{"", "b"}, "b"},
		{[]string{"", "/b"}, "/b"},
		{[]string{"", "b/"}, "b/"},
		{[]string{"", "/b/"}, "/b/"},
		{[]string{"a", "b"}, "a/b"},
		{[]string{"a", "/b"}, "a/b"},
		{[]string{"a", "b/"}, "a/b/"},
		{[]string{"a", "/b/"}, "a/b/"},
		{[]string{"/", "b"}, "/b"},
		{[]string{"/", "/b"}, "/b"},
		{[]string{"/", "b/"}, "/b/"},
		{[]string{"/", "/b/"}, "/b/"},
		{[]string{"/a", "b"}, "/a/b"},
		{[]string{"/a", "/b"}, "/a/b"},
		{[]string{"/a", "b/"}, "/a/b/"},
		{[]string{"/a", "/b/"}, "/a/b/"},
		{[]string{"a/", "b"}, "a/b"},
		{[]string{"a/", "/b"}, "a/b"},
		{[]string{"a/", "b/"}, "a/b/"},
		{[]string{"a/", "/b/"}, "a/b/"},
		{[]string{"/a/", "b"}, "/a/b"},
		{[]string{"/a/", "/b"}, "/a/b"},
		{[]string{"/a/", "b/"}, "/a/b/"},
		{[]string{"/a/", "/b/"}, "/a/b/"},
	} {
		if got := joinPatternPath(c.elem...); got != c.want {
			t.Errorf("joinPatternPath(%#v) = %q; want %q", c.elem, got, c.want)
		}
	}
}
