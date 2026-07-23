package flyskyapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const (
	defaultTimeout       = 30 * time.Second
	defaultMaxBodyBytes  = 8 << 20
	defaultClientVersion = "development"
)

var (
	ErrCursorExpired    = errors.New("flysky node API cursor expired")
	ErrResponseTooLarge = errors.New("flysky node API response is too large")
)

type Config struct {
	BaseURL           string
	HTTPClient        *http.Client
	Timeout           time.Duration
	MaxBodyBytes      int64
	AllowInsecureHTTP bool
	ClientVersion     string
}

type Client struct {
	baseURL      *url.URL
	httpClient   *http.Client
	maxBodyBytes int64
	userAgent    string
}

type APIError struct {
	StatusCode int
	Code       string
	Retryable  bool
	RequestID  string
	RetryAfter string
}

func (e *APIError) Error() string {
	code := strings.TrimSpace(e.Code)
	if code == "" {
		code = "HTTP_ERROR"
	}
	return fmt.Sprintf("flysky node API: status %d (%s)", e.StatusCode, code)
}

func NewClient(config Config) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimSpace(config.BaseURL))
	if err != nil {
		return nil, fmt.Errorf("parse Flysky API base URL: %w", err)
	}
	if err := validateBaseURL(baseURL, config.AllowInsecureHTTP); err != nil {
		return nil, err
	}
	baseURL.Path = strings.TrimSuffix(baseURL.Path, "/")

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	clientCopy := *httpClient
	if config.Timeout > 0 {
		clientCopy.Timeout = config.Timeout
	} else if clientCopy.Timeout <= 0 {
		clientCopy.Timeout = defaultTimeout
	}
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	maxBodyBytes := config.MaxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultMaxBodyBytes
	}
	clientVersion := strings.TrimSpace(config.ClientVersion)
	if clientVersion == "" {
		clientVersion = defaultClientVersion
	}
	return &Client{
		baseURL:      baseURL,
		httpClient:   &clientCopy,
		maxBodyBytes: maxBodyBytes,
		userAgent:    "ssbad-flysky/" + clientVersion,
	}, nil
}

func (c *Client) Capabilities(ctx context.Context) (Capabilities, error) {
	return doJSON[Capabilities](ctx, c, http.MethodGet, "/api/node/v1/capabilities", "", nil)
}

func (c *Client) Enroll(ctx context.Context, enrollmentToken string, report CapabilityReport) (MachineCredential, error) {
	if strings.TrimSpace(enrollmentToken) == "" {
		return MachineCredential{}, errors.New("Flysky enrollment token is required")
	}
	return doJSON[MachineCredential](ctx, c, http.MethodPost, "/api/node/v1/enroll", "", EnrollmentRequest{
		CapabilityReport: report,
		EnrollmentToken:  enrollmentToken,
	})
}

func (c *Client) RotateCredential(ctx context.Context, accessToken string) (MachineCredential, error) {
	return doJSON[MachineCredential](ctx, c, http.MethodPost, "/api/node/v1/credentials/rotate", accessToken, struct{}{})
}

func (c *Client) ReportStatus(ctx context.Context, accessToken string, report StatusRequest) (RuntimeState, error) {
	return doJSON[RuntimeState](ctx, c, http.MethodPost, "/api/node/v1/status", accessToken, report)
}

func (c *Client) Snapshot(ctx context.Context, accessToken string) (Snapshot, error) {
	return doJSON[Snapshot](ctx, c, http.MethodGet, "/api/node/v1/snapshot", accessToken, nil)
}

func (c *Client) Changes(ctx context.Context, accessToken, cursor string) (Changes, error) {
	if strings.TrimSpace(cursor) == "" {
		return Changes{}, errors.New("Flysky change cursor is required")
	}
	endpoint := "/api/node/v1/changes?" + url.Values{"since": []string{cursor}}.Encode()
	changes, err := doJSON[Changes](ctx, c, http.MethodGet, endpoint, accessToken, nil)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusGone && apiErr.Code == "CURSOR_EXPIRED" {
		return Changes{}, errors.Join(ErrCursorExpired, apiErr)
	}
	return changes, err
}

func (c *Client) SubmitUsage(ctx context.Context, accessToken string, report UsageReport) (ReportReceipt, error) {
	return doJSON[ReportReceipt](ctx, c, http.MethodPost, "/api/node/v1/usage-reports", accessToken, report)
}

func (c *Client) SubmitAliveIPs(ctx context.Context, accessToken string, report AliveIPReport) (ReportReceipt, error) {
	return doJSON[ReportReceipt](ctx, c, http.MethodPost, "/api/node/v1/alive-ips", accessToken, report)
}

func doJSON[T any](ctx context.Context, client *Client, method, endpoint, accessToken string, requestBody any) (T, error) {
	var zero T
	if client == nil {
		return zero, errors.New("Flysky API client is nil")
	}
	if accessToken == "" && endpoint != "/api/node/v1/capabilities" && endpoint != "/api/node/v1/enroll" {
		return zero, errors.New("Flysky node access token is required")
	}

	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return zero, fmt.Errorf("encode Flysky API request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	requestURL := *client.baseURL
	requestURL.Path = path.Join(client.baseURL.Path, strings.SplitN(endpoint, "?", 2)[0])
	if queryIndex := strings.IndexByte(endpoint, '?'); queryIndex >= 0 {
		requestURL.RawQuery = endpoint[queryIndex+1:]
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if err != nil {
		return zero, fmt.Errorf("create Flysky API request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("User-Agent", client.userAgent)
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if accessToken != "" {
		request.Header.Set("Authorization", "Bearer "+accessToken)
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		return zero, fmt.Errorf("perform Flysky API request: %w", err)
	}
	defer response.Body.Close()
	data, err := readLimited(response.Body, client.maxBodyBytes)
	if err != nil {
		return zero, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return zero, decodeAPIError(response, data)
	}
	if err := requireJSON(response.Header.Get("Content-Type")); err != nil {
		return zero, err
	}

	var envelope successEnvelope[T]
	if err := decodeOneJSON(data, &envelope); err != nil {
		return zero, fmt.Errorf("decode Flysky API response: %w", err)
	}
	if !envelope.OK {
		return zero, errors.New("Flysky API returned an unsuccessful success response")
	}
	return envelope.Data, nil
}

type successEnvelope[T any] struct {
	OK   bool `json:"ok"`
	Data T    `json:"data"`
	Meta struct {
		RequestID string `json:"request_id"`
	} `json:"meta"`
}

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Retryable bool   `json:"retryable"`
	} `json:"error"`
	Meta struct {
		RequestID string `json:"request_id"`
	} `json:"meta"`
}

func decodeAPIError(response *http.Response, data []byte) error {
	apiErr := &APIError{
		StatusCode: response.StatusCode,
		Code:       http.StatusText(response.StatusCode),
		RetryAfter: response.Header.Get("Retry-After"),
	}
	var envelope errorEnvelope
	if err := decodeOneJSON(data, &envelope); err == nil {
		if strings.TrimSpace(envelope.Error.Code) != "" {
			apiErr.Code = envelope.Error.Code
		}
		apiErr.Retryable = envelope.Error.Retryable
		apiErr.RequestID = envelope.Meta.RequestID
	}
	return apiErr
}

func validateBaseURL(baseURL *url.URL, allowInsecureHTTP bool) error {
	if baseURL == nil || baseURL.Host == "" || !baseURL.IsAbs() {
		return errors.New("Flysky API base URL must be absolute")
	}
	if baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return errors.New("Flysky API base URL must not contain credentials, query, or fragment")
	}
	if baseURL.Scheme == "https" {
		return nil
	}
	if baseURL.Scheme != "http" || !allowInsecureHTTP || !isLoopbackHost(baseURL.Hostname()) {
		return errors.New("Flysky API base URL must use HTTPS; HTTP is allowed only for explicit loopback development")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func requireJSON(contentType string) error {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		return errors.New("Flysky API response content type is not application/json")
	}
	return nil
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read Flysky API response: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, ErrResponseTooLarge
	}
	return data, nil
}

func decodeOneJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
