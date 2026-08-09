package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Agent-Field/agentfield/control-plane/internal/config"
	"github.com/Agent-Field/agentfield/control-plane/internal/events"
	"github.com/Agent-Field/agentfield/control-plane/internal/services"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"

	"github.com/gin-gonic/gin"
)

const authorityToken = "authority-token-with-at-least-32-random-characters"

func TestNewRunAuthorityVerifierFailsClosedOnInvalidConfig(t *testing.T) {
	tests := []config.RunAuthorityConfig{
		{Enabled: true, BaseURL: "http://127.0.0.1:8080", ExpectedHomeID: "home-a"},
		{Enabled: true, BaseURL: "http://example.com", BearerToken: authorityToken, ExpectedHomeID: "home-a"},
		{Enabled: true, BaseURL: "http://127.0.0.1:8080", BearerToken: "changeme", ExpectedHomeID: "home-a"},
	}
	for _, cfg := range tests {
		if _, err := NewRunAuthorityVerifier(cfg); err == nil {
			t.Fatalf("expected invalid config to fail: %+v", cfg)
		}
	}
}

func TestRunAuthorityVerifierRequiresAuthenticatedMatchingEligibleView(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, authorityView("running", true, "home-a", "run-1", "worker-a"))
	}))
	defer server.Close()

	verifier := mustRunAuthorityVerifier(t, server.URL, 20*time.Millisecond)
	err := verifier.Verify(context.Background(), RunAuthorityRef{
		HomeID: "home-a", RunID: "run-1", LeaseOwner: "worker-a",
	})
	if err != nil {
		t.Fatalf("expected eligible authority view: %v", err)
	}
	if receivedAuth != "Bearer "+authorityToken {
		t.Fatalf("unexpected authorization header: %q", receivedAuth)
	}

	for _, ref := range []RunAuthorityRef{
		{HomeID: "home-b", RunID: "run-1", LeaseOwner: "worker-a"},
		{HomeID: "home-a", RunID: "run-1", LeaseOwner: "worker-b"},
	} {
		if err := verifier.Verify(context.Background(), ref); err == nil {
			t.Fatalf("expected mismatched authority reference to fail: %+v", ref)
		}
	}
}

func TestRunAuthorityVerifierRejectsStaleHeartbeat(t *testing.T) {
	heartbeatAt := time.Now().UTC().Add(-time.Minute)
	leaseExpiresAt := time.Now().UTC().Add(time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"schemaVersion":"deputies.run-authority.v1","homeId":"home-a","runId":"run-1","sessionId":"session-1","messageId":"message-1","attempt":1,"runnerType":"external","status":"running","leaseOwner":"worker-a","leaseExpiresAt":%q,"heartbeatAt":%q,"heartbeatAgeMs":60000,"terminalAt":null,"eligibleForDispatch":true,"reasonCodes":[]}`, leaseExpiresAt.Format(time.RFC3339Nano), heartbeatAt.Format(time.RFC3339Nano))
	}))
	defer server.Close()

	verifier := mustRunAuthorityVerifier(t, server.URL, 20*time.Millisecond)
	err := verifier.Verify(context.Background(), RunAuthorityRef{
		HomeID: "home-a", RunID: "run-1", LeaseOwner: "worker-a",
	})
	if err == nil || !strings.Contains(err.Error(), "heartbeat") {
		t.Fatalf("expected stale heartbeat rejection, got %v", err)
	}
}

func TestRunAuthorityVerifierPropagatesCancellation(t *testing.T) {
	var status atomic.Value
	status.Store("running")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := status.Load().(string)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, authorityView(current, current == "running", "home-a", "run-1", "worker-a"))
	}))
	defer server.Close()

	verifier := mustRunAuthorityVerifier(t, server.URL, 10*time.Millisecond)
	guarded, stop, err := verifier.Guard(context.Background(), RunAuthorityRef{
		HomeID: "home-a", RunID: "run-1", LeaseOwner: "worker-a",
	})
	if err != nil {
		t.Fatalf("guard admission failed: %v", err)
	}
	defer stop()
	status.Store("cancelled")

	select {
	case <-guarded.Done():
		if !errors.Is(context.Cause(guarded), ErrRunAuthorityRevoked) {
			t.Fatalf("unexpected cancellation cause: %v", context.Cause(guarded))
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("authority cancellation was not propagated")
	}
}

func TestExecuteHandlerRefusesDispatchWithoutEligibleOuterAuthority(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var agentCalls atomic.Int32
	agentServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		agentCalls.Add(1)
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer agentServer.Close()
	authorityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, authorityView("running", false, "home-a", "run-1", "worker-a"))
	}))
	defer authorityServer.Close()

	store := newTestExecutionStorage(&types.AgentNode{
		ID: "node-1", BaseURL: agentServer.URL, Reasoners: []types.ReasonerDefinition{{ID: "reasoner-a"}},
	})
	router := gin.New()
	router.POST(
		"/api/v1/execute/:target",
		ExecuteHandlerWithARDAndRunAuthority(
			store, services.NewFilePayloadStore(t.TempDir()), nil, time.Second, "", nil,
			mustRunAuthorityVerifier(t, authorityServer.URL, 20*time.Millisecond),
		),
	)
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/execute/node-1.reasoner-a",
		strings.NewReader(`{"input":{},"authority":{"home_id":"home-a","run_id":"run-1","lease_owner":"worker-a"}}`),
	)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Run-ID", "run-1")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, req)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected fail-closed response, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "run_authority_unavailable") {
		t.Fatalf("missing stable authority error code: %s", response.Body.String())
	}
	if agentCalls.Load() != 0 {
		t.Fatalf("agent was called despite denied authority: %d", agentCalls.Load())
	}
}

func TestExecuteHandlerCancelsExecutionWhenRunAuthorityIsRevoked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var authorityCalls atomic.Int32
	authorityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		eligible := authorityCalls.Add(1) == 1
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, authorityView("running", eligible, "home-a", "run-1", "worker-a"))
	}))
	defer authorityServer.Close()

	executionID := make(chan string, 1)
	agentServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		executionID <- r.Header.Get("X-Execution-ID")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer agentServer.Close()
	cancelEvents := events.GlobalExecutionEventBus.Subscribe("run-authority-revocation-test")
	defer events.GlobalExecutionEventBus.Unsubscribe("run-authority-revocation-test")

	store := newTestExecutionStorage(&types.AgentNode{
		ID: "node-1", BaseURL: agentServer.URL, Reasoners: []types.ReasonerDefinition{{ID: "reasoner-a"}},
	})
	router := gin.New()
	router.POST("/execute/:target", ExecuteHandlerWithARDAndRunAuthority(
		store, services.NewFilePayloadStore(t.TempDir()), nil, time.Second, "", func() config.ARDConfig { return config.ARDConfig{} },
		mustRunAuthorityVerifier(t, authorityServer.URL, 10*time.Millisecond),
	))
	req := httptest.NewRequest(http.MethodPost, "/execute/node-1.reasoner-a", strings.NewReader(
		`{"input":{"value":1},"authority":{"home_id":"home-a","run_id":"run-1","lease_owner":"worker-a"}}`,
	))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Run-ID", "run-1")
	response := httptest.NewRecorder()

	requestDone := make(chan struct{})
	go func() {
		router.ServeHTTP(response, req)
		close(requestDone)
	}()

	var id string
	select {
	case id = <-executionID:
	case <-time.After(time.Second):
		t.Fatal("agent was not dispatched")
	}
	cancelled := false
	deadline := time.After(time.Second)
	for !cancelled {
		select {
		case event := <-cancelEvents:
			cancelled = event.Type == events.ExecutionCancelledEvent && event.ExecutionID == id
		case <-deadline:
			t.Fatalf("execution cancellation event was not published after authority revocation; authority checks=%d", authorityCalls.Load())
		}
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("execute handler did not return after authority revocation")
	}
	record, err := store.GetExecutionRecord(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if record == nil || record.Status != types.ExecutionStatusCancelled {
		t.Fatalf("expected cancelled execution record, got %+v", record)
	}
}

func TestExecuteAsyncMonitorsAuthorityAfterAgentAcceptance(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var authorityCalls atomic.Int32
	authorityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		eligible := authorityCalls.Add(1) <= 3
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, authorityView("running", eligible, "home-a", "run-1", "worker-a"))
	}))
	defer authorityServer.Close()

	executionID := make(chan string, 1)
	agentServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		executionID <- r.Header.Get("X-Execution-ID")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer agentServer.Close()
	cancelEvents := events.GlobalExecutionEventBus.Subscribe("async-run-authority-revocation-test")
	defer events.GlobalExecutionEventBus.Unsubscribe("async-run-authority-revocation-test")

	store := newTestExecutionStorage(&types.AgentNode{
		ID: "node-1", BaseURL: agentServer.URL, Reasoners: []types.ReasonerDefinition{{ID: "reasoner-a"}},
	})
	router := gin.New()
	router.POST("/execute/async/:target", ExecuteAsyncHandlerWithRunAuthority(
		store, services.NewFilePayloadStore(t.TempDir()), nil, time.Second, "",
		mustRunAuthorityVerifier(t, authorityServer.URL, 10*time.Millisecond),
	))
	req := httptest.NewRequest(http.MethodPost, "/execute/async/node-1.reasoner-a", strings.NewReader(
		`{"input":{"value":1},"authority":{"home_id":"home-a","run_id":"run-1","lease_owner":"worker-a"}}`,
	))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Run-ID", "run-1")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	if response.Code != http.StatusAccepted {
		t.Fatalf("expected accepted response, got %d: %s", response.Code, response.Body.String())
	}

	var id string
	select {
	case id = <-executionID:
	case <-time.After(time.Second):
		t.Fatal("queued execution was not dispatched")
	}
	deadline := time.After(time.Second)
	for {
		select {
		case event := <-cancelEvents:
			if event.Type == events.ExecutionCancelledEvent && event.ExecutionID == id {
				record, err := store.GetExecutionRecord(context.Background(), id)
				if err != nil {
					t.Fatal(err)
				}
				if record == nil || record.Status != types.ExecutionStatusCancelled {
					t.Fatalf("expected cancelled queued execution, got %+v", record)
				}
				return
			}
		case <-deadline:
			t.Fatalf("queued execution authority was not monitored after acceptance; authority checks=%d", authorityCalls.Load())
		}
	}
}

func TestExecuteAsyncIsIdempotentForOneOuterAuthorityRun(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var agentCalls atomic.Int32
	agentServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		agentCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer agentServer.Close()
	authorityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, authorityView("running", true, "home-a", "run-1", "worker-a"))
	}))
	defer authorityServer.Close()

	store := newTestExecutionStorage(&types.AgentNode{
		ID: "node-1", BaseURL: agentServer.URL, Reasoners: []types.ReasonerDefinition{{ID: "reasoner-a"}},
	})
	router := gin.New()
	router.POST("/execute/async/:target", ExecuteAsyncHandlerWithRunAuthority(
		store, services.NewFilePayloadStore(t.TempDir()), nil, time.Second, "",
		mustRunAuthorityVerifier(t, authorityServer.URL, 20*time.Millisecond),
	))

	responses := make([]*httptest.ResponseRecorder, 2)
	for index := range responses {
		req := httptest.NewRequest(http.MethodPost, "/execute/async/node-1.reasoner-a", strings.NewReader(
			`{"input":{"value":1},"authority":{"home_id":"home-a","run_id":"run-1","lease_owner":"worker-a"}}`,
		))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Run-ID", "run-1")
		responses[index] = httptest.NewRecorder()
		router.ServeHTTP(responses[index], req)
		if responses[index].Code != http.StatusAccepted {
			t.Fatalf("request %d was not accepted: %d %s", index+1, responses[index].Code, responses[index].Body.String())
		}
	}

	firstID := responses[0].Header().Get("X-Execution-ID")
	if firstID == "" || responses[1].Header().Get("X-Execution-ID") != firstID {
		t.Fatalf("authority replay changed execution identity: %q then %q", firstID, responses[1].Header().Get("X-Execution-ID"))
	}
	if responses[1].Header().Get("X-AgentField-Authority-Replay") != "true" {
		t.Fatalf("second response did not identify the authority replay")
	}
	deadline := time.Now().Add(time.Second)
	for agentCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(25 * time.Millisecond)
	if agentCalls.Load() != 1 {
		t.Fatalf("expected exactly one AgentField effect, got %d", agentCalls.Load())
	}
}

func mustRunAuthorityVerifier(t *testing.T, baseURL string, pollInterval time.Duration) *RunAuthorityVerifier {
	t.Helper()
	verifier, err := NewRunAuthorityVerifier(config.RunAuthorityConfig{
		Enabled: true, BaseURL: baseURL, BearerToken: authorityToken, ExpectedHomeID: "home-a",
		RequestTimeout: time.Second, PollInterval: pollInterval, HeartbeatMaxAge: 30 * time.Second, ClockSkew: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}
	return verifier
}

func authorityView(status string, eligible bool, homeID, runID, leaseOwner string) string {
	heartbeatAt := time.Now().UTC()
	leaseExpiresAt := heartbeatAt.Add(time.Hour)
	return fmt.Sprintf(`{
			"schemaVersion":"deputies.run-authority.v1",
			"homeId":%q,"runId":%q,"sessionId":"session-1","messageId":"message-1",
			"attempt":1,"runnerType":"external","status":%q,"leaseOwner":%q,
			"leaseExpiresAt":%q,"heartbeatAt":%q,
			"heartbeatAgeMs":0,"terminalAt":null,"eligibleForDispatch":%t,"reasonCodes":[]
		}`, homeID, runID, status, leaseOwner, leaseExpiresAt.Format(time.RFC3339Nano), heartbeatAt.Format(time.RFC3339Nano), eligible)
}
