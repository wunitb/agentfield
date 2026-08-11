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
		{Enabled: true, BaseURL: "http://127.0.0.1:8080", BearerToken: authorityToken, ExpectedHomeID: "home-a", ExpectedRunnerType: "external", RequestTimeout: time.Second, PollInterval: time.Second, HeartbeatMaxAge: time.Second, ClockSkew: time.Second},
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
		HomeID: "home-a", RunID: "run-1", LeaseOwner: "worker-a", Attempt: 1,
	})
	if err != nil {
		t.Fatalf("expected eligible authority view: %v", err)
	}
	if receivedAuth != "Bearer "+authorityToken {
		t.Fatalf("unexpected authorization header: %q", receivedAuth)
	}

	for _, ref := range []RunAuthorityRef{
		{HomeID: "home-b", RunID: "run-1", LeaseOwner: "worker-a", Attempt: 1},
		{HomeID: "home-a", RunID: "run-1", LeaseOwner: "worker-b", Attempt: 1},
	} {
		if err := verifier.Verify(context.Background(), ref); err == nil {
			t.Fatalf("expected mismatched authority reference to fail: %+v", ref)
		}
	}
}

func TestRunAuthorityVerifierRejectsWrongDeputiesRunnerType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		view := strings.Replace(authorityView("running", true, "home-a", "run-1", "worker-a"), `"runnerType":"agentfield"`, `"runnerType":"external"`, 1)
		fmt.Fprint(w, view)
	}))
	defer server.Close()

	verifier := mustRunAuthorityVerifier(t, server.URL, 20*time.Millisecond)
	err := verifier.Verify(context.Background(), RunAuthorityRef{HomeID: "home-a", RunID: "run-1", LeaseOwner: "worker-a", Attempt: 1})
	if err == nil || !strings.Contains(err.Error(), "runner type") {
		t.Fatalf("expected runner type rejection, got %v", err)
	}
}

func TestRunAuthorityVerifierRejectsStaleHeartbeat(t *testing.T) {
	heartbeatAt := time.Now().UTC().Add(-time.Minute)
	leaseExpiresAt := time.Now().UTC().Add(time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"schemaVersion":"deputies.run-authority.v1","homeId":"home-a","runId":"run-1","sessionId":"session-1","messageId":"message-1","attempt":1,"runnerType":"agentfield","status":"running","leaseOwner":"worker-a","leaseExpiresAt":%q,"heartbeatAt":%q,"heartbeatAgeMs":60000,"terminalAt":null,"eligibleForDispatch":true,"reasonCodes":[]}`, leaseExpiresAt.Format(time.RFC3339Nano), heartbeatAt.Format(time.RFC3339Nano))
	}))
	defer server.Close()

	verifier := mustRunAuthorityVerifier(t, server.URL, 20*time.Millisecond)
	err := verifier.Verify(context.Background(), RunAuthorityRef{
		HomeID: "home-a", RunID: "run-1", LeaseOwner: "worker-a", Attempt: 1,
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
		HomeID: "home-a", RunID: "run-1", LeaseOwner: "worker-a", Attempt: 1,
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
		strings.NewReader(`{"input":{},"authority":{"home_id":"home-a","run_id":"run-1","lease_owner":"worker-a","attempt":1}}`),
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

func TestExecuteAsyncVerifiesAuthorityBeforeDeterministicRecordCreation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authorityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, authorityView("running", true, "home-a", "run-1", "worker-a"))
	}))
	defer authorityServer.Close()
	agentServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	defer agentServer.Close()

	store := newTestExecutionStorage(&types.AgentNode{ID: "node-1", BaseURL: agentServer.URL, Reasoners: []types.ReasonerDefinition{{ID: "reasoner-a"}}})
	router := gin.New()
	router.POST("/execute/async/:target", ExecuteAsyncHandlerWithRunAuthority(store, services.NewFilePayloadStore(t.TempDir()), nil, time.Second, "", mustRunAuthorityVerifier(t, authorityServer.URL, 20*time.Millisecond)))

	request := func(leaseOwner string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"input":{},"authority":{"home_id":"home-a","run_id":"run-1","lease_owner":%q,"attempt":1}}`, leaseOwner)
		req := httptest.NewRequest(http.MethodPost, "/execute/async/node-1.reasoner-a", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Run-ID", "run-1")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}

	if response := request("worker-b"); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("wrong lease was not denied: %d %s", response.Code, response.Body.String())
	}
	if records, _ := store.QueryExecutionRecords(context.Background(), types.ExecutionFilter{}); len(records) != 0 {
		t.Fatalf("denied authority poisoned durable execution identity: %+v", records)
	}
	if response := request("worker-a"); response.Code != http.StatusAccepted {
		t.Fatalf("valid lease was not accepted after denied request: %d %s", response.Code, response.Body.String())
	}
}

func TestExecuteHandlerCancelsExecutionWhenRunAuthorityIsRevoked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var authorityCalls atomic.Int32
	authorityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		eligible := authorityCalls.Add(1) <= 2
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
		`{"input":{"value":1},"authority":{"home_id":"home-a","run_id":"run-1","lease_owner":"worker-a","attempt":1}}`,
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
		`{"input":{"value":1},"authority":{"home_id":"home-a","run_id":"run-1","lease_owner":"worker-a","attempt":1}}`,
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
			`{"input":{"value":1},"authority":{"home_id":"home-a","run_id":"run-1","lease_owner":"worker-a","attempt":1}}`,
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

func TestRevocationPreventsLaterSuccessAndPersistsBinding(t *testing.T) {
	store := newTestExecutionStorage(nil)
	ref := &RunAuthorityRef{HomeID: "home-a", RunID: "run-1", LeaseOwner: "worker-a", Attempt: 1}
	exec := &types.Execution{ExecutionID: "exec-race", RunID: "run-1", Status: types.ExecutionStatusRunning, StartedAt: time.Now().UTC(), CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	bindExecutionAuthority(exec, ref)
	if err := store.CreateExecutionRecord(context.Background(), exec); err != nil {
		t.Fatal(err)
	}
	controller := newExecutionController(store, nil, nil, time.Second, "")
	plan := &preparedExecution{exec: exec, runAuthority: ref}
	if err := controller.cancelRevokedRunAuthority(context.Background(), plan, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := controller.completeExecution(context.Background(), plan, []byte(`{"ok":true}`), time.Millisecond); err == nil {
		t.Fatal("success overwrote revoked execution")
	}
	record, _ := store.GetExecutionRecord(context.Background(), exec.ExecutionID)
	if record.Status != types.ExecutionStatusCancelled || record.AuthorityRevokedAt == nil || !sameAuthorityExecution(record, exec) {
		t.Fatalf("revocation or authority binding was not durable: %+v", record)
	}
}

func TestTerminalExecutionWritesAreImmutableAndIdempotent(t *testing.T) {
	store := newTestExecutionStorage(nil)
	exec := &types.Execution{ExecutionID: "exec-terminal", RunID: "run-1", Status: types.ExecutionStatusRunning, StartedAt: time.Now().UTC()}
	if err := store.CreateExecutionRecord(context.Background(), exec); err != nil {
		t.Fatal(err)
	}
	controller := newExecutionController(store, nil, nil, time.Second, "")
	now := time.Now().UTC()
	desired := terminalExecutionMutation{status: string(types.ExecutionStatusSucceeded), result: []byte(`{"ok":true}`), completedAt: now, durationMS: 1, compareDuration: true}
	if _, transitioned, err := controller.writeTerminalExecution(context.Background(), exec.ExecutionID, desired); err != nil || !transitioned {
		t.Fatalf("first terminal transition failed: transitioned=%t err=%v", transitioned, err)
	}
	if _, transitioned, err := controller.writeTerminalExecution(context.Background(), exec.ExecutionID, desired); err != nil || transitioned {
		t.Fatalf("identical retry was not a no-op: transitioned=%t err=%v", transitioned, err)
	}
	conflict := desired
	conflict.result = []byte(`{"ok":false}`)
	if _, _, err := controller.writeTerminalExecution(context.Background(), exec.ExecutionID, conflict); !errors.Is(err, errTerminalExecutionConflict) {
		t.Fatalf("conflicting terminal retry was not rejected: %v", err)
	}
}

func TestRecoverRunAuthorityExecutionsRehydratesMonitor(t *testing.T) {
	var status atomic.Value
	status.Store("running")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := status.Load().(string)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, authorityView(current, current == "running", "home-a", "run-1", "worker-a"))
	}))
	defer server.Close()
	verifier := mustRunAuthorityVerifier(t, server.URL, 10*time.Millisecond)
	defer verifier.Close()

	store := newTestExecutionStorage(nil)
	ref := &RunAuthorityRef{HomeID: "home-a", RunID: "run-1", LeaseOwner: "worker-a", Attempt: 1}
	exec := &types.Execution{ExecutionID: "exec-recover", RunID: "run-1", Status: types.ExecutionStatusRunning, StartedAt: time.Now().UTC()}
	bindExecutionAuthority(exec, ref)
	if err := store.CreateExecutionRecord(context.Background(), exec); err != nil {
		t.Fatal(err)
	}
	if err := RecoverRunAuthorityExecutions(context.Background(), store, verifier, time.Second); err != nil {
		t.Fatal(err)
	}
	status.Store("cancelled")
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		record, _ := store.GetExecutionRecord(context.Background(), exec.ExecutionID)
		if record.Status == types.ExecutionStatusCancelled && record.AuthorityRevokedAt != nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("recovered authority monitor did not reconcile revocation")
}

func mustRunAuthorityVerifier(t *testing.T, baseURL string, pollInterval time.Duration) *RunAuthorityVerifier {
	t.Helper()
	verifier, err := NewRunAuthorityVerifier(config.RunAuthorityConfig{
		Enabled: true, BaseURL: baseURL, BearerToken: authorityToken, ExpectedHomeID: "home-a", ExpectedRunnerType: "agentfield",
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
			"attempt":1,"runnerType":"agentfield","status":%q,"leaseOwner":%q,
			"leaseExpiresAt":%q,"heartbeatAt":%q,
			"heartbeatAgeMs":0,"terminalAt":null,"eligibleForDispatch":%t,"reasonCodes":[]
		}`, homeID, runID, status, leaseOwner, leaseExpiresAt.Format(time.RFC3339Nano), heartbeatAt.Format(time.RFC3339Nano), eligible)
}
