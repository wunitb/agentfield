package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Agent-Field/agentfield/control-plane/internal/config"
	"github.com/Agent-Field/agentfield/control-plane/internal/events"
	"github.com/Agent-Field/agentfield/control-plane/internal/logger"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"

	"github.com/gin-gonic/gin"
)

const runAuthoritySchemaVersion = "deputies.run-authority.v1"

var (
	ErrRunAuthorityRevoked    = errors.New("outer run authority revoked")
	runAuthorityHomeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// RunAuthorityRef binds an AgentField execution to one outer lifecycle lease.
type RunAuthorityRef struct {
	HomeID     string `json:"home_id"`
	RunID      string `json:"run_id"`
	LeaseOwner string `json:"lease_owner"`
	Attempt    int    `json:"attempt"`
}

// RunAuthorityVerifier admits and monitors executions against an outer control plane.
type RunAuthorityVerifier struct {
	baseURL         *url.URL
	bearerToken     string
	expectedHomeID     string
	expectedRunnerType string
	pollInterval    time.Duration
	heartbeatMaxAge time.Duration
	clockSkew       time.Duration
	client          *http.Client
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc
	monitorMu       sync.Mutex
	monitorWG       sync.WaitGroup
	closed          bool
}

// RunAuthorityUnsupportedHandler blocks dispatch surfaces that cannot carry an outer lease.
func RunAuthorityUnsupportedHandler(surface string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "run_authority_unavailable",
			"message": fmt.Sprintf("%s dispatch is disabled while outer run authority is required", surface),
		})
	}
}

type runAuthorityView struct {
	SchemaVersion       string   `json:"schemaVersion"`
	HomeID              string   `json:"homeId"`
	RunID               string   `json:"runId"`
	SessionID           string   `json:"sessionId"`
	MessageID           string   `json:"messageId"`
	Attempt             int      `json:"attempt"`
	RunnerType          string   `json:"runnerType"`
	Status              string   `json:"status"`
	LeaseOwner          *string  `json:"leaseOwner"`
	LeaseExpiresAt      *string  `json:"leaseExpiresAt"`
	HeartbeatAt         *string  `json:"heartbeatAt"`
	HeartbeatAgeMS      *int64   `json:"heartbeatAgeMs"`
	TerminalAt          *string  `json:"terminalAt"`
	EligibleForDispatch bool     `json:"eligibleForDispatch"`
	ReasonCodes         []string `json:"reasonCodes"`
}

// NewRunAuthorityVerifier validates the complete trust boundary before creating a client.
func NewRunAuthorityVerifier(cfg config.RunAuthorityConfig) (*RunAuthorityVerifier, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	baseURL, err := url.Parse(strings.TrimSpace(cfg.BaseURL))
	if err != nil || baseURL.Host == "" || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("run authority base_url must be an absolute URL without credentials, query, or fragment")
	}
	if baseURL.Scheme != "https" && !(baseURL.Scheme == "http" && isLoopbackHost(baseURL.Hostname())) {
		return nil, errors.New("run authority base_url must use HTTPS or loopback HTTP")
	}
	baseURL.Path = strings.TrimRight(baseURL.Path, "/")
	token := strings.TrimSpace(cfg.BearerToken)
	if len(token) < 32 || isPlaceholderAuthoritySecret(token) {
		return nil, errors.New("run authority bearer_token must be a non-placeholder secret of at least 32 characters")
	}
	homeID := strings.TrimSpace(cfg.ExpectedHomeID)
	if !runAuthorityHomeIDPattern.MatchString(homeID) {
		return nil, errors.New("run authority expected_home_id must be a stable deployment identifier")
	}
	expectedRunnerType := strings.TrimSpace(cfg.ExpectedRunnerType)
	if expectedRunnerType != "agentfield" {
		return nil, errors.New("run authority expected_runner_type must be agentfield")
	}
	if cfg.RequestTimeout <= 0 || cfg.RequestTimeout > 30*time.Second {
		return nil, errors.New("run authority request_timeout must be between 0 and 30s")
	}
	if cfg.PollInterval < 10*time.Millisecond || cfg.PollInterval > time.Minute {
		return nil, errors.New("run authority poll_interval must be between 10ms and 1m")
	}
	if cfg.HeartbeatMaxAge <= 0 || cfg.HeartbeatMaxAge > 10*time.Minute {
		return nil, errors.New("run authority heartbeat_max_age must be between 0 and 10m")
	}
	if cfg.ClockSkew < 0 || cfg.ClockSkew > 30*time.Second {
		return nil, errors.New("run authority clock_skew must be between 0 and 30s")
	}
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())

	return &RunAuthorityVerifier{
		baseURL:         baseURL,
		bearerToken:        token,
		expectedHomeID:     homeID,
		expectedRunnerType: expectedRunnerType,
		pollInterval:    cfg.PollInterval,
		heartbeatMaxAge: cfg.HeartbeatMaxAge,
		clockSkew:       cfg.ClockSkew,
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
		client: &http.Client{
			Timeout: cfg.RequestTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Close cancels and joins every detached authority monitor owned by this verifier.
func (v *RunAuthorityVerifier) Close() {
	if v == nil || v.lifecycleCancel == nil {
		return
	}
	v.monitorMu.Lock()
	if !v.closed {
		v.closed = true
		v.lifecycleCancel()
	}
	v.monitorMu.Unlock()
	v.monitorWG.Wait()
}

func (v *RunAuthorityVerifier) startMonitor(run func(context.Context)) {
	if v == nil || v.lifecycleCtx == nil {
		return
	}
	v.monitorMu.Lock()
	if v.closed {
		v.monitorMu.Unlock()
		return
	}
	v.monitorWG.Add(1)
	v.monitorMu.Unlock()
	go func() {
		defer v.monitorWG.Done()
		run(v.lifecycleCtx)
	}()
}

func normalizeRunAuthorityRef(ref *RunAuthorityRef) error {
	if ref == nil {
		return errors.New("run authority reference is required")
	}
	ref.HomeID = strings.TrimSpace(ref.HomeID)
	ref.RunID = strings.TrimSpace(ref.RunID)
	ref.LeaseOwner = strings.TrimSpace(ref.LeaseOwner)
	if !runAuthorityHomeIDPattern.MatchString(ref.HomeID) || ref.RunID == "" || ref.LeaseOwner == "" || ref.Attempt < 1 {
		return errors.New("run authority reference requires home_id, run_id, lease_owner, and a 1-based attempt")
	}
	return nil
}

// Verify performs one fail-closed admission check.
func (v *RunAuthorityVerifier) Verify(ctx context.Context, ref RunAuthorityRef) error {
	if v == nil {
		return nil
	}
	if err := normalizeRunAuthorityRef(&ref); err != nil {
		return err
	}
	if ref.HomeID != v.expectedHomeID {
		return errors.New("run authority reference does not match configured home identity")
	}

	endpoint := *v.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/run-authority/v1/runs/" + url.PathEscape(ref.RunID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return fmt.Errorf("build run authority request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+v.bearerToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")

	response, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("read run authority: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("run authority returned HTTP %d", response.StatusCode)
	}

	var view runAuthorityView
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64*1024+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&view); err != nil {
		return fmt.Errorf("decode run authority view: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	return v.validateView(view, ref)
}

// Guard verifies once, then cancels the returned context if authority is lost.
func (v *RunAuthorityVerifier) Guard(ctx context.Context, ref RunAuthorityRef) (context.Context, func(), error) {
	if v == nil {
		return ctx, func() {}, nil
	}
	if err := v.Verify(ctx, ref); err != nil {
		return nil, nil, err
	}

	guarded, revoke := context.WithCancelCause(ctx)
	monitor, stop := context.WithCancel(ctx)
	go v.monitor(monitor, ref, revoke)
	return guarded, stop, nil
}

func (v *RunAuthorityVerifier) monitor(ctx context.Context, ref RunAuthorityRef, revoke context.CancelCauseFunc) {
	ticker := time.NewTicker(v.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := v.Verify(ctx, ref); err != nil {
				revoke(fmt.Errorf("%w: %v", ErrRunAuthorityRevoked, err))
				return
			}
		}
	}
}

func (v *RunAuthorityVerifier) validateView(view runAuthorityView, ref RunAuthorityRef) error {
	if view.SchemaVersion != runAuthoritySchemaVersion || view.HomeID != v.expectedHomeID || view.RunID != ref.RunID || view.Attempt != ref.Attempt {
		return errors.New("run authority response identity mismatch")
	}
	if view.LeaseOwner == nil || *view.LeaseOwner != ref.LeaseOwner {
		return errors.New("run authority lease owner mismatch")
	}
	if view.RunnerType != v.expectedRunnerType {
		return errors.New("run authority runner type mismatch")
	}
	if view.Status != "running" || !view.EligibleForDispatch || len(view.ReasonCodes) != 0 {
		return fmt.Errorf("run authority denied dispatch: status=%s reasons=%s", view.Status, strings.Join(view.ReasonCodes, ","))
	}
	if view.TerminalAt != nil || view.Attempt < 1 || view.SessionID == "" || view.MessageID == "" || view.RunnerType == "" {
		return errors.New("run authority response is incomplete or contradictory")
	}
	if view.LeaseExpiresAt == nil || view.HeartbeatAt == nil || view.HeartbeatAgeMS == nil || *view.HeartbeatAgeMS < 0 {
		return errors.New("run authority lease or heartbeat is incomplete")
	}
	now := time.Now()
	leaseExpiresAt, err := time.Parse(time.RFC3339Nano, *view.LeaseExpiresAt)
	if err != nil || !leaseExpiresAt.After(now) {
		return errors.New("run authority lease is expired or invalid")
	}
	heartbeatAt, err := time.Parse(time.RFC3339Nano, *view.HeartbeatAt)
	if err != nil {
		return errors.New("run authority heartbeat is invalid")
	}
	calculatedAge := now.Sub(heartbeatAt)
	if calculatedAge < -v.clockSkew || calculatedAge > v.heartbeatMaxAge+v.clockSkew {
		return errors.New("run authority heartbeat is outside the local freshness window")
	}
	reportedAge := time.Duration(*view.HeartbeatAgeMS) * time.Millisecond
	if reportedAge > v.heartbeatMaxAge || absoluteDuration(calculatedAge-reportedAge) > v.clockSkew {
		return errors.New("run authority heartbeat age is stale or inconsistent")
	}
	return nil
}

func absoluteDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("run authority response has trailing JSON")
		}
		return fmt.Errorf("decode run authority response trailer: %w", err)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isPlaceholderAuthoritySecret(secret string) bool {
	normalized := strings.ToLower(secret)
	for _, marker := range []string{"changeme", "change-me", "replace-me", "example", "placeholder"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func (c *executionController) monitorAcceptedRunAuthority(plan preparedExecution) {
	if c.runAuthority == nil || plan.runAuthority == nil || plan.exec == nil {
		return
	}
	c.runAuthority.startMonitor(func(parent context.Context) {
		c.runAcceptedAuthorityMonitor(parent, plan)
	})
}

// RecoverRunAuthorityExecutions rehydrates authority monitors for durable nonterminal work.
func RecoverRunAuthorityExecutions(ctx context.Context, store ExecutionStore, authority *RunAuthorityVerifier, timeout time.Duration) error {
	if authority == nil {
		return nil
	}
	controller := newExecutionControllerWithRunAuthority(store, nil, nil, timeout, "", nil, authority)
	records, err := store.QueryExecutionRecords(ctx, types.ExecutionFilter{AuthorityBoundOnly: true, NonTerminalOnly: true})
	if err != nil {
		return fmt.Errorf("query authority-bound executions for recovery: %w", err)
	}
	for _, record := range records {
		ref, ok := executionAuthorityRef(record)
		if !ok {
			return fmt.Errorf("execution %s has an incomplete persisted authority binding", record.ExecutionID)
		}
		controller.monitorAcceptedRunAuthority(preparedExecution{exec: record, runAuthority: ref, executionMode: "recovery"})
	}
	return nil
}

func (c *executionController) runAcceptedAuthorityMonitor(parent context.Context, plan preparedExecution) {
	deadline := plan.exec.StartedAt.Add(c.timeout)
	monitorCtx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()

	guardedCtx, stop, err := c.runAuthority.Guard(monitorCtx, *plan.runAuthority)
	if err != nil {
		if errors.Is(monitorCtx.Err(), context.DeadlineExceeded) {
			_, err = c.terminalizeExecutionTimeout(monitorCtx, plan.exec.ExecutionID, time.Since(plan.exec.StartedAt))
		} else {
			err = c.cancelRevokedRunAuthority(monitorCtx, &plan, time.Since(plan.exec.StartedAt))
		}
		if err != nil {
			logger.Logger.Error().Err(err).Str("execution_id", plan.exec.ExecutionID).Msg("failed to reconcile accepted execution authority")
		}
		return
	}
	defer stop()

	statusTicker := time.NewTicker(time.Second)
	defer statusTicker.Stop()
	for {
		select {
		case <-guardedCtx.Done():
			elapsed := time.Since(plan.exec.StartedAt)
			if errors.Is(context.Cause(guardedCtx), ErrRunAuthorityRevoked) {
				_ = c.runAuthorityRevocationError(guardedCtx, &plan, elapsed)
			} else if errors.Is(context.Cause(guardedCtx), context.DeadlineExceeded) {
				if _, err := c.terminalizeExecutionTimeout(guardedCtx, plan.exec.ExecutionID, elapsed); err != nil && !errors.Is(err, ErrRunAuthorityRevoked) && !errors.Is(err, errTerminalExecutionConflict) {
					logger.Logger.Error().Err(err).Str("execution_id", plan.exec.ExecutionID).Msg("failed to persist accepted execution timeout")
				}
			}
			return
		case <-statusTicker.C:
			record, lookupErr := c.store.GetExecutionRecord(monitorCtx, plan.exec.ExecutionID)
			if lookupErr == nil && record != nil && types.IsTerminalExecutionStatus(record.Status) {
				return
			}
		}
	}
}

func (c *executionController) runAuthorityRevocationError(ctx context.Context, plan *preparedExecution, elapsed time.Duration) error {
	if ctx == nil {
		return nil
	}
	cause := context.Cause(ctx)
	if !errors.Is(cause, ErrRunAuthorityRevoked) {
		return nil
	}
	if err := c.cancelRevokedRunAuthority(ctx, plan, elapsed); err != nil {
		executionID := ""
		if plan != nil && plan.exec != nil {
			executionID = plan.exec.ExecutionID
		}
		logger.Logger.Error().Err(err).Str("execution_id", executionID).Msg("failed to persist run authority cancellation")
	}
	return runAuthorityAdmissionError(cause)
}

func (c *executionController) cancelRevokedRunAuthority(ctx context.Context, plan *preparedExecution, elapsed time.Duration) error {
	if plan == nil || plan.exec == nil {
		return errors.New("cannot cancel execution without a prepared execution record")
	}
	executionID := plan.exec.ExecutionID
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	reason := ErrRunAuthorityRevoked.Error()
	cancelled := false
	updated, err := c.store.UpdateExecutionRecord(persistCtx, executionID, func(current *types.Execution) (*types.Execution, error) {
		if current == nil {
			return nil, fmt.Errorf("execution %s not found", executionID)
		}
		persisted, ok := executionAuthorityRef(current)
		if !ok || plan.runAuthority == nil || *persisted != *plan.runAuthority {
			return nil, errors.New("execution authority binding changed before revocation")
		}
		now := time.Now().UTC()
		if current.AuthorityRevokedAt == nil {
			current.AuthorityRevokedAt = &now
		}
		if types.IsTerminalExecutionStatus(current.Status) {
			return current, nil
		}
		current.Status = types.ExecutionStatusCancelled
		current.StatusReason = &reason
		current.CompletedAt = &now
		duration := elapsed.Milliseconds()
		current.DurationMS = &duration
		current.UpdatedAt = now
		cancelled = true
		return current, nil
	})
	if err != nil {
		return fmt.Errorf("persist run authority cancellation: %w", err)
	}
	if !cancelled || updated == nil {
		return nil
	}

	if workflow, lookupErr := c.store.GetWorkflowExecution(persistCtx, updated.ExecutionID); lookupErr == nil && workflow != nil {
		c.updateWorkflowExecutionFinalState(persistCtx, updated.ExecutionID, types.ExecutionStatusCancelled, nil, elapsed, &reason)
	}
	eventData := map[string]interface{}{
		"reason":            reason,
		"transition_source": "run_authority",
	}
	enrichExecutionLifecycleData(eventData, updated, string(types.ExecutionStatusCancelled))
	events.PublishExecutionCancelled(updated.ExecutionID, updated.RunID, updated.AgentNodeID, eventData)
	return nil
}

func (c *executionController) verifyRunAuthority(ctx context.Context, plan *preparedExecution) error {
	ref, err := c.requiredRunAuthority(plan)
	if err != nil || ref == nil {
		return err
	}
	if err := c.runAuthority.Verify(ctx, *ref); err != nil {
		return runAuthorityAdmissionError(err)
	}
	return nil
}

func (c *executionController) guardRunAuthority(ctx context.Context, plan *preparedExecution) (context.Context, func(), error) {
	ref, err := c.requiredRunAuthority(plan)
	if err != nil {
		return nil, nil, err
	}
	if ref == nil {
		return ctx, func() {}, nil
	}
	guarded, stop, err := c.runAuthority.Guard(ctx, *ref)
	if err != nil {
		return nil, nil, runAuthorityAdmissionError(err)
	}
	return guarded, stop, nil
}

func (c *executionController) requiredRunAuthority(plan *preparedExecution) (*RunAuthorityRef, error) {
	if c.runAuthority == nil {
		return nil, nil
	}
	if plan == nil || plan.exec == nil || plan.runAuthority == nil {
		return nil, runAuthorityAdmissionError(errors.New("execution is missing an outer run authority reference"))
	}
	if plan.exec.RunID != plan.runAuthority.RunID {
		return nil, runAuthorityAdmissionError(errors.New("execution run does not match outer run authority"))
	}
	persisted, ok := executionAuthorityRef(plan.exec)
	if !ok || *persisted != *plan.runAuthority {
		return nil, runAuthorityAdmissionError(errors.New("execution authority binding does not match persisted authority"))
	}
	return plan.runAuthority, nil
}

func runAuthorityAdmissionError(err error) error {
	return &executionPreconditionError{
		code:      http.StatusServiceUnavailable,
		message:   fmt.Sprintf("outer run authority denied execution: %v", err),
		category:  ErrorCategoryAgentError,
		errorCode: "run_authority_unavailable",
	}
}
