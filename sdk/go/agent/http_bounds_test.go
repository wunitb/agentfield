package agent

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExecuteRejectsOversizedAndTrailingJSON(t *testing.T) {
	node, err := New(Config{NodeID: "node-1", Version: "1.0.0", Logger: log.New(io.Discard, "", 0)})
	require.NoError(t, err)
	node.RegisterReasoner("echo", func(_ context.Context, input map[string]any) (any, error) { return input, nil })

	oversized := `{"input":{"value":"` + strings.Repeat("a", int(maxExecutionRequestBytes)) + `"}}`
	request := httptest.NewRequest(http.MethodPost, "/execute/echo", strings.NewReader(oversized))
	response := httptest.NewRecorder()
	node.handleExecute(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code)

	request = httptest.NewRequest(http.MethodPost, "/execute/echo", strings.NewReader(`{"input":{}} {}`))
	response = httptest.NewRecorder()
	node.handleExecute(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code)
}

func TestAgentHTTPServerUsesBoundedTimeouts(t *testing.T) {
	node, err := New(Config{
		NodeID:        "node-1",
		Version:       "1.0.0",
		ListenAddress: "127.0.0.1:0",
		Logger:        log.New(io.Discard, "", 0),
	})
	require.NoError(t, err)
	require.NoError(t, node.startServer())
	t.Cleanup(func() { _ = node.server.Close() })

	require.Equal(t, 5*time.Second, node.server.ReadHeaderTimeout)
	require.Equal(t, 30*time.Second, node.server.ReadTimeout)
	require.Equal(t, 30*time.Second, node.server.WriteTimeout)
	require.Equal(t, 30*time.Second, node.server.IdleTimeout)
	require.Equal(t, 16<<10, node.server.MaxHeaderBytes)
}
