package config

import (
	"testing"
	"time"
)

func TestRunAuthorityConfigDefaultsAndEnvironmentOverrides(t *testing.T) {
	t.Setenv("AGENTFIELD_RUN_AUTHORITY_ENABLED", "true")
	t.Setenv("AGENTFIELD_RUN_AUTHORITY_BASE_URL", "https://deputies.example.test")
	t.Setenv("AGENTFIELD_RUN_AUTHORITY_BEARER_TOKEN", "authority-token-with-at-least-32-random-characters")
	t.Setenv("AGENTFIELD_RUN_AUTHORITY_EXPECTED_HOME_ID", "home-a")
	t.Setenv("AGENTFIELD_RUN_AUTHORITY_REQUEST_TIMEOUT", "1500ms")
	t.Setenv("AGENTFIELD_RUN_AUTHORITY_POLL_INTERVAL", "3s")

	cfg := Config{}
	ApplyDefaults(&cfg)
	if cfg.AgentField.RunAuthority.RequestTimeout != 2*time.Second {
		t.Fatalf("unexpected request timeout default: %s", cfg.AgentField.RunAuthority.RequestTimeout)
	}
	if cfg.AgentField.RunAuthority.PollInterval != 5*time.Second {
		t.Fatalf("unexpected poll interval default: %s", cfg.AgentField.RunAuthority.PollInterval)
	}

	ApplyEnvOverrides(&cfg)
	authority := cfg.AgentField.RunAuthority
	if !authority.Enabled || authority.BaseURL != "https://deputies.example.test" || authority.ExpectedHomeID != "home-a" {
		t.Fatalf("authority identity overrides not applied: %+v", authority)
	}
	if authority.BearerToken == "" || authority.RequestTimeout != 1500*time.Millisecond || authority.PollInterval != 3*time.Second {
		t.Fatalf("authority credential or timing overrides not applied: %+v", authority)
	}
}
