package main

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"

	"github.com/Agent-Field/agentfield/sdk/go/agent"
)

func requiredEnvironment(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		log.Fatalf("required environment %s is missing", name)
	}
	return value
}

func main() {
	originToken := requiredEnvironment("AGENTFIELD_AUTHORIZATION_INTERNAL_TOKEN")
	cfg := agent.Config{
		NodeID:            requiredEnvironment("AGENT_NODE_ID"),
		Version:           "1.0.0",
		AgentFieldURL:     requiredEnvironment("AGENTFIELD_URL"),
		Token:             requiredEnvironment("AGENTFIELD_TOKEN"),
		InternalToken:     originToken,
		RequireOriginAuth: true,
		ListenAddress:     requiredEnvironment("AGENT_LISTEN_ADDR"),
		PublicURL:         requiredEnvironment("AGENT_PUBLIC_URL"),
		CLIConfig: &agent.CLIConfig{
			AppName:        "bee-security-triage",
			AppDescription: "Bounded deterministic tracked-source security triage",
		},
	}

	node, err := agent.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	triageSlot := make(chan struct{}, 1)
	node.RegisterReasoner("security_triage", func(_ context.Context, input map[string]any) (any, error) {
		select {
		case triageSlot <- struct{}{}:
			defer func() { <-triageSlot }()
		default:
			return nil, errors.New("security triage already in progress")
		}
		return runSecurityTriage(input, securityTriageArchivePath)
	},
		agent.WithDescription("Runs bounded deterministic security triage over one digest- and tree-bound tracked-source archive"),
	)

	if err := node.Run(context.Background()); err != nil {
		if cliErr, ok := err.(*agent.CLIError); ok {
			os.Exit(cliErr.ExitCode())
		}
		log.Fatal(err)
	}
}
