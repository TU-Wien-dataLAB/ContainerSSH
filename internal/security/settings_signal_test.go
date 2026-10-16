package security //nolint:testpackage // Exercises internal policy routing, consistent with existing security tests.

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.containerssh.io/containerssh/config"
	"go.containerssh.io/containerssh/log"
)

func TestSettingsSignalPolicyIndependentOfShell(t *testing.T) {
	for _, tc := range []struct {
		name          string
		shell, signal config.SecurityExecutionPolicy
		allow, deny   []string
		wantForward   bool
	}{
		{"disabled with shell enabled", config.ExecutionPolicyEnable, config.ExecutionPolicyDisable, nil, nil, false},
		{"enabled with shell disabled", config.ExecutionPolicyDisable, config.ExecutionPolicyEnable, nil, nil, true},
		{"filter allowed", config.ExecutionPolicyDisable, config.ExecutionPolicyFilter, []string{"TERM"}, nil, true},
		{"filter unlisted", config.ExecutionPolicyEnable, config.ExecutionPolicyFilter, []string{"INT"}, nil, false},
		{"enabled denied", config.ExecutionPolicyEnable, config.ExecutionPolicyEnable, nil, []string{"TERM"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &settingsSignalBackend{}
			session := &sessionHandler{backend: backend, logger: log.NewTestLogger(t)}
			session.config.Shell.Mode = tc.shell
			session.config.Signal.Mode = tc.signal
			session.config.Signal.Allow = tc.allow
			session.config.Signal.Deny = tc.deny
			err := session.OnSignal(7, "TERM")
			if tc.wantForward {
				require.NoError(t, err)
				require.Equal(t, []string{"TERM"}, backend.signals)
			} else {
				require.Error(t, err)
				require.Empty(t, backend.signals)
			}
		})
	}
}

type settingsSignalBackend struct {
	dummyBackend
	signals []string
}

func (b *settingsSignalBackend) OnSignal(_ uint64, signal string) error {
	b.signals = append(b.signals, signal)
	return nil
}
