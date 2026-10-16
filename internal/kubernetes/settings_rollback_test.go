package kubernetes //nolint:testpackage // Exercises the real client/readiness lifecycle against an HTTP API fixture.

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.containerssh.io/containerssh/config"
	"go.containerssh.io/containerssh/internal/metrics"
	"go.containerssh.io/containerssh/internal/structutils"
	"go.containerssh.io/containerssh/log"
	"go.containerssh.io/containerssh/metadata"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Use the real client, readiness watch and network-handler lifecycle against an
// HTTP API seam. No cluster/scheduler is needed to reproduce a pending pod leak.
func TestSettingsReadinessFailureRollback(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mode        config.KubernetesExecutionMode
		deleteFails bool
		wantDelete  bool
	}{
		{"connection healthy API", config.KubernetesExecutionModeConnection, false, true},
		{"connection unavailable delete", config.KubernetesExecutionModeConnection, true, true},
		{"persistent unchanged", config.KubernetesExecutionModePersistent, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var lock sync.Mutex
			var created, deleted int
			var deleteAfterStartTimeout bool
			var started time.Time
			pod := core.Pod{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Pod"},
				ObjectMeta: meta.ObjectMeta{Name: "settings-pending", Namespace: "sessions", UID: "created-uid", ResourceVersion: "1"},
				Status:     core.PodStatus{Phase: core.PodPending}}
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodPost:
					lock.Lock()
					created++
					lock.Unlock()
					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).Encode(pod)
				case r.Method == http.MethodDelete:
					lock.Lock()
					deleted++
					deleteAfterStartTimeout = time.Since(started) >= 300*time.Millisecond
					lock.Unlock()
					if tc.deleteFails {
						w.WriteHeader(http.StatusServiceUnavailable)
						_ = json.NewEncoder(w).Encode(meta.Status{Status: "Failure", Reason: meta.StatusReasonServiceUnavailable, Code: 503})
					} else {
						// Kubernetes can acknowledge deletion while finalizers retain the object.
						_ = json.NewEncoder(w).Encode(meta.Status{Status: "Success", Code: 200})
					}
				case r.URL.Query().Get("watch") == "true":
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"type": "ADDED", "object": pod})
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				default:
					_ = json.NewEncoder(w).Encode(core.PodList{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "PodList"},
						ListMeta: meta.ListMeta{ResourceVersion: "1"}, Items: []core.Pod{pod}})
				}
			}))
			defer api.Close()
			cfg := config.KubernetesConfig{}
			structutils.Defaults(&cfg)
			cfg.Pod.Mode = tc.mode
			cfg.Connection.Host = api.URL
			cfg.Timeouts.PodStart = 300 * time.Millisecond
			cfg.Timeouts.PodStop = 200 * time.Millisecond
			logger := log.NewTestLogger(t)
			collector := metrics.New(nil)
			factory := &kubernetesClientFactoryImpl{
				backendRequestsMetric: collector.MustCreateCounter("requests", "", "test"),
				backendFailuresMetric: collector.MustCreateCounter("failures", "", "test"),
			}
			cli, err := factory.get(context.Background(), cfg, logger)
			require.NoError(t, err)
			network := &networkHandler{mutex: &sync.Mutex{}, cli: cli, config: cfg, logger: logger,
				client: net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, connectionID: "settings", done: make(chan struct{})}
			// Persistent mode uses findPod first; exercise creation directly to avoid its stock retry sleeps.
			started = time.Now()
			if tc.mode == config.KubernetesExecutionModePersistent {
				ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeouts.PodStart)
				defer cancel()
				_, err = cli.createPod(ctx, nil, nil, nil, nil, nil)
			} else {
				_, _, err = network.OnHandshakeSuccess(metadata.ConnectionAuthenticatedMetadata{AuthenticatedUsername: "owner"})
			}
			require.Error(t, err, "pending pod must fail startup")
			require.Less(t, time.Since(started), 2*time.Second, "rollback must not reuse a background context without a deadline")
			network.OnDisconnect()
			lock.Lock()
			defer lock.Unlock()
			require.Equal(t, 1, created)
			if tc.wantDelete {
				require.Equal(t, 1, deleted, "failed readiness must not orphan the created connection pod")
				require.True(t, deleteAfterStartTimeout, "rollback uses a fresh context after startup expires")
			} else {
				require.Zero(t, deleted, "persistent pods retain their existing lifecycle")
			}
		})
	}
}
