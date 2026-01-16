package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// Agent is a lightweight Kubernetes security agent
type Agent struct {
	config     AgentConfig
	collectors []Collector
	telemetry  chan Event
	httpClient *http.Client
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// AgentConfig configures the agent
type AgentConfig struct {
	NodeName        string        `json:"node_name"`
	ClusterName     string        `json:"cluster_name"`
	Namespace       string        `json:"namespace"`
	CerebroURL      string        `json:"cerebro_url"`
	APIToken        string        `json:"api_token"`
	CollectInterval time.Duration `json:"collect_interval"`
	BatchSize       int           `json:"batch_size"`
	EnableEBPF      bool          `json:"enable_ebpf"`
	EnableAudit     bool          `json:"enable_audit"`
}

// Event represents a telemetry event
type Event struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Timestamp   time.Time              `json:"timestamp"`
	NodeName    string                 `json:"node_name"`
	ClusterName string                 `json:"cluster_name"`
	Namespace   string                 `json:"namespace,omitempty"`
	PodName     string                 `json:"pod_name,omitempty"`
	ContainerID string                 `json:"container_id,omitempty"`
	ProcessInfo *ProcessInfo           `json:"process,omitempty"`
	NetworkInfo *NetworkInfo           `json:"network,omitempty"`
	FileInfo    *FileInfo              `json:"file,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type ProcessInfo struct {
	PID        int      `json:"pid"`
	PPID       int      `json:"ppid"`
	Name       string   `json:"name"`
	Cmdline    string   `json:"cmdline"`
	UID        int      `json:"uid"`
	GID        int      `json:"gid"`
	Executable string   `json:"executable"`
	Cwd        string   `json:"cwd"`
	Ancestors  []string `json:"ancestors,omitempty"`
}

type NetworkInfo struct {
	Direction string `json:"direction"`
	Protocol  string `json:"protocol"`
	SrcAddr   string `json:"src_addr"`
	SrcPort   int    `json:"src_port"`
	DstAddr   string `json:"dst_addr"`
	DstPort   int    `json:"dst_port"`
	Domain    string `json:"domain,omitempty"`
}

type FileInfo struct {
	Path      string `json:"path"`
	Operation string `json:"operation"`
	Size      int64  `json:"size,omitempty"`
	Hash      string `json:"hash,omitempty"`
}

// Collector interface for different data sources
type Collector interface {
	Name() string
	Start(ctx context.Context, events chan<- Event) error
	Stop() error
}

func NewAgent(config AgentConfig) *Agent {
	if config.CollectInterval == 0 {
		config.CollectInterval = 10 * time.Second
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}

	return &Agent{
		config:    config,
		telemetry: make(chan Event, 1000),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		stopCh: make(chan struct{}),
	}
}

func (a *Agent) RegisterCollector(c Collector) {
	a.collectors = append(a.collectors, c)
}

// Start begins collecting telemetry
func (a *Agent) Start(ctx context.Context) error {
	// Start collectors
	for _, c := range a.collectors {
		collector := c
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			if err := collector.Start(ctx, a.telemetry); err != nil {
				fmt.Fprintf(os.Stderr, "collector %s error: %v\n", collector.Name(), err)
			}
		}()
	}

	// Start batch sender
	a.wg.Add(1)
	go a.batchSender(ctx)

	return nil
}

func (a *Agent) batchSender(ctx context.Context) {
	defer a.wg.Done()

	batch := make([]Event, 0, a.config.BatchSize)
	ticker := time.NewTicker(a.config.CollectInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if len(batch) > 0 {
				_ = a.sendBatch(batch)
			}
			return
		case <-a.stopCh:
			if len(batch) > 0 {
				_ = a.sendBatch(batch)
			}
			return
		case event := <-a.telemetry:
			batch = append(batch, event)
			if len(batch) >= a.config.BatchSize {
				_ = a.sendBatch(batch)
				batch = make([]Event, 0, a.config.BatchSize)
			}
		case <-ticker.C:
			if len(batch) > 0 {
				_ = a.sendBatch(batch)
				batch = make([]Event, 0, a.config.BatchSize)
			}
		}
	}
}

func (a *Agent) sendBatch(events []Event) error {
	return a.sendBatchWithContext(context.Background(), events)
}

func (a *Agent) sendBatchWithContext(ctx context.Context, events []Event) error {
	if a.config.CerebroURL == "" {
		return nil
	}

	data, err := json.Marshal(map[string]interface{}{
		"events":        events,
		"node":          a.config.NodeName,
		"cluster":       a.config.ClusterName,
		"agent_version": "1.0.0",
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.config.CerebroURL+"/api/v1/telemetry/ingest", nil)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.config.APIToken)
	req.Body = &bytesReader{data: data}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	return nil
}

func (a *Agent) Stop() {
	close(a.stopCh)
	for _, c := range a.collectors {
		_ = c.Stop()
	}
	a.wg.Wait()
}

type bytesReader struct {
	data []byte
	pos  int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *bytesReader) Close() error { return nil }

// ProcCollector collects process events from /proc
type ProcCollector struct {
	interval time.Duration
	stopCh   chan struct{}
}

func NewProcCollector(interval time.Duration) *ProcCollector {
	if interval == 0 {
		interval = 5 * time.Second
	}
	return &ProcCollector{
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

func (c *ProcCollector) Name() string { return "proc" }

func (c *ProcCollector) Start(ctx context.Context, events chan<- Event) error {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.stopCh:
			return nil
		case <-ticker.C:
			// Would scan /proc for process info
			// For now, this is a framework
		}
	}
}

func (c *ProcCollector) Stop() error {
	close(c.stopCh)
	return nil
}

// AuditCollector collects Kubernetes audit events
type AuditCollector struct {
	auditLogPath string
	stopCh       chan struct{}
}

func NewAuditCollector(auditLogPath string) *AuditCollector {
	return &AuditCollector{
		auditLogPath: auditLogPath,
		stopCh:       make(chan struct{}),
	}
}

func (c *AuditCollector) Name() string { return "audit" }

func (c *AuditCollector) Start(ctx context.Context, events chan<- Event) error {
	// Would tail audit log and emit events
	// For now, this is a framework
	<-c.stopCh
	return nil
}

func (c *AuditCollector) Stop() error {
	close(c.stopCh)
	return nil
}

// NetworkCollector collects network connection events
type NetworkCollector struct {
	interval time.Duration
	stopCh   chan struct{}
}

func NewNetworkCollector(interval time.Duration) *NetworkCollector {
	if interval == 0 {
		interval = 10 * time.Second
	}
	return &NetworkCollector{
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

func (c *NetworkCollector) Name() string { return "network" }

func (c *NetworkCollector) Start(ctx context.Context, events chan<- Event) error {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.stopCh:
			return nil
		case <-ticker.C:
			// Would parse /proc/net/tcp, /proc/net/udp
			// Or use conntrack
		}
	}
}

func (c *NetworkCollector) Stop() error {
	close(c.stopCh)
	return nil
}

// DaemonSetManifest returns K8s DaemonSet YAML for deployment
func DaemonSetManifest(namespace, cerebroURL, apiToken string) string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: cerebro-agent
  namespace: %s
  labels:
    app: cerebro-agent
spec:
  selector:
    matchLabels:
      app: cerebro-agent
  template:
    metadata:
      labels:
        app: cerebro-agent
    spec:
      hostPID: true
      hostNetwork: true
      serviceAccountName: cerebro-agent
      containers:
      - name: agent
        image: cerebro/agent:latest
        securityContext:
          privileged: true
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: CEREBRO_URL
          value: "%s"
        - name: CEREBRO_TOKEN
          valueFrom:
            secretKeyRef:
              name: cerebro-agent
              key: token
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: sys
          mountPath: /host/sys
          readOnly: true
        - name: containerd
          mountPath: /run/containerd
          readOnly: true
        resources:
          limits:
            memory: 256Mi
            cpu: 200m
          requests:
            memory: 64Mi
            cpu: 50m
      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: sys
        hostPath:
          path: /sys
      - name: containerd
        hostPath:
          path: /run/containerd
      tolerations:
      - operator: Exists
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cerebro-agent
  namespace: %s
---
apiVersion: v1
kind: Secret
metadata:
  name: cerebro-agent
  namespace: %s
type: Opaque
stringData:
  token: "%s"
`, namespace, cerebroURL, namespace, namespace, apiToken)
}
