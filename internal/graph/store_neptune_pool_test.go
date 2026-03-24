package graph

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptunedata"
)

func TestPooledNeptuneDataExecutorRespectsConfiguredPoolSize(t *testing.T) {
	var (
		created atomic.Int32
		started = make(chan int, 3)
		release = make(chan struct{})
		wg      sync.WaitGroup
	)

	exec, err := NewPooledNeptuneDataExecutor(func() (neptuneDataClient, error) {
		id := int(created.Add(1))
		return &testPooledNeptuneClient{
			id: id,
			queryFn: func(_ context.Context, query string, _ *neptunedata.ExecuteOpenCypherQueryInput) (*neptunedata.ExecuteOpenCypherQueryOutput, error) {
				if query == neptuneConnectionPoolHealthcheckQuery {
					return &neptunedata.ExecuteOpenCypherQueryOutput{}, nil
				}
				started <- id
				<-release
				return &neptunedata.ExecuteOpenCypherQueryOutput{}, nil
			},
		}, nil
	}, NeptuneDataExecutorPoolConfig{
		Size: 2,
	})
	if err != nil {
		t.Fatalf("NewPooledNeptuneDataExecutor() error = %v", err)
	}
	defer func() {
		if err := exec.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := exec.ExecuteOpenCypher(context.Background(), "MATCH (n) RETURN n", nil); err != nil {
				t.Errorf("ExecuteOpenCypher() error = %v", err)
			}
		}()
	}

	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for pooled Neptune queries to start")
		}
	}

	select {
	case id := <-started:
		t.Fatalf("unexpected third pooled query started before a connection was released, client=%d", id)
	case <-time.After(100 * time.Millisecond):
	}

	if got := created.Load(); got != 2 {
		t.Fatalf("created pooled clients = %d, want 2", got)
	}

	close(release)
	wg.Wait()

	if got := created.Load(); got != 2 {
		t.Fatalf("created pooled clients after reuse = %d, want 2", got)
	}
}

func TestPooledNeptuneDataExecutorHealthCheckReplacesUnhealthyConnections(t *testing.T) {
	var (
		created atomic.Int32
		mu      sync.Mutex
		clients []*testPooledNeptuneClient
	)

	exec, err := NewPooledNeptuneDataExecutor(func() (neptuneDataClient, error) {
		id := int(created.Add(1))
		client := &testPooledNeptuneClient{id: id}
		if id == 1 {
			client.queryFn = func(_ context.Context, query string, _ *neptunedata.ExecuteOpenCypherQueryInput) (*neptunedata.ExecuteOpenCypherQueryOutput, error) {
				if query == neptuneConnectionPoolHealthcheckQuery {
					client.healthChecks.Add(1)
					return nil, errors.New("connection unhealthy")
				}
				client.queries.Add(1)
				return &neptunedata.ExecuteOpenCypherQueryOutput{}, nil
			}
		} else {
			client.queryFn = func(_ context.Context, query string, _ *neptunedata.ExecuteOpenCypherQueryInput) (*neptunedata.ExecuteOpenCypherQueryOutput, error) {
				if query == neptuneConnectionPoolHealthcheckQuery {
					client.healthChecks.Add(1)
					return &neptunedata.ExecuteOpenCypherQueryOutput{}, nil
				}
				client.queries.Add(1)
				return &neptunedata.ExecuteOpenCypherQueryOutput{}, nil
			}
		}
		mu.Lock()
		clients = append(clients, client)
		mu.Unlock()
		return client, nil
	}, NeptuneDataExecutorPoolConfig{
		Size:                1,
		HealthCheckInterval: 10 * time.Millisecond,
		HealthCheckTimeout:  50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewPooledNeptuneDataExecutor() error = %v", err)
	}
	defer func() {
		if err := exec.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	if _, err := exec.ExecuteOpenCypher(context.Background(), "MATCH (n) RETURN n", nil); err != nil {
		t.Fatalf("ExecuteOpenCypher() initial query error = %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if created.Load() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := created.Load(); got != 2 {
		t.Fatalf("created pooled clients after health replacement = %d, want 2", got)
	}

	if _, err := exec.ExecuteOpenCypher(context.Background(), "MATCH (m) RETURN m", nil); err != nil {
		t.Fatalf("ExecuteOpenCypher() replacement query error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(clients) != 2 {
		t.Fatalf("pooled clients = %d, want 2", len(clients))
	}
	if clients[0].healthChecks.Load() == 0 {
		t.Fatalf("expected first client health checks, got 0")
	}
	if clients[1].queries.Load() == 0 {
		t.Fatalf("expected replacement client to serve a query, got 0")
	}
}

func TestPooledNeptuneDataExecutorRecyclesConnectionsAfterMaxUses(t *testing.T) {
	var (
		created atomic.Int32
		mu      sync.Mutex
		clients []*testPooledNeptuneClient
	)

	exec, err := NewPooledNeptuneDataExecutor(func() (neptuneDataClient, error) {
		id := int(created.Add(1))
		client := &testPooledNeptuneClient{
			id: id,
			queryFn: func(_ context.Context, query string, _ *neptunedata.ExecuteOpenCypherQueryInput) (*neptunedata.ExecuteOpenCypherQueryOutput, error) {
				return &neptunedata.ExecuteOpenCypherQueryOutput{}, nil
			},
		}
		mu.Lock()
		clients = append(clients, client)
		mu.Unlock()
		return client, nil
	}, NeptuneDataExecutorPoolConfig{
		Size:          1,
		MaxClientUses: 1,
	})
	if err != nil {
		t.Fatalf("NewPooledNeptuneDataExecutor() error = %v", err)
	}
	defer func() {
		if err := exec.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	if _, err := exec.ExecuteOpenCypher(context.Background(), "RETURN 1", nil); err != nil {
		t.Fatalf("ExecuteOpenCypher() first error = %v", err)
	}
	if _, err := exec.ExecuteOpenCypher(context.Background(), "RETURN 2", nil); err != nil {
		t.Fatalf("ExecuteOpenCypher() second error = %v", err)
	}

	if got := created.Load(); got != 2 {
		t.Fatalf("created pooled clients after recycle = %d, want 2", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(clients) != 2 {
		t.Fatalf("pooled clients = %d, want 2", len(clients))
	}
	if clients[0].closeCalls.Load() == 0 {
		t.Fatalf("expected recycled client to be closed")
	}
}

func TestPooledNeptuneDataExecutorDrainWaitsForInflightQueriesAndRejectsNewWork(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})

	exec, err := NewPooledNeptuneDataExecutor(func() (neptuneDataClient, error) {
		return &testPooledNeptuneClient{
			queryFn: func(_ context.Context, query string, _ *neptunedata.ExecuteOpenCypherQueryInput) (*neptunedata.ExecuteOpenCypherQueryOutput, error) {
				if query == neptuneConnectionPoolHealthcheckQuery {
					return &neptunedata.ExecuteOpenCypherQueryOutput{}, nil
				}
				started <- struct{}{}
				<-release
				return &neptunedata.ExecuteOpenCypherQueryOutput{}, nil
			},
		}, nil
	}, NeptuneDataExecutorPoolConfig{
		Size:         1,
		DrainTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewPooledNeptuneDataExecutor() error = %v", err)
	}

	queryDone := make(chan error, 1)
	go func() {
		_, queryErr := exec.ExecuteOpenCypher(context.Background(), "MATCH (n) RETURN n", nil)
		queryDone <- queryErr
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for inflight pooled query to start")
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- exec.Close()
	}()

	select {
	case err := <-closeDone:
		t.Fatalf("Close() returned before inflight work drained: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := exec.ExecuteOpenCypher(context.Background(), "MATCH (m) RETURN m", nil); !errors.Is(err, errNeptuneConnectionPoolDraining) {
		t.Fatalf("ExecuteOpenCypher() during drain error = %v, want draining error", err)
	}

	close(release)

	select {
	case err := <-queryDone:
		if err != nil {
			t.Fatalf("inflight ExecuteOpenCypher() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for inflight pooled query to finish")
	}

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for pooled executor close")
	}
}

type testPooledNeptuneClient struct {
	id           int
	queryFn      func(ctx context.Context, query string, input *neptunedata.ExecuteOpenCypherQueryInput) (*neptunedata.ExecuteOpenCypherQueryOutput, error)
	explainFn    func(ctx context.Context, query string, input *neptunedata.ExecuteOpenCypherExplainQueryInput) (*neptunedata.ExecuteOpenCypherExplainQueryOutput, error)
	closeCalls   atomic.Int32
	queries      atomic.Int32
	healthChecks atomic.Int32
}

func (c *testPooledNeptuneClient) ExecuteOpenCypherQuery(ctx context.Context, input *neptunedata.ExecuteOpenCypherQueryInput, _ ...func(*neptunedata.Options)) (*neptunedata.ExecuteOpenCypherQueryOutput, error) {
	if c.queryFn == nil {
		return &neptunedata.ExecuteOpenCypherQueryOutput{}, nil
	}
	return c.queryFn(ctx, aws.ToString(input.OpenCypherQuery), input)
}

func (c *testPooledNeptuneClient) ExecuteOpenCypherExplainQuery(ctx context.Context, input *neptunedata.ExecuteOpenCypherExplainQueryInput, _ ...func(*neptunedata.Options)) (*neptunedata.ExecuteOpenCypherExplainQueryOutput, error) {
	if c.explainFn == nil {
		return &neptunedata.ExecuteOpenCypherExplainQueryOutput{}, nil
	}
	return c.explainFn(ctx, aws.ToString(input.OpenCypherQuery), input)
}

func (c *testPooledNeptuneClient) Close() error {
	c.closeCalls.Add(1)
	return nil
}
