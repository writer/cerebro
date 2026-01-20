# Cerebro Sync Engine Design

## CloudQuery Architecture Analysis

### Key Components Studied

1. **Plugin SDK** (`plugin-sdk`)
   - `schema.Table` - defines table structure with columns, resolvers, relations
   - `schema.Column` - column definition with type, primary key, incremental key flags
   - `scheduler.Scheduler` - concurrent sync with DFS/round-robin strategies
   - `transformers` - auto-generate columns from Go structs

2. **Scheduler Design**
   - Uses semaphores for concurrency control
   - `resourceSem` - limits concurrent resources being fetched
   - `tableSems` - per-depth table concurrency (reduces logarithmically)
   - Strategies: DFS, RoundRobin, Shuffle, ShuffleQueue
   - Default concurrency: 50,000 total, 5 per resource, 5 per nested table

3. **Snowflake Destination**
   - Uses staged file approach: write JSON → PUT to stage → COPY/MERGE into table
   - MERGE for upserts when primary keys exist
   - Batch writer for efficient bulk inserts
   - Schema type mapping: Arrow types → Snowflake types

4. **Source Plugin Pattern**
   - `TableResolver` - main fetch function per table
   - `Multiplexer` - enables multi-account/region sync
   - `PreResourceResolver` / `PostResourceResolver` - lifecycle hooks
   - `IsIncremental` flag for CDC-style syncing

### What Works Well
- Concurrent scheduling with backpressure
- Struct-to-table transformers
- Staged file uploads for bulk writes
- Multiplexer pattern for multi-account

### What Caused Us Problems
- MERGE failures with schema mismatches
- Complex plugin architecture for simple use cases
- External binary dependency
- No built-in change detection

---

## Cerebro Sync Engine Design

### Goals
1. **Simple** - Single binary, no external dependencies
2. **Fast** - Parallel sync with concurrency control
3. **Reliable** - Schema evolution, change detection, proper error handling
4. **Observable** - Track changes, emit metrics, alerting hooks

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         SyncEngine                               │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │  AWS     │  │  GCP     │  │  Azure   │  │  K8s     │        │
│  │ Provider │  │ Provider │  │ Provider │  │ Provider │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       │             │             │             │               │
│       ▼             ▼             ▼             ▼               │
│  ┌─────────────────────────────────────────────────────┐       │
│  │                  Resource Registry                   │       │
│  │  - Table definitions                                 │       │
│  │  - Column schemas                                    │       │
│  │  - Fetch functions                                   │       │
│  └─────────────────────────────────────────────────────┘       │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────┐       │
│  │                    Scheduler                         │       │
│  │  - Parallel execution                                │       │
│  │  - Rate limiting                                     │       │
│  │  - Error handling                                    │       │
│  └─────────────────────────────────────────────────────┘       │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────┐       │
│  │                  Change Detector                     │       │
│  │  - Hash existing rows                                │       │
│  │  - Compare with new data                             │       │
│  │  - Emit add/modify/remove events                     │       │
│  └─────────────────────────────────────────────────────┘       │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────┐       │
│  │                  Destination Writer                  │       │
│  │  - Schema evolution (ALTER TABLE)                    │       │
│  │  - Batch inserts                                     │       │
│  │  - Change history table                              │       │
│  └─────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

### Table Definition

```go
type Table struct {
    Name        string
    Description string
    Columns     []Column
    Resolver    func(ctx context.Context, client interface{}) ([]Resource, error)
    Relations   []*Table  // child tables
    PrimaryKey  []string
    Incremental bool
}

type Column struct {
    Name       string
    Type       ColumnType  // String, Int, Float, Bool, JSON, Timestamp
    PrimaryKey bool
    Required   bool
}
```

### Provider Interface

```go
type Provider interface {
    Name() string
    Tables() []*Table
    Configure(ctx context.Context, config []byte) error
}
```

### Change Detection

```go
type ChangeEvent struct {
    Table     string
    Operation string  // "add", "modify", "remove"
    ResourceID string
    OldHash   string
    NewHash   string
    Timestamp time.Time
    Diff      map[string]interface{}  // for modifications
}
```

### Implementation Plan

1. **Phase 1: Core Engine** ✅
   - [x] Table definition structs
   - [x] AWS provider with 14 resource types
   - [x] Schema evolution (ALTER TABLE)
   - [x] Basic change detection

2. **Phase 2: Improvements** (Current)
   - [ ] Fix change detection hashing
   - [ ] Parallel sync execution
   - [ ] Multi-region support
   - [ ] Change history table
   - [ ] Remove CloudQuery dependency

3. **Phase 3: Expansion**
   - [ ] More AWS resources (RDS, DynamoDB, ELB, etc.)
   - [ ] GCP provider
   - [ ] Azure provider
   - [ ] K8s provider

4. **Phase 4: Advanced**
   - [ ] Incremental sync (only fetch changed)
   - [ ] Real-time sync via CloudTrail/EventBridge
   - [ ] Alerting on risky changes
