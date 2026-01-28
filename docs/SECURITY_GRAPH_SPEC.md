# Security Graph Specification

## Research Summary

### Git Archaeology Findings

**Python attack path implementation** (commit `d23ed20`):
- Uses NetworkX for in-memory graph
- `IamEdge` table stores pre-computed permission edges
- `service_identity.py` maps CI/CD → cloud trust relationships
- `blast_radius.py` queries `IamEdge` table + BFS traversal
- Trust policy parsing in `findings/producers/aws/service_account_open_assume.py`

**Go codebase already has:**
- `internal/attackpath/graph.go` - Graph structure with Node/Edge types (but no builder)
- `internal/identity/service_mapper.go` - CI/CD to cloud identity mapping (GitHub/GitLab OIDC)
- `internal/snowflake/client.go` - Query returns `[]map[string]interface{}`
- `internal/webhooks/webhooks.go` - Event emission (can add `sync.completed` event)
- `internal/sync` table definitions including `assume_role_policy_document`

**Missing asset tables** (need to add to table definitions):
- `aws_iam_user_attached_policies` (user_arn, policy_arn)
- `aws_iam_role_attached_policies` (role_arn, policy_arn)  
- `aws_iam_role_policies` (role_name, policy_name, policy_document)
- `aws_iam_user_policies` (user_name, policy_name, policy_document)

### What Python Does (Source of Truth)

The Python codebase has a sophisticated IAM analysis system:

1. **Data Storage**: PostgreSQL with SQLAlchemy ORM
   - `IamEdge` table: `principal_id`, `resource_id`, `permission`, `via`, `is_admin`, `effective_at`, `expires_at`
   - `Principal` table: users, roles, service accounts across providers
   - `Resource` table: buckets, instances, databases
   - `IdentityCluster` table: cross-provider identity stitching

2. **Data Collection**: Providers call AWS/GCP/Azure APIs directly
   - `AWSProvider.discover_iam_edges()` - iterates all users/roles/groups
   - Parses inline policies and attached managed policies
   - Creates `IamPermission` objects that become `IamEdge` rows

3. **Graph Model** (`attack_path/graph_model.py`):
   - Uses NetworkX for in-memory graph
   - Nodes: principals, resources, services
   - Edges: direct_access, role_assignment, role_inheritance, service_identity, trust_relationship
   - Builds from PostgreSQL `IamEdge` + `Principal` + `Resource` tables

4. **Queries** (`attack_path/reachability.py`, `analysis/blast_radius.py`):
   - BFS traversal for reachability
   - Risk scoring based on resource sensitivity
   - Cross-provider impact via identity clusters

### What Go Has Now

1. **Data Source**: Snowflake with asset tables
   - `aws_iam_users`, `aws_iam_roles`, `aws_iam_policies`
   - Policy documents stored as VARIANT (JSON) in `document` column
   - No pre-computed edges - must parse policies at query time

2. **Existing Graph** (`internal/attackpath/graph.go`):
   - Empty shell - has Node/Edge types and BFS pathfinding
   - **No builder** - cannot populate from data
   - Not wired to any data source

3. **No IAM Policy Parser**:
   - Asset tables store raw policy JSON
   - We need to parse `{"Statement": [{"Effect": "Allow", "Action": [...], "Resource": [...]}]}`

### The Gap

| Component | Python | Go |
|-----------|--------|-----|
| IAM Edge Storage | PostgreSQL `iam_edges` table | None - must compute from asset tables |
| Policy Parser | Inline in providers | None - need to build or use `liamg/iamgo` |
| Graph Builder | Queries PostgreSQL | None - need to query Snowflake |
| Identity Stitching | `IdentityCluster` table | None |

### Available Go Libraries

- **`liamg/iamgo`** (MIT): Parses AWS IAM policy JSON, handles quirks (Action as string or array)
- **`aws-sdk-go-v2`**: Has IAM client but NOT policy parsing

### Key Insight

Python collects IAM data via boto3 and stores computed edges in PostgreSQL.
Go has asset data in Snowflake but must **recompute edges from policy documents**.

This is actually an advantage - we query the source of truth (raw policies) rather than pre-computed edges that might be stale.

---

## The Core Insight

The Security Graph is the product. Everything else is a query.

```
┌────────────────────────────────────────────────────────────────────┐
│                         SECURITY GRAPH                             │
│                                                                    │
│   ┌─────────┐     can_assume      ┌─────────┐                     │
│   │  User   │ ──────────────────► │  Role   │                     │
│   └─────────┘                     └─────────┘                     │
│        │                               │                          │
│        │ has_policy                    │ has_policy               │
│        ▼                               ▼                          │
│   ┌─────────┐                     ┌─────────┐                     │
│   │ Policy  │                     │ Policy  │                     │
│   └─────────┘                     └─────────┘                     │
│        │                               │                          │
│        │ allows                        │ allows                   │
│        ▼                               ▼                          │
│   ┌─────────┐     exposed_to      ┌─────────┐                     │
│   │ Bucket  │ ◄────────────────── │Internet │                     │
│   └─────────┘                     └─────────┘                     │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘

Queries on this graph:
- Blast Radius: "What can user X reach?" (forward traversal)
- Reverse Access: "Who can access bucket Y?" (reverse traversal)  
- Attack Path: "Path from internet to database Z?" (pathfinding)
- Toxic Combo: "Public + sensitive + unencrypted?" (pattern match)
- Peer Anomaly: "Edges X has that peers don't?" (set difference)
```

## Architecture

```
internal/
├── graph/                    # THE CORE - Security Graph
│   ├── graph.go              # Graph data structure (refactor from attackpath)
│   ├── node.go               # Node types and properties
│   ├── edge.go               # Edge types and properties
│   ├── builder.go            # Builds graph from data sources
│   ├── builder_aws.go        # AWS-specific node/edge extraction
│   ├── builder_gcp.go        # GCP-specific node/edge extraction
│   ├── builder_azure.go      # Azure-specific node/edge extraction
│   └── queries/              # Graph query implementations
│       ├── blast_radius.go   # Forward reachability
│       ├── reverse_access.go # Reverse reachability
│       ├── attack_path.go    # Path finding (move from attackpath/)
│       ├── toxic_combos.go   # Pattern matching
│       └── peer_analysis.go  # Comparative analysis
│
├── iampolicy/                # IAM Policy parsing (lowest primitive)
│   ├── parser.go             # Interface
│   ├── aws.go                # AWS IAM policy JSON parser
│   ├── gcp.go                # GCP IAM policy parser
│   ├── azure.go              # Azure RBAC parser
│   └── statement.go          # Normalized statement type
│
└── attackpath/               # DEPRECATED - move to graph/queries/
```

## Layer 1: IAM Policy Parser (Lowest Primitive)

Every cloud provider has IAM policies. We need to normalize them.

### AWS IAM Policy Format
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": "arn:aws:s3:::bucket/*",
    "Condition": {"StringEquals": {"s3:x-amz-acl": "public-read"}}
  }]
}
```

### GCP IAM Policy Format
```json
{
  "bindings": [{
    "role": "roles/storage.objectViewer",
    "members": ["user:alice@example.com", "serviceAccount:sa@project.iam.gserviceaccount.com"]
  }]
}
```

### Normalized Statement (our internal format)
```go
// internal/iampolicy/statement.go

type Statement struct {
    Effect     Effect              // Allow, Deny
    Actions    []string            // Normalized action names
    Resources  []string            // Resource ARN patterns
    Principals []string            // Who this applies to (for resource policies)
    Conditions map[string]any      // Provider-specific conditions
}

type Effect string
const (
    EffectAllow Effect = "allow"
    EffectDeny  Effect = "deny"
)
```

```go
// internal/iampolicy/parser.go

type Parser interface {
    // Parse takes a raw policy document and returns normalized statements
    Parse(document string) ([]Statement, error)
}

// internal/iampolicy/aws.go
type AWSParser struct{}
func (p *AWSParser) Parse(document string) ([]Statement, error)

// internal/iampolicy/gcp.go  
type GCPParser struct{}
func (p *GCPParser) Parse(document string) ([]Statement, error)
```

## Layer 2: Graph Data Structure

Refactor `internal/attackpath/graph.go` into `internal/graph/`.

### Nodes

```go
// internal/graph/node.go

type NodeKind string
const (
    // Identities
    NodeKindUser           NodeKind = "user"
    NodeKindRole           NodeKind = "role"
    NodeKindGroup          NodeKind = "group"
    NodeKindServiceAccount NodeKind = "service_account"
    
    // Resources
    NodeKindBucket         NodeKind = "bucket"
    NodeKindInstance       NodeKind = "instance"
    NodeKindDatabase       NodeKind = "database"
    NodeKindSecret         NodeKind = "secret"
    NodeKindFunction       NodeKind = "function"
    NodeKindContainer      NodeKind = "container"
    NodeKindNetwork        NodeKind = "network"
    
    // Abstract
    NodeKindPolicy         NodeKind = "policy"
    NodeKindInternet       NodeKind = "internet"  // Entry point
)

type Node struct {
    ID         string            `json:"id"`          // Unique ID (usually ARN)
    Kind       NodeKind          `json:"kind"`
    Name       string            `json:"name"`        // Human-readable
    Provider   string            `json:"provider"`    // aws, gcp, azure
    Account    string            `json:"account"`     // Account/Project ID
    Region     string            `json:"region,omitempty"`
    Properties map[string]any    `json:"properties"`  // Kind-specific properties
    Tags       map[string]string `json:"tags,omitempty"`
    Risk       RiskLevel         `json:"risk"`
    Findings   []string          `json:"findings,omitempty"` // Finding IDs
}

// Common properties by kind:
// - user: email, mfa_enabled, last_login, department, title
// - role: assumable_by, trust_policy
// - bucket: public, encrypted, versioning
// - instance: public_ip, imdsv2, security_groups
// - database: public, encrypted, multi_az
```

### Edges

```go
// internal/graph/edge.go

type EdgeKind string
const (
    // Identity -> Identity
    EdgeKindCanAssume    EdgeKind = "can_assume"    // User/Role can assume Role
    EdgeKindMemberOf     EdgeKind = "member_of"     // User is member of Group
    
    // Identity -> Resource (permissions)
    EdgeKindCanRead      EdgeKind = "can_read"
    EdgeKindCanWrite     EdgeKind = "can_write"
    EdgeKindCanDelete    EdgeKind = "can_delete"
    EdgeKindCanAdmin     EdgeKind = "can_admin"     // Full control
    
    // Resource -> Resource
    EdgeKindConnectsTo   EdgeKind = "connects_to"   // Network connectivity
    EdgeKindContains     EdgeKind = "contains"      // VPC contains subnet
    
    // Internet -> Resource
    EdgeKindExposedTo    EdgeKind = "exposed_to"    // Publicly accessible
    
    // Identity -> Policy -> Resource (for detailed view)
    EdgeKindHasPolicy    EdgeKind = "has_policy"
    EdgeKindAllows       EdgeKind = "allows"
)

type Edge struct {
    ID         string         `json:"id"`
    Source     string         `json:"source"`      // Source node ID
    Target     string         `json:"target"`      // Target node ID
    Kind       EdgeKind       `json:"kind"`
    Properties map[string]any `json:"properties"`  // e.g., specific actions, conditions
    Risk       RiskLevel      `json:"risk"`
}

// Properties by kind:
// - can_read/write/delete: actions ([]string), conditions
// - can_assume: trust_policy, external_id
// - exposed_to: ports ([]int), protocols
```

### Graph

```go
// internal/graph/graph.go

type Graph struct {
    nodes    map[string]*Node       // ID -> Node
    outEdges map[string][]*Edge     // Source ID -> Edges
    inEdges  map[string][]*Edge     // Target ID -> Edges (for reverse traversal)
    mu       sync.RWMutex
    
    metadata GraphMetadata
}

type GraphMetadata struct {
    BuiltAt      time.Time
    NodeCount    int
    EdgeCount    int
    Providers    []string
    Accounts     []string
    BuildDuration time.Duration
}

func NewGraph() *Graph

// Mutations
func (g *Graph) AddNode(node *Node)
func (g *Graph) AddEdge(edge *Edge)
func (g *Graph) RemoveNode(id string)
func (g *Graph) Clear()

// Lookups
func (g *Graph) GetNode(id string) (*Node, bool)
func (g *Graph) GetOutEdges(nodeID string) []*Edge    // Edges FROM this node
func (g *Graph) GetInEdges(nodeID string) []*Edge     // Edges TO this node

// Bulk queries
func (g *Graph) GetNodesByKind(kind NodeKind) []*Node
func (g *Graph) GetNodesByProvider(provider string) []*Node
func (g *Graph) GetAllNodes() []*Node
func (g *Graph) GetAllEdges() []*Edge

// Stats
func (g *Graph) Metadata() GraphMetadata
```

## Layer 3: Graph Builder

The builder populates the graph from Snowflake asset data.

```go
// internal/graph/builder.go

type DataSource interface {
    // Query Snowflake and return rows
    Query(ctx context.Context, query string, args ...any) ([]map[string]any, error)
    ListTables(ctx context.Context) ([]string, error)
}

type Builder struct {
    source     DataSource
    graph      *Graph
    parsers    map[string]iampolicy.Parser  // provider -> parser
    logger     *slog.Logger
}

func NewBuilder(source DataSource, logger *slog.Logger) *Builder

// Build constructs the entire graph from scratch
func (b *Builder) Build(ctx context.Context) error {
    b.graph.Clear()
    
    // Build in order: identities first, then resources, then edges
    if err := b.buildAWSNodes(ctx); err != nil { return err }
    if err := b.buildGCPNodes(ctx); err != nil { return err }
    if err := b.buildAzureNodes(ctx); err != nil { return err }
    
    if err := b.buildAWSEdges(ctx); err != nil { return err }
    if err := b.buildGCPEdges(ctx); err != nil { return err }
    if err := b.buildAzureEdges(ctx); err != nil { return err }
    
    // Add internet entry point node
    b.addInternetNode()
    
    // Add exposure edges (public resources)
    b.buildExposureEdges(ctx)
    
    return nil
}

// Graph returns the built graph
func (b *Builder) Graph() *Graph
```

### AWS Builder

```go
// internal/graph/builder_aws.go

func (b *Builder) buildAWSNodes(ctx context.Context) error {
    // IAM Users
    users, _ := b.source.Query(ctx, `
        SELECT _cq_id, account_id, arn, user_name, 
               password_last_used, tags
        FROM aws_iam_users
    `)
    for _, u := range users {
        b.graph.AddNode(&Node{
            ID:       u["arn"].(string),
            Kind:     NodeKindUser,
            Name:     u["user_name"].(string),
            Provider: "aws",
            Account:  u["account_id"].(string),
            Properties: map[string]any{
                "last_login": u["password_last_used"],
            },
        })
    }
    
    // IAM Roles
    roles, _ := b.source.Query(ctx, `
        SELECT _cq_id, account_id, arn, role_name,
               assume_role_policy_document
        FROM aws_iam_roles
    `)
    for _, r := range roles {
        b.graph.AddNode(&Node{
            ID:       r["arn"].(string),
            Kind:     NodeKindRole,
            Name:     r["role_name"].(string),
            Provider: "aws",
            Account:  r["account_id"].(string),
            Properties: map[string]any{
                "trust_policy": r["assume_role_policy_document"],
            },
        })
    }
    
    // S3 Buckets
    buckets, _ := b.source.Query(ctx, `
        SELECT _cq_id, account_id, arn, name, region,
               block_public_acls, block_public_policy,
               versioning_status, tags
        FROM aws_s3_buckets
    `)
    for _, bucket := range buckets {
        isPublic := !toBool(bucket["block_public_acls"]) || 
                    !toBool(bucket["block_public_policy"])
        b.graph.AddNode(&Node{
            ID:       bucket["arn"].(string),
            Kind:     NodeKindBucket,
            Name:     bucket["name"].(string),
            Provider: "aws",
            Account:  bucket["account_id"].(string),
            Region:   toString(bucket["region"]),
            Properties: map[string]any{
                "public":     isPublic,
                "versioning": bucket["versioning_status"],
            },
            Risk: riskFromPublic(isPublic),
        })
    }
    
    // EC2 Instances, RDS, Lambda, etc...
    return nil
}

func (b *Builder) buildAWSEdges(ctx context.Context) error {
    // User -> attached policies -> resources
    userPolicies, _ := b.source.Query(ctx, `
        SELECT uap.user_arn, p.arn as policy_arn, p.document
        FROM aws_iam_user_attached_policies uap
        JOIN aws_iam_policies p ON uap.policy_arn = p.arn
    `)
    
    parser := b.parsers["aws"]
    for _, up := range userPolicies {
        userARN := up["user_arn"].(string)
        document := toString(up["document"])
        
        statements, err := parser.Parse(document)
        if err != nil {
            continue
        }
        
        for _, stmt := range statements {
            if stmt.Effect != iampolicy.EffectAllow {
                continue
            }
            
            for _, resource := range stmt.Resources {
                edgeKind := actionsToEdgeKind(stmt.Actions)
                b.graph.AddEdge(&Edge{
                    ID:     userARN + "->" + resource,
                    Source: userARN,
                    Target: resource,
                    Kind:   edgeKind,
                    Properties: map[string]any{
                        "actions": stmt.Actions,
                        "via":     up["policy_arn"],
                    },
                })
            }
        }
    }
    
    // Role assumption edges (from trust policies)
    roles, _ := b.source.Query(ctx, `
        SELECT arn, assume_role_policy_document
        FROM aws_iam_roles
        WHERE assume_role_policy_document IS NOT NULL
    `)
    for _, role := range roles {
        roleARN := role["arn"].(string)
        trustPolicy := toString(role["assume_role_policy_document"])
        
        // Parse trust policy to find who can assume
        principals := extractTrustPrincipals(trustPolicy)
        for _, principal := range principals {
            b.graph.AddEdge(&Edge{
                ID:     principal + "->assume->" + roleARN,
                Source: principal,
                Target: roleARN,
                Kind:   EdgeKindCanAssume,
            })
        }
    }
    
    return nil
}

func (b *Builder) buildExposureEdges(ctx context.Context) error {
    // Find all public nodes and connect them to "internet"
    for _, node := range b.graph.GetAllNodes() {
        if isPublic, ok := node.Properties["public"].(bool); ok && isPublic {
            b.graph.AddEdge(&Edge{
                ID:     "internet->" + node.ID,
                Source: "internet",
                Target: node.ID,
                Kind:   EdgeKindExposedTo,
                Risk:   RiskHigh,
            })
        }
    }
    return nil
}

func actionsToEdgeKind(actions []string) EdgeKind {
    hasWrite := false
    hasDelete := false
    hasAdmin := false
    
    for _, action := range actions {
        if action == "*" || strings.Contains(action, ":*") {
            hasAdmin = true
        }
        if strings.Contains(action, "Put") || strings.Contains(action, "Create") || 
           strings.Contains(action, "Update") || strings.Contains(action, "Write") {
            hasWrite = true
        }
        if strings.Contains(action, "Delete") || strings.Contains(action, "Remove") {
            hasDelete = true
        }
    }
    
    if hasAdmin {
        return EdgeKindCanAdmin
    }
    if hasDelete {
        return EdgeKindCanDelete
    }
    if hasWrite {
        return EdgeKindCanWrite
    }
    return EdgeKindCanRead
}
```

## Layer 4: Graph Queries

All the "features" are queries on the graph.

### Blast Radius (Forward Reachability)

```go
// internal/graph/queries/blast_radius.go

type BlastRadiusResult struct {
    PrincipalID    string           `json:"principal_id"`
    PrincipalName  string           `json:"principal_name"`
    ReachableNodes []*ReachableNode `json:"reachable_nodes"`
    TotalCount     int              `json:"total_count"`
    MaxDepth       int              `json:"max_depth"`
    RiskSummary    RiskSummary      `json:"risk_summary"`
}

type ReachableNode struct {
    Node     *Node    `json:"node"`
    Depth    int      `json:"depth"`
    Path     []string `json:"path"`      // Node IDs in path
    EdgeKind EdgeKind `json:"edge_kind"` // How they can access
    Actions  []string `json:"actions"`   // Specific actions
}

type RiskSummary struct {
    Critical int `json:"critical"`
    High     int `json:"high"`
    Medium   int `json:"medium"`
    Low      int `json:"low"`
}

func BlastRadius(g *Graph, principalID string, maxDepth int) (*BlastRadiusResult, error) {
    principal, ok := g.GetNode(principalID)
    if !ok {
        return nil, fmt.Errorf("principal not found: %s", principalID)
    }
    
    result := &BlastRadiusResult{
        PrincipalID:   principalID,
        PrincipalName: principal.Name,
        MaxDepth:      maxDepth,
    }
    
    // BFS traversal
    visited := make(map[string]bool)
    queue := []struct {
        nodeID string
        depth  int
        path   []string
    }{{principalID, 0, []string{principalID}}}
    
    for len(queue) > 0 {
        current := queue[0]
        queue = queue[1:]
        
        if current.depth > maxDepth || visited[current.nodeID] {
            continue
        }
        visited[current.nodeID] = true
        
        for _, edge := range g.GetOutEdges(current.nodeID) {
            targetNode, _ := g.GetNode(edge.Target)
            if targetNode == nil {
                continue
            }
            
            newPath := append([]string{}, current.path...)
            newPath = append(newPath, edge.Target)
            
            // Only include resource nodes in results, not intermediate roles
            if isResourceKind(targetNode.Kind) {
                result.ReachableNodes = append(result.ReachableNodes, &ReachableNode{
                    Node:     targetNode,
                    Depth:    current.depth + 1,
                    Path:     newPath,
                    EdgeKind: edge.Kind,
                    Actions:  toStringSlice(edge.Properties["actions"]),
                })
                
                // Update risk summary
                switch targetNode.Risk {
                case RiskCritical: result.RiskSummary.Critical++
                case RiskHigh:     result.RiskSummary.High++
                case RiskMedium:   result.RiskSummary.Medium++
                case RiskLow:      result.RiskSummary.Low++
                }
            }
            
            queue = append(queue, struct {
                nodeID string
                depth  int
                path   []string
            }{edge.Target, current.depth + 1, newPath})
        }
    }
    
    result.TotalCount = len(result.ReachableNodes)
    return result, nil
}
```

### Reverse Access (Who Can Access This?)

```go
// internal/graph/queries/reverse_access.go

type ReverseAccessResult struct {
    ResourceID     string            `json:"resource_id"`
    ResourceName   string            `json:"resource_name"`
    AccessibleBy   []*AccessorNode   `json:"accessible_by"`
    TotalCount     int               `json:"total_count"`
}

type AccessorNode struct {
    Node     *Node    `json:"node"`
    EdgeKind EdgeKind `json:"edge_kind"`
    Path     []string `json:"path"`      // Reverse path
    Actions  []string `json:"actions"`
}

func ReverseAccess(g *Graph, resourceID string, maxDepth int) (*ReverseAccessResult, error) {
    resource, ok := g.GetNode(resourceID)
    if !ok {
        return nil, fmt.Errorf("resource not found: %s", resourceID)
    }
    
    result := &ReverseAccessResult{
        ResourceID:   resourceID,
        ResourceName: resource.Name,
    }
    
    // Reverse BFS using inEdges
    visited := make(map[string]bool)
    queue := []struct {
        nodeID string
        depth  int
        path   []string
    }{{resourceID, 0, []string{resourceID}}}
    
    for len(queue) > 0 {
        current := queue[0]
        queue = queue[1:]
        
        if current.depth > maxDepth || visited[current.nodeID] {
            continue
        }
        visited[current.nodeID] = true
        
        for _, edge := range g.GetInEdges(current.nodeID) {
            sourceNode, _ := g.GetNode(edge.Source)
            if sourceNode == nil {
                continue
            }
            
            newPath := append([]string{edge.Source}, current.path...)
            
            // Include identity nodes (users, roles, service accounts)
            if isIdentityKind(sourceNode.Kind) {
                result.AccessibleBy = append(result.AccessibleBy, &AccessorNode{
                    Node:     sourceNode,
                    EdgeKind: edge.Kind,
                    Path:     newPath,
                    Actions:  toStringSlice(edge.Properties["actions"]),
                })
            }
            
            queue = append(queue, struct {
                nodeID string
                depth  int
                path   []string
            }{edge.Source, current.depth + 1, newPath})
        }
    }
    
    result.TotalCount = len(result.AccessibleBy)
    return result, nil
}
```

### Toxic Combinations (Pattern Matching)

```go
// internal/graph/queries/toxic_combos.go

type ToxicCombo struct {
    ID          string   `json:"id"`
    Name        string   `json:"name"`
    Description string   `json:"description"`
    Severity    RiskLevel `json:"severity"`
    Nodes       []*Node  `json:"nodes"`
    Reason      string   `json:"reason"`
    Remediation []string `json:"remediation"`
}

// Predefined toxic combination patterns
var ToxicPatterns = []ToxicPattern{
    {
        Name:        "Public bucket with sensitive data",
        Description: "S3 bucket is publicly accessible and contains sensitive data",
        Severity:    RiskCritical,
        Match: func(g *Graph) []*ToxicCombo {
            var combos []*ToxicCombo
            for _, node := range g.GetNodesByKind(NodeKindBucket) {
                isPublic, _ := node.Properties["public"].(bool)
                hasSensitive, _ := node.Properties["has_sensitive_data"].(bool)
                
                if isPublic && hasSensitive {
                    combos = append(combos, &ToxicCombo{
                        ID:          "toxic-" + node.ID,
                        Name:        "Public bucket with sensitive data",
                        Severity:    RiskCritical,
                        Nodes:       []*Node{node},
                        Reason:      fmt.Sprintf("Bucket %s is public and contains sensitive data", node.Name),
                        Remediation: []string{"Block public access", "Enable bucket encryption"},
                    })
                }
            }
            return combos
        },
    },
    {
        Name:        "Admin without MFA",
        Description: "User with admin permissions has MFA disabled",
        Severity:    RiskCritical,
        Match: func(g *Graph) []*ToxicCombo {
            var combos []*ToxicCombo
            for _, node := range g.GetNodesByKind(NodeKindUser) {
                mfaEnabled, _ := node.Properties["mfa_enabled"].(bool)
                if mfaEnabled {
                    continue
                }
                
                // Check if user has admin edges
                for _, edge := range g.GetOutEdges(node.ID) {
                    if edge.Kind == EdgeKindCanAdmin {
                        combos = append(combos, &ToxicCombo{
                            ID:          "toxic-" + node.ID,
                            Name:        "Admin without MFA",
                            Severity:    RiskCritical,
                            Nodes:       []*Node{node},
                            Reason:      fmt.Sprintf("User %s has admin access but MFA is disabled", node.Name),
                            Remediation: []string{"Enable MFA immediately"},
                        })
                        break
                    }
                }
            }
            return combos
        },
    },
    {
        Name:        "Internet-exposed database",
        Description: "Database is accessible from the internet",
        Severity:    RiskCritical,
        Match: func(g *Graph) []*ToxicCombo {
            var combos []*ToxicCombo
            internetNode, _ := g.GetNode("internet")
            if internetNode == nil {
                return combos
            }
            
            // BFS from internet to find databases
            for _, node := range g.GetNodesByKind(NodeKindDatabase) {
                // Check if there's a path from internet to this database
                if path := findPath(g, "internet", node.ID, 5); path != nil {
                    combos = append(combos, &ToxicCombo{
                        ID:          "toxic-" + node.ID,
                        Name:        "Internet-exposed database",
                        Severity:    RiskCritical,
                        Nodes:       []*Node{node},
                        Reason:      fmt.Sprintf("Database %s is reachable from internet", node.Name),
                        Remediation: []string{"Restrict public access", "Use private subnet"},
                    })
                }
            }
            return combos
        },
    },
}

func FindToxicCombos(g *Graph) []*ToxicCombo {
    var all []*ToxicCombo
    for _, pattern := range ToxicPatterns {
        all = append(all, pattern.Match(g)...)
    }
    return all
}
```

### Peer Analysis

```go
// internal/graph/queries/peer_analysis.go

type PeerAnalysisResult struct {
    PrincipalID       string            `json:"principal_id"`
    PrincipalName     string            `json:"principal_name"`
    Department        string            `json:"department"`
    Role              string            `json:"role"`
    PeerGroupSize     int               `json:"peer_group_size"`
    UnusualEdges      []*UnusualEdge    `json:"unusual_edges"`
    RiskScore         float64           `json:"risk_score"`
    Recommendations   []string          `json:"recommendations"`
}

type UnusualEdge struct {
    Edge          *Edge   `json:"edge"`
    TargetNode    *Node   `json:"target_node"`
    PeerFrequency float64 `json:"peer_frequency"` // What % of peers have this
}

func PeerAnalysis(g *Graph, principalID string, peerIDs []string) (*PeerAnalysisResult, error) {
    principal, ok := g.GetNode(principalID)
    if !ok {
        return nil, fmt.Errorf("principal not found: %s", principalID)
    }
    
    // Get edges for principal
    principalEdges := make(map[string]*Edge)
    for _, edge := range g.GetOutEdges(principalID) {
        key := edge.Target + ":" + string(edge.Kind)
        principalEdges[key] = edge
    }
    
    // Count edge frequencies across peers
    edgeCounts := make(map[string]int)
    for _, peerID := range peerIDs {
        for _, edge := range g.GetOutEdges(peerID) {
            key := edge.Target + ":" + string(edge.Kind)
            edgeCounts[key]++
        }
    }
    
    // Find edges that principal has but few peers have
    result := &PeerAnalysisResult{
        PrincipalID:   principalID,
        PrincipalName: principal.Name,
        Department:    toString(principal.Properties["department"]),
        Role:          toString(principal.Properties["title"]),
        PeerGroupSize: len(peerIDs),
    }
    
    for key, edge := range principalEdges {
        peerCount := edgeCounts[key]
        frequency := float64(peerCount) / float64(len(peerIDs))
        
        // Flag if less than 10% of peers have this edge
        if frequency < 0.1 {
            targetNode, _ := g.GetNode(edge.Target)
            result.UnusualEdges = append(result.UnusualEdges, &UnusualEdge{
                Edge:          edge,
                TargetNode:    targetNode,
                PeerFrequency: frequency,
            })
        }
    }
    
    // Calculate risk score
    result.RiskScore = calculatePeerRiskScore(result.UnusualEdges)
    result.Recommendations = generatePeerRecommendations(result)
    
    return result, nil
}
```

## Wiring It All Together

```go
// internal/app/app.go

type App struct {
    // ... existing fields ...
    
    Graph        *graph.Graph        // THE security graph
    GraphBuilder *graph.Builder      // Builds graph from Snowflake
}

func (a *App) initGraph(ctx context.Context) {
    if a.Snowflake == nil {
        return
    }
    
    a.Graph = graph.NewGraph()
    a.GraphBuilder = graph.NewBuilder(a.Snowflake, a.Logger)
    
    // Initial build
    if err := a.GraphBuilder.Build(ctx); err != nil {
        a.Logger.Error("failed to build security graph", "error", err)
    }
    
    // Schedule periodic rebuilds
    a.Scheduler.AddJob("graph-rebuild", 1*time.Hour, func(ctx context.Context) error {
        return a.GraphBuilder.Build(ctx)
    })
}
```

## API Endpoints

```go
// All endpoints query the same graph

// Blast radius
GET /api/v1/graph/blast-radius/{principal_id}?max_depth=3

// Reverse access  
GET /api/v1/graph/reverse-access/{resource_id}?max_depth=3

// Attack paths
GET /api/v1/graph/attack-paths?from={node_id}&to={node_id}
GET /api/v1/graph/attack-paths/to-high-value

// Toxic combinations
GET /api/v1/graph/toxic-combos

// Peer analysis
GET /api/v1/graph/peer-analysis/{principal_id}?department={dept}

// Raw graph access (for visualization)
GET /api/v1/graph/nodes?kind={kind}&provider={provider}
GET /api/v1/graph/edges?source={id}
GET /api/v1/graph/stats
```

## Implementation Order

### Phase 1: Foundation (1 week)
1. Create `internal/iampolicy/` package with AWS parser
2. Create `internal/graph/` package (refactor from attackpath)
3. Basic builder that creates nodes from asset tables

### Phase 2: Edges (1 week)
1. Parse AWS IAM policies into edges
2. Parse trust policies for assume role edges
3. Build exposure edges (internet -> public resources)

### Phase 3: Queries (1 week)
1. Blast radius query
2. Reverse access query
3. Attack path (move from existing attackpath)

### Phase 4: Advanced (1 week)
1. Toxic combination patterns
2. Peer analysis (requires identity data with departments)
3. GCP and Azure support

---

## Why This Architecture

1. **Single Source of Truth** - All security relationships in one graph
2. **Composable** - New queries are just graph traversals
3. **Cacheable** - Build once, query many times
4. **Debuggable** - Can visualize the graph to understand relationships
5. **Extensible** - Add new node/edge types without changing query logic

This is exactly how Wiz works - they build a graph and everything else is derived from it.

---

## Detailed Implementation Plan

### Phase 1: IAM Policy Parser

**Goal**: Parse AWS IAM policy JSON into normalized statements

**Option A: Use `liamg/iamgo` (Recommended)**
```bash
go get github.com/liamg/iamgo
```

```go
// internal/iampolicy/aws.go

import "github.com/liamg/iamgo"

type AWSParser struct{}

func (p *AWSParser) Parse(document string) ([]Statement, error) {
    doc, err := iamgo.Parse([]byte(document))
    if err != nil {
        return nil, err
    }
    
    var statements []Statement
    for _, stmt := range doc.Statements() {
        statements = append(statements, Statement{
            Effect:    string(stmt.Effect()),
            Actions:   stmt.Actions(),
            Resources: stmt.Resources(),
            // iamgo handles the quirks (Action can be string or []string)
        })
    }
    return statements, nil
}
```

**Option B: Roll our own** (if iamgo doesn't handle trust policies well)
```go
// Handle AWS policy document quirks:
// - Action can be string or []string
// - Resource can be string or []string  
// - Principal can be "*" or {"AWS": "arn:..."} or {"Service": "ec2.amazonaws.com"}
```

### Phase 1: Graph Package Structure

```
internal/graph/
├── graph.go           # Graph struct with nodes/edges maps + mutex
├── node.go            # Node struct and NodeKind enum
├── edge.go            # Edge struct and EdgeKind enum
├── builder.go         # Builder interface and implementation
├── builder_aws.go     # AWS-specific node/edge building
├── queries.go         # BlastRadius, ReverseAccess, etc.
└── graph_test.go      # Tests with mock data
```

### Phase 1: Exact Asset Queries

```sql
-- 1. Get all IAM users (nodes)
SELECT 
    arn,
    user_name,
    account_id,
    password_last_used,
    tags
FROM aws_iam_users;

-- 2. Get all IAM roles (nodes)
SELECT 
    arn,
    role_name,
    account_id,
    assume_role_policy_document,
    description
FROM aws_iam_roles;

-- 3. Get user -> policy attachments
SELECT 
    user_arn,
    policy_arn
FROM aws_iam_user_attached_policies;

-- 4. Get role -> policy attachments  
SELECT
    role_arn,
    policy_arn
FROM aws_iam_role_attached_policies;

-- 5. Get policy documents (the actual permissions)
-- NOTE: aws_iam_policies has `document` as VARIANT
SELECT 
    arn,
    name,
    document
FROM aws_iam_policies;

-- 6. Get inline role policies (not managed policies)
SELECT
    role_name,
    policy_name,
    policy_document
FROM aws_iam_role_policies;

-- 7. Get S3 buckets (resource nodes)
SELECT
    arn,
    name,
    account_id,
    region,
    block_public_acls,
    block_public_policy
FROM aws_s3_buckets;

-- 8. Get EC2 instances (resource nodes)
SELECT
    arn,
    instance_id,
    account_id,
    region,
    public_ip_address,
    iam_instance_profile
FROM aws_ec2_instances;

-- 9. Get RDS instances (resource nodes)
SELECT
    arn,
    db_instance_identifier,
    account_id,
    region,
    publicly_accessible,
    storage_encrypted
FROM aws_rds_instances;
```

### Phase 2: Edge Building Logic

```go
// For each user, find their policies and parse into edges
func (b *Builder) buildUserEdges(ctx context.Context) error {
    // Step 1: Get user -> policy mappings
    attachments, _ := b.source.Query(ctx, `
        SELECT user_arn, policy_arn 
        FROM aws_iam_user_attached_policies
    `)
    
    // Step 2: Get policy documents
    policies, _ := b.source.Query(ctx, `
        SELECT arn, document FROM aws_iam_policies
    `)
    policyDocs := make(map[string]string)
    for _, p := range policies {
        policyDocs[p["arn"].(string)] = p["document"].(string)
    }
    
    // Step 3: For each attachment, parse policy and create edges
    for _, att := range attachments {
        userARN := att["user_arn"].(string)
        policyARN := att["policy_arn"].(string)
        
        doc, ok := policyDocs[policyARN]
        if !ok {
            continue
        }
        
        statements, err := b.parser.Parse(doc)
        if err != nil {
            b.logger.Warn("failed to parse policy", "policy", policyARN, "error", err)
            continue
        }
        
        for _, stmt := range statements {
            if stmt.Effect != "Allow" {
                continue // Skip Deny statements for now
            }
            
            for _, resource := range stmt.Resources {
                // Resource might be a pattern like "arn:aws:s3:::*"
                // We need to match it against actual resources
                matchingNodes := b.matchResourcePattern(resource)
                
                for _, node := range matchingNodes {
                    b.graph.AddEdge(&Edge{
                        Source: userARN,
                        Target: node.ID,
                        Kind:   actionsToEdgeKind(stmt.Actions),
                        Properties: map[string]any{
                            "actions":    stmt.Actions,
                            "via":        policyARN,
                            "conditions": stmt.Conditions,
                        },
                    })
                }
            }
        }
    }
    return nil
}

// Match resource pattern to actual graph nodes
func (b *Builder) matchResourcePattern(pattern string) []*Node {
    // Handle patterns like:
    // - "arn:aws:s3:::my-bucket/*" -> match bucket node
    // - "arn:aws:s3:::*" -> match all buckets
    // - "*" -> match everything (admin)
    
    if pattern == "*" {
        return b.graph.GetNodesByKind(NodeKindBucket, NodeKindInstance, NodeKindDatabase)
    }
    
    // For now, do simple prefix matching
    var matches []*Node
    for _, node := range b.graph.GetAllNodes() {
        if matchesARNPattern(node.ID, pattern) {
            matches = append(matches, node)
        }
    }
    return matches
}
```

### Phase 2: Trust Policy Parsing (Role Assumption)

```go
// Parse assume_role_policy_document to find who can assume a role
func (b *Builder) buildAssumeRoleEdges(ctx context.Context) error {
    roles, _ := b.source.Query(ctx, `
        SELECT arn, assume_role_policy_document
        FROM aws_iam_roles
        WHERE assume_role_policy_document IS NOT NULL
    `)
    
    for _, role := range roles {
        roleARN := role["arn"].(string)
        trustPolicy := role["assume_role_policy_document"].(string)
        
        // Trust policy format:
        // {
        //   "Statement": [{
        //     "Effect": "Allow",
        //     "Principal": {"AWS": "arn:aws:iam::123:user/alice"},
        //     "Action": "sts:AssumeRole"
        //   }]
        // }
        
        principals := extractTrustPrincipals(trustPolicy)
        for _, principalARN := range principals {
            // Create can_assume edge: principal -> role
            b.graph.AddEdge(&Edge{
                Source: principalARN,
                Target: roleARN,
                Kind:   EdgeKindCanAssume,
                Properties: map[string]any{
                    "mechanism": "trust_policy",
                },
            })
        }
    }
    return nil
}

func extractTrustPrincipals(trustPolicy string) []string {
    var doc struct {
        Statement []struct {
            Effect    string
            Principal any // Can be "*", string, or {"AWS": ...}
            Action    any
        }
    }
    json.Unmarshal([]byte(trustPolicy), &doc)
    
    var principals []string
    for _, stmt := range doc.Statement {
        if stmt.Effect != "Allow" {
            continue
        }
        
        switch p := stmt.Principal.(type) {
        case string:
            if p == "*" {
                principals = append(principals, "internet") // Anyone can assume!
            } else {
                principals = append(principals, p)
            }
        case map[string]any:
            if aws, ok := p["AWS"]; ok {
                switch a := aws.(type) {
                case string:
                    principals = append(principals, a)
                case []any:
                    for _, arn := range a {
                        principals = append(principals, arn.(string))
                    }
                }
            }
            if svc, ok := p["Service"]; ok {
                // Service principal like "ec2.amazonaws.com"
                principals = append(principals, "service:"+svc.(string))
            }
        }
    }
    return principals
}
```

### Phase 3: Query Implementation

```go
// BlastRadius: Forward BFS from a principal
func BlastRadius(g *Graph, principalID string, maxDepth int) *BlastRadiusResult {
    result := &BlastRadiusResult{PrincipalID: principalID}
    
    visited := make(map[string]bool)
    type queueItem struct {
        nodeID string
        depth  int
        path   []string
    }
    queue := []queueItem{{principalID, 0, []string{principalID}}}
    
    for len(queue) > 0 {
        item := queue[0]
        queue = queue[1:]
        
        if item.depth > maxDepth || visited[item.nodeID] {
            continue
        }
        visited[item.nodeID] = true
        
        for _, edge := range g.GetOutEdges(item.nodeID) {
            targetNode, ok := g.GetNode(edge.Target)
            if !ok {
                continue
            }
            
            newPath := append([]string{}, item.path...)
            newPath = append(newPath, edge.Target)
            
            // Collect resource nodes (not intermediate roles)
            if isResourceKind(targetNode.Kind) {
                result.ReachableNodes = append(result.ReachableNodes, &ReachableNode{
                    Node:     targetNode,
                    Depth:    item.depth + 1,
                    Path:     newPath,
                    EdgeKind: edge.Kind,
                    Actions:  edge.Properties["actions"].([]string),
                })
            }
            
            // Continue traversal (for role assumption chains)
            queue = append(queue, queueItem{
                nodeID: edge.Target,
                depth:  item.depth + 1,
                path:   newPath,
            })
        }
    }
    
    return result
}
```

### Testing Strategy

```go
// internal/graph/graph_test.go

func TestBuilder_AWS(t *testing.T) {
    // Mock Snowflake source
    source := &MockDataSource{
        tables: map[string][]map[string]any{
            "aws_iam_users": {
                {"arn": "arn:aws:iam::123:user/alice", "user_name": "alice", "account_id": "123"},
            },
            "aws_iam_policies": {
                {
                    "arn": "arn:aws:iam::123:policy/S3ReadOnly",
                    "document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::my-bucket/*"}]}`,
                },
            },
            "aws_iam_user_attached_policies": {
                {"user_arn": "arn:aws:iam::123:user/alice", "policy_arn": "arn:aws:iam::123:policy/S3ReadOnly"},
            },
            "aws_s3_buckets": {
                {"arn": "arn:aws:s3:::my-bucket", "name": "my-bucket", "account_id": "123"},
            },
        },
    }
    
    builder := NewBuilder(source, slog.Default())
    err := builder.Build(context.Background())
    require.NoError(t, err)
    
    g := builder.Graph()
    
    // Verify nodes
    aliceNode, ok := g.GetNode("arn:aws:iam::123:user/alice")
    assert.True(t, ok)
    assert.Equal(t, NodeKindUser, aliceNode.Kind)
    
    // Verify edges
    edges := g.GetOutEdges("arn:aws:iam::123:user/alice")
    assert.Len(t, edges, 1)
    assert.Equal(t, "arn:aws:s3:::my-bucket", edges[0].Target)
    assert.Equal(t, EdgeKindCanRead, edges[0].Kind)
}

func TestBlastRadius(t *testing.T) {
    g := NewGraph()
    
    // Setup: alice -> can_assume -> AdminRole -> can_admin -> prod-db
    g.AddNode(&Node{ID: "alice", Kind: NodeKindUser})
    g.AddNode(&Node{ID: "AdminRole", Kind: NodeKindRole})
    g.AddNode(&Node{ID: "prod-db", Kind: NodeKindDatabase, Risk: RiskCritical})
    
    g.AddEdge(&Edge{Source: "alice", Target: "AdminRole", Kind: EdgeKindCanAssume})
    g.AddEdge(&Edge{Source: "AdminRole", Target: "prod-db", Kind: EdgeKindCanAdmin})
    
    result := BlastRadius(g, "alice", 3)
    
    assert.Len(t, result.ReachableNodes, 1)
    assert.Equal(t, "prod-db", result.ReachableNodes[0].Node.ID)
    assert.Equal(t, 2, result.ReachableNodes[0].Depth)
    assert.Equal(t, []string{"alice", "AdminRole", "prod-db"}, result.ReachableNodes[0].Path)
}
```

---

## Design Decisions

1. **ARN Pattern Matching**: Full wildcard parsing
2. **Graph Rebuild**: On sync completion (webhook or scheduler)
3. **Deny Statements**: Model everything - denies evaluated before allows
4. **Cross-Account**: Full support for cross-account role assumption

---

## Full ARN Wildcard Matching

AWS ARN patterns can include wildcards at any position:
- `arn:aws:s3:::*` - all buckets
- `arn:aws:s3:::my-bucket/*` - all objects in bucket
- `arn:aws:s3:::*-prod-*` - buckets with "prod" in name
- `arn:aws:iam::*:role/Admin*` - Admin roles in any account

```go
// internal/graph/arn.go

// ARN structure: arn:partition:service:region:account:resource
type ARN struct {
    Partition string // aws, aws-cn, aws-us-gov
    Service   string // s3, iam, ec2
    Region    string // us-east-1, * for global
    Account   string // 123456789012, *
    Resource  string // bucket-name, role/RoleName
}

func ParseARN(arn string) (*ARN, error) {
    // Handle special case "*" = match everything
    if arn == "*" {
        return &ARN{Partition: "*", Service: "*", Region: "*", Account: "*", Resource: "*"}, nil
    }
    
    parts := strings.SplitN(arn, ":", 6)
    if len(parts) < 6 {
        return nil, fmt.Errorf("invalid ARN: %s", arn)
    }
    
    return &ARN{
        Partition: parts[1],
        Service:   parts[2],
        Region:    parts[3],
        Account:   parts[4],
        Resource:  parts[5],
    }, nil
}

// MatchesPattern checks if this ARN matches a pattern ARN (with wildcards)
func (a *ARN) MatchesPattern(pattern *ARN) bool {
    return matchComponent(a.Partition, pattern.Partition) &&
           matchComponent(a.Service, pattern.Service) &&
           matchComponent(a.Region, pattern.Region) &&
           matchComponent(a.Account, pattern.Account) &&
           matchComponent(a.Resource, pattern.Resource)
}

// matchComponent handles AWS wildcard matching
// Supports: * (match all), ? (match single char), and literal
func matchComponent(value, pattern string) bool {
    if pattern == "*" || pattern == "" {
        return true
    }
    
    // Convert AWS pattern to regex
    // * matches any sequence, ? matches single char
    regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
    regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")
    regexPattern = strings.ReplaceAll(regexPattern, `\?`, ".")
    
    matched, _ := regexp.MatchString(regexPattern, value)
    return matched
}

// FindMatchingNodes returns all graph nodes matching an ARN pattern
func (b *Builder) FindMatchingNodes(pattern string) []*Node {
    patternARN, err := ParseARN(pattern)
    if err != nil {
        return nil
    }
    
    var matches []*Node
    for _, node := range b.graph.GetAllNodes() {
        // Only match resource nodes, not identities
        if !isResourceKind(node.Kind) {
            continue
        }
        
        nodeARN, err := ParseARN(node.ID)
        if err != nil {
            continue
        }
        
        if nodeARN.MatchesPattern(patternARN) {
            matches = append(matches, node)
        }
    }
    return matches
}
```

---

## Webhook-Triggered Graph Rebuild

Rebuild graph when native sync completes:

```go
// internal/webhooks/sync.go

type SyncWebhook struct {
    graphBuilder *graph.Builder
    logger       *slog.Logger
}

func (w *SyncWebhook) HandleSyncComplete(c *gin.Context) {
    var payload struct {
        SyncID    string    `json:"sync_id"`
        Status    string    `json:"status"`
        Tables    []string  `json:"tables"`
        Timestamp time.Time `json:"timestamp"`
    }
    
    if err := c.BindJSON(&payload); err != nil {
        c.JSON(400, gin.H{"error": "invalid payload"})
        return
    }
    
    if payload.Status != "completed" {
        c.JSON(200, gin.H{"status": "ignored", "reason": "sync not completed"})
        return
    }
    
    // Check if IAM-related tables were synced
    iamTables := []string{
        "aws_iam_users", "aws_iam_roles", "aws_iam_policies",
        "aws_iam_user_attached_policies", "aws_iam_role_attached_policies",
    }
    
    needsRebuild := false
    for _, table := range payload.Tables {
        for _, iamTable := range iamTables {
            if table == iamTable {
                needsRebuild = true
                break
            }
        }
    }
    
    if !needsRebuild {
        c.JSON(200, gin.H{"status": "ignored", "reason": "no IAM tables synced"})
        return
    }
    
    // Trigger async rebuild
    go func() {
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
        defer cancel()
        
		w.logger.Info("rebuilding security graph after sync",
            "sync_id", payload.SyncID,
            "tables", payload.Tables)
        
        if err := w.graphBuilder.Build(ctx); err != nil {
            w.logger.Error("failed to rebuild graph", "error", err)
        } else {
            w.logger.Info("security graph rebuilt successfully",
                "nodes", w.graphBuilder.Graph().NodeCount(),
                "edges", w.graphBuilder.Graph().EdgeCount())
        }
    }()
    
    c.JSON(202, gin.H{"status": "accepted", "message": "graph rebuild triggered"})
}

// Wire up in server.go
func (s *Server) setupRoutes() {
    // ... existing routes ...
    
    s.router.POST("/webhooks/sync", s.syncWebhook.HandleSyncComplete)
}
```

---

## Modeling Deny Statements

AWS policy evaluation order:
1. Explicit Deny -> DENY (highest priority)
2. Explicit Allow -> ALLOW
3. Implicit Deny (default)

```go
// internal/graph/edge.go

type EdgeEffect string
const (
    EdgeEffectAllow EdgeEffect = "allow"
    EdgeEffectDeny  EdgeEffect = "deny"
)

type Edge struct {
    ID         string         `json:"id"`
    Source     string         `json:"source"`
    Target     string         `json:"target"`
    Kind       EdgeKind       `json:"kind"`
    Effect     EdgeEffect     `json:"effect"`     // NEW: allow or deny
    Priority   int            `json:"priority"`   // NEW: deny=100, allow=50
    Properties map[string]any `json:"properties"`
    Risk       RiskLevel      `json:"risk"`
}

// internal/graph/builder_aws.go

func (b *Builder) buildPolicyEdges(ctx context.Context, principalARN, policyDoc string, via string) error {
    statements, err := b.parser.Parse(policyDoc)
    if err != nil {
        return err
    }
    
    for _, stmt := range statements {
        effect := EdgeEffectAllow
        priority := 50
        if stmt.Effect == "Deny" {
            effect = EdgeEffectDeny
            priority = 100 // Deny always wins
        }
        
        for _, resource := range stmt.Resources {
            matchingNodes := b.FindMatchingNodes(resource)
            
            for _, node := range matchingNodes {
                b.graph.AddEdge(&Edge{
                    ID:       fmt.Sprintf("%s->%s:%s", principalARN, node.ID, stmt.Effect),
                    Source:   principalARN,
                    Target:   node.ID,
                    Kind:     actionsToEdgeKind(stmt.Actions),
                    Effect:   effect,
                    Priority: priority,
                    Properties: map[string]any{
                        "actions":    stmt.Actions,
                        "via":        via,
                        "conditions": stmt.Conditions,
                    },
                })
            }
        }
    }
    return nil
}

// internal/graph/queries.go

// EffectiveAccess evaluates if principal can actually access resource
// considering both Allow and Deny edges
func EffectiveAccess(g *Graph, principalID, resourceID string) *AccessResult {
    // Get all edges from principal to resource (direct and via roles)
    paths := findAllPaths(g, principalID, resourceID, 5)
    
    result := &AccessResult{
        PrincipalID: principalID,
        ResourceID:  resourceID,
        Allowed:     false,
        DeniedBy:    nil,
        AllowedBy:   nil,
    }
    
    for _, path := range paths {
        // Check each edge in path for denies
        hasDeny := false
        hasAllow := false
        
        for _, edge := range path.Edges {
            if edge.Effect == EdgeEffectDeny {
                hasDeny = true
                result.DeniedBy = append(result.DeniedBy, edge)
            }
            if edge.Effect == EdgeEffectAllow {
                hasAllow = true
                result.AllowedBy = append(result.AllowedBy, edge)
            }
        }
        
        // Deny wins over Allow
        if hasAllow && !hasDeny {
            result.Allowed = true
        }
    }
    
    return result
}

// BlastRadius now respects Deny edges
func BlastRadius(g *Graph, principalID string, maxDepth int) *BlastRadiusResult {
    result := &BlastRadiusResult{PrincipalID: principalID}
    
    // ... BFS traversal ...
    
    for _, edge := range g.GetOutEdges(item.nodeID) {
        // Skip if this is a Deny edge - it blocks access, doesn't grant it
        if edge.Effect == EdgeEffectDeny {
            continue
        }
        
        // Check if there's a Deny edge that blocks this Allow
        if isDeniedByOtherEdge(g, item.nodeID, edge.Target) {
            continue
        }
        
        // ... rest of traversal ...
    }
    
    return result
}

func isDeniedByOtherEdge(g *Graph, source, target string) bool {
    for _, edge := range g.GetOutEdges(source) {
        if edge.Target == target && edge.Effect == EdgeEffectDeny {
            return true
        }
    }
    return false
}
```

---

## Cross-Account Role Assumption

Handle roles that can be assumed from other AWS accounts:

```go
// internal/graph/builder_aws.go

func (b *Builder) buildCrossAccountEdges(ctx context.Context) error {
    // Get all roles with their trust policies
    roles, _ := b.source.Query(ctx, `
        SELECT arn, account_id, assume_role_policy_document
        FROM aws_iam_roles
        WHERE assume_role_policy_document IS NOT NULL
    `)
    
    for _, role := range roles {
        roleARN := role["arn"].(string)
        roleAccount := role["account_id"].(string)
        trustPolicy := role["assume_role_policy_document"].(string)
        
        principals := extractTrustPrincipals(trustPolicy)
        
        for _, principalARN := range principals {
            // Determine if this is cross-account
            principalAccount := extractAccountFromARN(principalARN)
            isCrossAccount := principalAccount != "" && principalAccount != roleAccount
            
            // Handle account-level trust (arn:aws:iam::123456789012:root)
            if strings.HasSuffix(principalARN, ":root") {
                // Any principal in that account can assume this role
                b.graph.AddEdge(&Edge{
                    ID:     principalARN + "->assume->" + roleARN,
                    Source: principalARN,
                    Target: roleARN,
                    Kind:   EdgeKindCanAssume,
                    Effect: EdgeEffectAllow,
                    Properties: map[string]any{
                        "mechanism":      "trust_policy",
                        "cross_account":  isCrossAccount,
                        "source_account": principalAccount,
                        "target_account": roleAccount,
                        "trust_type":     "account_root",
                    },
                })
                
                // Also create edges from all users/roles in that account
                accountPrincipals := b.graph.GetNodesByAccount(principalAccount)
                for _, p := range accountPrincipals {
                    if p.Kind == NodeKindUser || p.Kind == NodeKindRole {
                        b.graph.AddEdge(&Edge{
                            ID:     p.ID + "->assume->" + roleARN,
                            Source: p.ID,
                            Target: roleARN,
                            Kind:   EdgeKindCanAssume,
                            Effect: EdgeEffectAllow,
                            Properties: map[string]any{
                                "mechanism":      "account_trust",
                                "cross_account":  isCrossAccount,
                                "via":            principalARN,
                            },
                        })
                    }
                }
            } else {
                // Specific principal trust
                b.graph.AddEdge(&Edge{
                    ID:     principalARN + "->assume->" + roleARN,
                    Source: principalARN,
                    Target: roleARN,
                    Kind:   EdgeKindCanAssume,
                    Effect: EdgeEffectAllow,
                    Properties: map[string]any{
                        "mechanism":      "trust_policy",
                        "cross_account":  isCrossAccount,
                        "source_account": principalAccount,
                        "target_account": roleAccount,
                    },
                })
            }
        }
    }
    
    return nil
}

func extractAccountFromARN(arn string) string {
    // arn:aws:iam::123456789012:user/alice -> 123456789012
    parts := strings.Split(arn, ":")
    if len(parts) >= 5 {
        return parts[4]
    }
    return ""
}

// Graph methods for cross-account queries
func (g *Graph) GetNodesByAccount(accountID string) []*Node {
    g.mu.RLock()
    defer g.mu.RUnlock()
    
    var nodes []*Node
    for _, node := range g.nodes {
        if node.Account == accountID {
            nodes = append(nodes, node)
        }
    }
    return nodes
}

func (g *Graph) GetCrossAccountEdges() []*Edge {
    g.mu.RLock()
    defer g.mu.RUnlock()
    
    var edges []*Edge
    for _, edgeList := range g.outEdges {
        for _, edge := range edgeList {
            if crossAccount, ok := edge.Properties["cross_account"].(bool); ok && crossAccount {
                edges = append(edges, edge)
            }
        }
    }
    return edges
}
```

### Cross-Account Blast Radius

```go
// BlastRadius now follows cross-account role assumptions
func BlastRadius(g *Graph, principalID string, maxDepth int) *BlastRadiusResult {
    result := &BlastRadiusResult{
        PrincipalID:      principalID,
        CrossAccountRisk: false,
    }
    
    visited := make(map[string]bool)
    accountsReached := make(map[string]bool)
    
    // Get starting account
    startNode, _ := g.GetNode(principalID)
    startAccount := ""
    if startNode != nil {
        startAccount = startNode.Account
    }
    
    // ... BFS traversal ...
    
    for _, edge := range g.GetOutEdges(item.nodeID) {
        // Track if we're crossing accounts
        if crossAccount, ok := edge.Properties["cross_account"].(bool); ok && crossAccount {
            targetAccount := edge.Properties["target_account"].(string)
            accountsReached[targetAccount] = true
            result.CrossAccountRisk = true
        }
        
        // ... continue traversal ...
    }
    
    result.AccountsReached = len(accountsReached)
    if startAccount != "" {
        delete(accountsReached, startAccount)
    }
    result.ForeignAccounts = maps.Keys(accountsReached)
    
    return result
}
```

### API Response with Cross-Account Info

```go
type BlastRadiusResult struct {
    PrincipalID      string           `json:"principal_id"`
    PrincipalName    string           `json:"principal_name"`
    ReachableNodes   []*ReachableNode `json:"reachable_nodes"`
    TotalCount       int              `json:"total_count"`
    
    // Cross-account analysis
    CrossAccountRisk bool     `json:"cross_account_risk"`
    AccountsReached  int      `json:"accounts_reached"`
    ForeignAccounts  []string `json:"foreign_accounts"`
    
    // Risk breakdown
    RiskSummary      RiskSummary `json:"risk_summary"`
}
```

---

## Updated Implementation Phases

### Phase 1: Foundation (1 week)
1. Create `internal/graph/arn.go` - full ARN parsing and wildcard matching
2. Create `internal/iampolicy/` with `liamg/iamgo` wrapper
3. Refactor `internal/attackpath/` -> `internal/graph/`
4. Basic node builder from asset tables

### Phase 2: Edges + Denies (1 week)  
1. Parse Allow AND Deny statements into edges
2. Edge effect and priority fields
3. Build edges from user/role attached policies
4. Build edges from inline policies

### Phase 3: Cross-Account + Trust (1 week)
1. Parse trust policies for role assumption
2. Handle account-root trust (`arn:aws:iam::*:root`)
3. Cross-account edge tracking
4. Service principal trust (EC2, Lambda, etc.)

### Phase 4: Queries + Webhook (1 week)
1. Blast radius with deny evaluation
2. Cross-account blast radius
3. Effective access query
4. Sync webhook for rebuild trigger
5. API endpoints
