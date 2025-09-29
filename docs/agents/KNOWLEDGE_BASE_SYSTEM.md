# Agent Knowledge Base System

**Status:** Design → Implementation
**Priority:** HIGH - Enables context-aware agent operations

---

## 🎯 Problem Statement

Current agent system limitations:
- **No Repository Context** - Agents don't know what repos exist or their purpose
- **No Historical Memory** - Each session starts from scratch
- **No Learning** - Agents can't build up understanding over time
- **Manual Context** - Users must explain everything in each conversation

**Example Pain Points:**
```
User: "Check the auth implementation"
Agent: "Which repository? Which auth system? GitHub? Okta? AWS IAM?"

User: "We talked about this yesterday"
Agent: "I have no memory of previous sessions"

User: "What providers do we support?"
Agent: "I don't have access to that information"
```

---

## 🏗️ Architecture Design

### Three-Layer Knowledge System

```
┌─────────────────────────────────────────────────────────────┐
│                    QUERY LAYER                               │
│  Agent asks: "What repos exist?" "What's our auth stack?"   │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│                  KNOWLEDGE BASE TOOLS                        │
│  • get_repository_context (metadata, tech stack, purpose)   │
│  • query_knowledge_base (semantic search over docs/code)    │
│  • remember_context (persist learnings across sessions)     │
│  • get_session_history (retrieve past conversations)        │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│                   STORAGE LAYER                              │
│  • PostgreSQL (structured metadata, session history)        │
│  • pgvector (semantic embeddings for RAG)                   │
│  • File System (repos, docs, code)                          │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 Storage Schema

### 1. Repository Metadata Table

```sql
CREATE TABLE repository_metadata (
    repo_id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(org_id),

    -- Basic Info
    repo_name VARCHAR(255) NOT NULL,
    repo_url TEXT,
    repo_type VARCHAR(50), -- 'backend', 'frontend', 'infra', 'docs'
    primary_language VARCHAR(50),

    -- Tech Stack
    frameworks JSONB, -- ['FastAPI', 'React', 'PostgreSQL']
    dependencies JSONB, -- package.json, requirements.txt parsed
    providers JSONB, -- ['aws', 'github', 'okta']

    -- Purpose & Context
    purpose TEXT,
    description TEXT,
    key_modules JSONB, -- {'auth': 'JWT-based', 'agents': 'Claude SDK'}

    -- Statistics
    total_files INTEGER,
    total_lines INTEGER,
    last_analyzed_at TIMESTAMP,

    -- Vector Embeddings for RAG
    description_embedding vector(1536), -- OpenAI ada-002

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_repo_embedding ON repository_metadata
    USING ivfflat (description_embedding vector_cosine_ops);
```

### 2. Agent Session Context Table

```sql
CREATE TABLE agent_session_context (
    context_id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES agent_sessions(session_id),

    -- Context Type
    context_type VARCHAR(50), -- 'repository', 'finding', 'insight', 'decision'

    -- Content
    context_key VARCHAR(255), -- 'auth_implementation', 'aws_config'
    context_value JSONB,
    confidence_score FLOAT, -- 0.0-1.0

    -- Metadata
    learned_from TEXT, -- 'user_conversation', 'code_analysis', 'tool_execution'
    verified BOOLEAN DEFAULT FALSE,

    -- Embeddings
    content_embedding vector(1536),

    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP -- Optional TTL for temporary context
);

CREATE INDEX idx_session_context ON agent_session_context(session_id, context_type);
CREATE INDEX idx_context_embedding ON agent_session_context
    USING ivfflat (content_embedding vector_cosine_ops);
```

### 3. Knowledge Base Entries Table

```sql
CREATE TABLE knowledge_base_entries (
    entry_id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(org_id),

    -- Entry Type
    entry_type VARCHAR(50), -- 'concept', 'procedure', 'architecture', 'decision'
    title VARCHAR(255),
    content TEXT,

    -- Relationships
    related_repos JSONB, -- [repo_id, repo_id]
    related_tags JSONB, -- ['authentication', 'aws', 'security']

    -- Provenance
    source VARCHAR(100), -- 'code_analysis', 'documentation', 'user_input'
    created_by VARCHAR(255), -- user_id or 'agent'

    -- Embeddings for RAG
    content_embedding vector(1536),

    -- Metadata
    access_count INTEGER DEFAULT 0,
    last_accessed_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_kb_org ON knowledge_base_entries(org_id, entry_type);
CREATE INDEX idx_kb_embedding ON knowledge_base_entries
    USING ivfflat (content_embedding vector_cosine_ops);
```

---

## 🔧 Tool Implementations

### Tool 1: `get_repository_context`

**Purpose:** Give agents understanding of repository structure, tech stack, and purpose

**Input:**
```python
class RepositoryContextInput(BaseModel):
    repo_path: Optional[str] = None  # Analyze specific repo
    include_tech_stack: bool = True
    include_file_structure: bool = True
    include_dependencies: bool = True
```

**Output:**
```python
class RepositoryContextOutput(BaseModel):
    repo_name: str
    repo_type: str  # backend/frontend/infra
    purpose: str
    tech_stack: Dict[str, List[str]]  # {languages, frameworks, tools}
    key_modules: Dict[str, str]  # {module_name: description}
    file_structure: Dict[str, Any]  # Directory tree
    dependencies: Dict[str, List[str]]  # {pip, npm, go.mod}
    providers_integrated: List[str]  # [aws, github, okta]
    entry_points: List[str]  # [main.py, app.py, index.tsx]
```

**Implementation:**
```python
async def execute(self, context, repo_path=None):
    # 1. Auto-detect repo if not provided
    if not repo_path:
        repo_path = await self._detect_current_repo(context)

    # 2. Check cache
    cached = await self._get_cached_context(repo_path)
    if cached and not self._is_stale(cached):
        return cached

    # 3. Analyze repository
    analysis = await self._analyze_repository(repo_path)

    # 4. Store in knowledge base
    await self._store_context(context.org_id, analysis)

    return analysis

async def _analyze_repository(self, repo_path):
    return {
        "tech_stack": await self._detect_tech_stack(repo_path),
        "dependencies": await self._parse_dependencies(repo_path),
        "file_structure": await self._build_file_tree(repo_path),
        "key_modules": await self._identify_modules(repo_path),
        "providers": await self._detect_providers(repo_path),
    }
```

**Example Usage:**
```
Agent: "Let me understand the repository first"
> Uses get_repository_context()
Agent: "I see this is a FastAPI backend with Claude Agent SDK integration,
       supporting AWS, GitHub, Okta, and Google Workspace providers.
       Key modules: agents/ (AI tools), api/ (REST endpoints),
       collectors/ (data ingestion)."
```

---

### Tool 2: `query_knowledge_base`

**Purpose:** Semantic search over organizational knowledge using RAG

**Input:**
```python
class KnowledgeQueryInput(BaseModel):
    query: str  # Natural language query
    entry_types: Optional[List[str]] = None  # Filter by type
    related_repos: Optional[List[str]] = None
    top_k: int = 5  # Number of results
```

**Output:**
```python
class KnowledgeQueryOutput(BaseModel):
    results: List[KnowledgeEntry]
    total_found: int

class KnowledgeEntry(BaseModel):
    entry_id: str
    title: str
    content: str
    relevance_score: float  # 0.0-1.0
    source: str
    related_repos: List[str]
    tags: List[str]
```

**Implementation:**
```python
async def execute(self, context, query, entry_types=None, top_k=5):
    # 1. Generate query embedding
    query_embedding = await self._embed_text(query)

    # 2. Vector similarity search
    results = await db.execute(f"""
        SELECT
            entry_id,
            title,
            content,
            1 - (content_embedding <=> $1) as similarity,
            related_repos,
            related_tags
        FROM knowledge_base_entries
        WHERE org_id = $2
        {f"AND entry_type = ANY($3)" if entry_types else ""}
        ORDER BY content_embedding <=> $1
        LIMIT $4
    """, query_embedding, context.org_id, entry_types, top_k)

    # 3. Update access stats
    await self._update_access_stats(results)

    return results
```

**Example Usage:**
```
User: "How does our authentication work?"
Agent: "Let me check the knowledge base"
> Uses query_knowledge_base(query="authentication implementation")
Agent: "Based on organizational knowledge: We use JWT-based authentication
       with OAuth2 flows. The auth module in cerebro/api/auth.py handles
       token generation and validation. We support dev mode for local
       development and production mode with refresh tokens."
```

---

### Tool 3: `remember_context`

**Purpose:** Allow agents to persist learnings across sessions

**Input:**
```python
class RememberContextInput(BaseModel):
    context_key: str  # 'aws_account_structure', 'auth_flow'
    context_value: Dict[str, Any]
    context_type: str  # 'repository', 'insight', 'decision'
    confidence: float = 0.8
    ttl_hours: Optional[int] = None  # Expire after N hours
```

**Implementation:**
```python
async def execute(self, context, context_key, context_value,
                 context_type, confidence=0.8, ttl_hours=None):
    # 1. Generate embedding
    embedding = await self._embed_context(context_key, context_value)

    # 2. Store in session context
    await db.execute("""
        INSERT INTO agent_session_context
        (session_id, context_key, context_value, context_type,
         confidence_score, content_embedding, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    """, context.session_id, context_key, context_value, context_type,
        confidence, embedding,
        datetime.now() + timedelta(hours=ttl_hours) if ttl_hours else None)

    return {"stored": True, "context_key": context_key}
```

**Example Usage:**
```
Agent: "I've analyzed the codebase structure"
> Uses remember_context(
    context_key="repo_structure",
    context_value={"backend": "cerebro/", "frontend": "cerebro-frontend/"},
    context_type="repository"
)
Agent: "I'll remember this for future questions"

[Later session]
User: "Where's the frontend code?"
Agent: [Retrieves context] "The frontend is in cerebro-frontend/ directory"
```

---

### Tool 4: `get_session_history`

**Purpose:** Retrieve context from past sessions for continuity

**Input:**
```python
class SessionHistoryInput(BaseModel):
    lookback_sessions: int = 5  # Last N sessions
    include_tools_used: bool = True
    topic_filter: Optional[str] = None  # "authentication", "aws"
```

**Output:**
```python
class SessionHistoryOutput(BaseModel):
    sessions: List[SessionSummary]

class SessionSummary(BaseModel):
    session_id: str
    created_at: str
    message_count: int
    topics_discussed: List[str]
    tools_used: List[str]
    key_decisions: List[str]
    context_learned: Dict[str, Any]
```

**Example Usage:**
```
User: "Remember what we discussed about AWS setup?"
Agent: "Let me check previous sessions"
> Uses get_session_history(topic_filter="aws")
Agent: "Yes! In our session 3 days ago, we configured AWS collectors
       for accounts [prod, staging, dev]. You mentioned the prod account
       ID is 123456789012."
```

---

## 🚀 Implementation Plan

### Phase 1: Database Setup (2 hours)
1. Add pgvector extension
2. Create 3 new tables (repository_metadata, agent_session_context, knowledge_base_entries)
3. Add migration script

### Phase 2: Repository Analyzer (4 hours)
1. Implement `get_repository_context` tool
   - Tech stack detection (package.json, requirements.txt, go.mod)
   - File structure analysis
   - Dependency parsing
   - Provider detection (search for aws/github/okta imports)
2. Add caching layer (24hr TTL)
3. Register tool

### Phase 3: Knowledge Base RAG (6 hours)
1. Set up OpenAI embeddings (ada-002)
2. Implement `query_knowledge_base` tool with vector search
3. Add seed knowledge from documentation
4. Implement relevance scoring

### Phase 4: Session Memory (4 hours)
1. Implement `remember_context` tool
2. Implement `get_session_history` tool
3. Add automatic context learning from tool executions
4. Add context expiration/cleanup

### Phase 5: Integration (2 hours)
1. Update agent runtime to auto-load context on session start
2. Add knowledge base seeding job
3. Add UI for viewing agent memory/context

**Total Effort:** ~18 hours (2-3 days)

---

## 💡 Quick Win: Start Simple

**Phase 0: Minimal Viable Knowledge (2 hours)**

Skip RAG initially, implement basic metadata tool:

```python
class GetOrgContextTool(Tool):
    """Quick context about organization setup"""

    async def execute(self, context):
        return {
            "repositories": {
                "backend": {
                    "path": "/cerebro",
                    "type": "FastAPI backend",
                    "providers": ["aws", "github", "okta", "google_workspace"]
                },
                "frontend": {
                    "path": "/cerebro-frontend",
                    "type": "Next.js 15 frontend",
                    "features": ["agent chat", "findings", "compliance"]
                }
            },
            "agent_tools": 15,
            "providers_supported": ["AWS", "GitHub", "Okta", "Google Workspace", "GCP", "Azure"],
            "key_features": [
                "AI Security Agents with 15+ tools",
                "Forensic replay and time travel",
                "Compliance testing (SOC2, ISO27001, CIS, NIST)",
                "Attack path simulation",
                "Zero-ETL SQL query engine"
            ]
        }
```

This gives agents immediate context without complex RAG implementation.

---

## 🎯 Expected Impact

**Before:**
- Agents start each session blind
- Users repeat context constantly
- No learning or improvement over time
- Generic, non-specific responses

**After:**
- Agents understand repo structure automatically
- Context persists across sessions
- Agents build organizational knowledge
- Specific, contextual responses

**Example Improvement:**
```
Before:
User: "Fix the auth bug"
Agent: "Which authentication system? Can you provide more details?"

After:
User: "Fix the auth bug"
Agent: "I see we use JWT auth in cerebro/api/auth.py. Let me check
       recent auth-related findings... Found 2 open findings related
       to token expiration. Would you like me to investigate those?"
```

---

## 📝 Next Steps

1. Implement Phase 0 (Quick Win) first - 2 hours
2. Get feedback on utility
3. Implement full RAG system if valuable
4. Continuously seed knowledge base from code analysis

**Start with:** `get_repository_context` tool (most immediate value)