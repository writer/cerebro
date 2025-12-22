## Deep Dives (research notes)

These documents are intentionally detailed “excessive research” notes meant to preserve:

- architectural understanding of Cerebro’s subsystems
- operational gotchas and failure modes
- Snowflake/warehouse design decisions + citations
- concrete code pointers (file paths, key functions/classes)

They are written as living internal notes (not polished public docs). When updating:

1. Prefer adding a dated section (e.g. `## 2025-12-15 Updates`) rather than rewriting history.
2. Link to code by file path (and function/class name) so the reader can jump quickly.
3. Cite external references in a `Sources` section.

### Index

- **Cerebro system architecture**: `2025-12-cerebro-system-architecture.md`
- **Snowflake warehouse deep dive**: `2025-12-snowflake-warehouse-deep-dive.md`
- **Query engine deep dive**: `2025-12-query-engine-deep-dive.md`
- **Agents + tool execution deep dive**: `2025-12-agents-and-tools-deep-dive.md`
