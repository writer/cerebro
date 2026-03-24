CREATE TABLE graph_nodes (
  node_id STRING(2048) NOT NULL,
  kind STRING(128) NOT NULL,
  name STRING(MAX),
  tenant_id STRING(256),
  provider STRING(128),
  account STRING(256),
  region STRING(128),
  properties_json STRING(MAX),
  tags_json STRING(MAX),
  risk STRING(32),
  findings_json STRING(MAX),
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  deleted_at TIMESTAMP,
  version INT64 NOT NULL,
  previous_properties_json STRING(MAX),
  property_history_json STRING(MAX)
) PRIMARY KEY (node_id);

CREATE TABLE graph_edges (
  edge_id STRING(2048) NOT NULL,
  source_node_id STRING(2048) NOT NULL,
  target_node_id STRING(2048) NOT NULL,
  kind STRING(128) NOT NULL,
  effect STRING(32),
  priority INT64 NOT NULL,
  properties_json STRING(MAX),
  risk STRING(32),
  created_at TIMESTAMP NOT NULL,
  deleted_at TIMESTAMP,
  version INT64 NOT NULL
) PRIMARY KEY (edge_id);

CREATE INDEX graph_nodes_by_kind ON graph_nodes(kind);
CREATE INDEX graph_edges_by_source ON graph_edges(source_node_id);
CREATE INDEX graph_edges_by_target ON graph_edges(target_node_id);

CREATE OR REPLACE PROPERTY GRAPH cerebro_graph_store
  NODE TABLES (
    graph_nodes
      KEY (node_id)
      LABEL graph_node
      PROPERTIES ALL COLUMNS
  )
  EDGE TABLES (
    graph_edges
      KEY (edge_id)
      SOURCE KEY (source_node_id) REFERENCES graph_nodes (node_id)
      DESTINATION KEY (target_node_id) REFERENCES graph_nodes (node_id)
      LABEL graph_edge
      PROPERTIES ALL COLUMNS
  );
