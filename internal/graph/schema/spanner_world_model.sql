CREATE TABLE entities (
  entity_id STRING(2048) NOT NULL,
  kind STRING(128) NOT NULL,
  name STRING(MAX),
  tenant_id STRING(256),
  provider STRING(128),
  account STRING(256),
  region STRING(128),
  canonical_ref STRING(2048),
  properties_json JSON,
  tags_json JSON,
  findings_json JSON,
  risk STRING(32),
  observed_at TIMESTAMP NOT NULL,
  valid_from TIMESTAMP NOT NULL,
  valid_to TIMESTAMP,
  recorded_at TIMESTAMP NOT NULL,
  transaction_from TIMESTAMP NOT NULL,
  transaction_to TIMESTAMP,
  source_system STRING(128) NOT NULL,
  source_event_id STRING(2048) NOT NULL,
  confidence FLOAT64 NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  deleted_at TIMESTAMP,
  version INT64 NOT NULL,
  previous_properties_json JSON,
  property_history_json JSON
) PRIMARY KEY (entity_id);

CREATE TABLE entity_relationships (
  relationship_id STRING(2048) NOT NULL,
  source_entity_id STRING(2048) NOT NULL,
  target_entity_id STRING(2048) NOT NULL,
  relationship_kind STRING(128) NOT NULL,
  effect STRING(32),
  priority INT64 NOT NULL,
  properties_json JSON,
  observed_at TIMESTAMP NOT NULL,
  valid_from TIMESTAMP NOT NULL,
  valid_to TIMESTAMP,
  recorded_at TIMESTAMP NOT NULL,
  transaction_from TIMESTAMP NOT NULL,
  transaction_to TIMESTAMP,
  source_system STRING(128) NOT NULL,
  source_event_id STRING(2048) NOT NULL,
  confidence FLOAT64 NOT NULL,
  created_at TIMESTAMP NOT NULL,
  deleted_at TIMESTAMP,
  version INT64 NOT NULL
) PRIMARY KEY (relationship_id);

CREATE TABLE sources (
  source_id STRING(2048) NOT NULL,
  source_type STRING(128),
  canonical_name STRING(MAX),
  source_url STRING(MAX),
  trust_tier STRING(64),
  reliability_score FLOAT64,
  properties_json JSON,
  observed_at TIMESTAMP NOT NULL,
  valid_from TIMESTAMP NOT NULL,
  valid_to TIMESTAMP,
  recorded_at TIMESTAMP NOT NULL,
  transaction_from TIMESTAMP NOT NULL,
  transaction_to TIMESTAMP,
  source_system STRING(128) NOT NULL,
  source_event_id STRING(2048) NOT NULL,
  confidence FLOAT64 NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  deleted_at TIMESTAMP,
  version INT64 NOT NULL
) PRIMARY KEY (source_id);

CREATE TABLE evidence (
  evidence_id STRING(2048) NOT NULL,
  evidence_type STRING(128) NOT NULL,
  detail STRING(MAX),
  properties_json JSON,
  observed_at TIMESTAMP NOT NULL,
  valid_from TIMESTAMP NOT NULL,
  valid_to TIMESTAMP,
  recorded_at TIMESTAMP NOT NULL,
  transaction_from TIMESTAMP NOT NULL,
  transaction_to TIMESTAMP,
  source_system STRING(128) NOT NULL,
  source_event_id STRING(2048) NOT NULL,
  confidence FLOAT64 NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  deleted_at TIMESTAMP,
  version INT64 NOT NULL
) PRIMARY KEY (evidence_id);

CREATE TABLE evidence_targets (
  evidence_id STRING(2048) NOT NULL,
  edge_id STRING(2048) NOT NULL,
  target_entity_id STRING(2048) NOT NULL,
  observed_at TIMESTAMP NOT NULL,
  valid_from TIMESTAMP NOT NULL,
  valid_to TIMESTAMP,
  recorded_at TIMESTAMP NOT NULL,
  transaction_from TIMESTAMP NOT NULL,
  transaction_to TIMESTAMP,
  source_system STRING(128) NOT NULL,
  source_event_id STRING(2048) NOT NULL,
  confidence FLOAT64 NOT NULL,
  properties_json JSON
) PRIMARY KEY (evidence_id, edge_id),
  INTERLEAVE IN PARENT evidence ON DELETE CASCADE;

CREATE TABLE observations (
  observation_id STRING(2048) NOT NULL,
  observation_type STRING(128) NOT NULL,
  detail STRING(MAX),
  properties_json JSON,
  observed_at TIMESTAMP NOT NULL,
  valid_from TIMESTAMP NOT NULL,
  valid_to TIMESTAMP,
  recorded_at TIMESTAMP NOT NULL,
  transaction_from TIMESTAMP NOT NULL,
  transaction_to TIMESTAMP,
  source_system STRING(128) NOT NULL,
  source_event_id STRING(2048) NOT NULL,
  confidence FLOAT64 NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  deleted_at TIMESTAMP,
  version INT64 NOT NULL
) PRIMARY KEY (observation_id);

CREATE TABLE observation_targets (
  observation_id STRING(2048) NOT NULL,
  edge_id STRING(2048) NOT NULL,
  target_entity_id STRING(2048) NOT NULL,
  observed_at TIMESTAMP NOT NULL,
  valid_from TIMESTAMP NOT NULL,
  valid_to TIMESTAMP,
  recorded_at TIMESTAMP NOT NULL,
  transaction_from TIMESTAMP NOT NULL,
  transaction_to TIMESTAMP,
  source_system STRING(128) NOT NULL,
  source_event_id STRING(2048) NOT NULL,
  confidence FLOAT64 NOT NULL,
  properties_json JSON
) PRIMARY KEY (observation_id, edge_id),
  INTERLEAVE IN PARENT observations ON DELETE CASCADE;

CREATE TABLE claims (
  claim_id STRING(2048) NOT NULL,
  claim_type STRING(128),
  subject_id STRING(2048) NOT NULL,
  predicate STRING(256) NOT NULL,
  object_id STRING(2048),
  object_value STRING(MAX),
  status STRING(64) NOT NULL,
  summary STRING(MAX),
  metadata_json JSON,
  observed_at TIMESTAMP NOT NULL,
  valid_from TIMESTAMP NOT NULL,
  valid_to TIMESTAMP,
  recorded_at TIMESTAMP NOT NULL,
  transaction_from TIMESTAMP NOT NULL,
  transaction_to TIMESTAMP,
  source_system STRING(128) NOT NULL,
  source_event_id STRING(2048) NOT NULL,
  confidence FLOAT64 NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  deleted_at TIMESTAMP,
  version INT64 NOT NULL
) PRIMARY KEY (claim_id);

CREATE TABLE claim_subjects (
  claim_id STRING(2048) NOT NULL,
  subject_entity_id STRING(2048) NOT NULL
) PRIMARY KEY (claim_id, subject_entity_id),
  INTERLEAVE IN PARENT claims ON DELETE CASCADE;

CREATE TABLE claim_objects (
  claim_id STRING(2048) NOT NULL,
  object_entity_id STRING(2048) NOT NULL
) PRIMARY KEY (claim_id, object_entity_id),
  INTERLEAVE IN PARENT claims ON DELETE CASCADE;

CREATE TABLE claim_sources (
  claim_id STRING(2048) NOT NULL,
  edge_id STRING(2048) NOT NULL,
  source_id STRING(2048) NOT NULL,
  observed_at TIMESTAMP NOT NULL,
  valid_from TIMESTAMP NOT NULL,
  valid_to TIMESTAMP,
  recorded_at TIMESTAMP NOT NULL,
  transaction_from TIMESTAMP NOT NULL,
  transaction_to TIMESTAMP,
  source_system STRING(128) NOT NULL,
  source_event_id STRING(2048) NOT NULL,
  confidence FLOAT64 NOT NULL,
  properties_json JSON
) PRIMARY KEY (claim_id, edge_id),
  INTERLEAVE IN PARENT claims ON DELETE CASCADE;

CREATE TABLE claim_evidence (
  claim_id STRING(2048) NOT NULL,
  edge_id STRING(2048) NOT NULL,
  evidence_id STRING(2048) NOT NULL,
  observed_at TIMESTAMP NOT NULL,
  valid_from TIMESTAMP NOT NULL,
  valid_to TIMESTAMP,
  recorded_at TIMESTAMP NOT NULL,
  transaction_from TIMESTAMP NOT NULL,
  transaction_to TIMESTAMP,
  source_system STRING(128) NOT NULL,
  source_event_id STRING(2048) NOT NULL,
  confidence FLOAT64 NOT NULL,
  properties_json JSON
) PRIMARY KEY (claim_id, edge_id),
  INTERLEAVE IN PARENT claims ON DELETE CASCADE;

CREATE TABLE claim_relationships (
  claim_id STRING(2048) NOT NULL,
  edge_id STRING(2048) NOT NULL,
  related_claim_id STRING(2048) NOT NULL,
  relationship_kind STRING(128) NOT NULL,
  observed_at TIMESTAMP NOT NULL,
  valid_from TIMESTAMP NOT NULL,
  valid_to TIMESTAMP,
  recorded_at TIMESTAMP NOT NULL,
  transaction_from TIMESTAMP NOT NULL,
  transaction_to TIMESTAMP,
  source_system STRING(128) NOT NULL,
  source_event_id STRING(2048) NOT NULL,
  confidence FLOAT64 NOT NULL,
  properties_json JSON
) PRIMARY KEY (claim_id, edge_id),
  INTERLEAVE IN PARENT claims ON DELETE CASCADE;

CREATE INDEX entities_by_kind ON entities(kind);
CREATE INDEX entities_by_valid_from ON entities(valid_from);
CREATE INDEX entity_relationships_by_source ON entity_relationships(source_entity_id);
CREATE INDEX entity_relationships_by_target ON entity_relationships(target_entity_id);
CREATE INDEX claims_by_subject_predicate ON claims(subject_id, predicate);
CREATE INDEX claims_by_valid_from ON claims(valid_from);
CREATE INDEX evidence_targets_by_target ON evidence_targets(target_entity_id);
CREATE INDEX observation_targets_by_target ON observation_targets(target_entity_id);

CREATE OR REPLACE PROPERTY GRAPH cerebro_world_model
  NODE TABLES (
    entities
      KEY (entity_id)
      LABEL entity
      PROPERTIES ALL COLUMNS,
    sources
      KEY (source_id)
      LABEL source
      PROPERTIES ALL COLUMNS,
    evidence
      KEY (evidence_id)
      LABEL evidence
      PROPERTIES ALL COLUMNS,
    observations
      KEY (observation_id)
      LABEL observation
      PROPERTIES ALL COLUMNS,
    claims
      KEY (claim_id)
      LABEL claim
      PROPERTIES ALL COLUMNS
  )
  EDGE TABLES (
    entity_relationships
      KEY (relationship_id)
      SOURCE KEY (source_entity_id) REFERENCES entities (entity_id)
      DESTINATION KEY (target_entity_id) REFERENCES entities (entity_id)
      LABEL relationship
      PROPERTIES ALL COLUMNS,
    evidence_targets
      KEY (evidence_id, edge_id)
      SOURCE KEY (evidence_id) REFERENCES evidence (evidence_id)
      DESTINATION KEY (target_entity_id) REFERENCES entities (entity_id)
      LABEL targets
      PROPERTIES ALL COLUMNS,
    observation_targets
      KEY (observation_id, edge_id)
      SOURCE KEY (observation_id) REFERENCES observations (observation_id)
      DESTINATION KEY (target_entity_id) REFERENCES entities (entity_id)
      LABEL targets
      PROPERTIES ALL COLUMNS,
    claim_subjects
      KEY (claim_id, subject_entity_id)
      SOURCE KEY (claim_id) REFERENCES claims (claim_id)
      DESTINATION KEY (subject_entity_id) REFERENCES entities (entity_id)
      LABEL refers
      PROPERTIES ALL COLUMNS,
    claim_objects
      KEY (claim_id, object_entity_id)
      SOURCE KEY (claim_id) REFERENCES claims (claim_id)
      DESTINATION KEY (object_entity_id) REFERENCES entities (entity_id)
      LABEL refers
      PROPERTIES ALL COLUMNS,
    claim_sources
      KEY (claim_id, edge_id)
      SOURCE KEY (claim_id) REFERENCES claims (claim_id)
      DESTINATION KEY (source_id) REFERENCES sources (source_id)
      LABEL asserted_by
      PROPERTIES ALL COLUMNS,
    claim_evidence
      KEY (claim_id, edge_id)
      SOURCE KEY (claim_id) REFERENCES claims (claim_id)
      DESTINATION KEY (evidence_id) REFERENCES evidence (evidence_id)
      LABEL based_on
      PROPERTIES ALL COLUMNS,
    claim_relationships
      KEY (claim_id, edge_id)
      SOURCE KEY (claim_id) REFERENCES claims (claim_id)
      DESTINATION KEY (related_claim_id) REFERENCES claims (claim_id)
      LABEL claim_relationship
      PROPERTIES ALL COLUMNS
  );
