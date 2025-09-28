-- Initialize PostgreSQL database for Cerebro
-- This script runs automatically in Docker

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS btree_gin;

-- Grant permissions to cerebro user
GRANT ALL PRIVILEGES ON DATABASE cerebro TO cerebro;

-- Create additional schemas if needed
-- CREATE SCHEMA IF NOT EXISTS audit;
-- CREATE SCHEMA IF NOT EXISTS reporting;

-- Set up basic configuration
ALTER DATABASE cerebro SET timezone TO 'UTC';
