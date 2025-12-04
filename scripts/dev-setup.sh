#!/bin/bash
set -e

echo "🚀 Cerebro Development Setup"
echo "================================"

# Check prerequisites
echo "Checking prerequisites..."
command -v python3 >/dev/null 2>&1 || { echo "❌ Python 3.11+ required"; exit 1; }
command -v psql >/dev/null 2>&1 || { echo "❌ PostgreSQL required"; exit 1; }
command -v redis-cli >/dev/null 2>&1 || { echo "❌ Redis required"; exit 1; }

echo "✅ Prerequisites met"

# Install UV if not present
if ! command -v uv &> /dev/null; then
    echo "Installing UV package manager..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    source $HOME/.cargo/env
fi

# Setup Python environment
echo "Setting up Python environment..."
uv sync

# Create development database
echo "Setting up database..."
createdb cerebro_dev 2>/dev/null || echo "Database already exists"

# Setup environment
if [ ! -f .env ]; then
    echo "Creating development .env file..."
    cat > .env << EOF
# Database
DATABASE_URL=postgresql://localhost/cerebro_dev

# Security
SECRET_KEY=dev-secret-key-$(openssl rand -hex 32)
KMS_PROVIDER=local

# Redis
REDIS_URL=redis://localhost:6379/0

# Logging
LOG_LEVEL=INFO

# Development
DEV_MODE=true
EOF
    echo "✅ Created .env file"
else
    echo "✅ .env file already exists"
fi

# Run migrations
echo "Running database migrations..."
uv run alembic upgrade head

# Create default user
echo "Creating development user..."
uv run python -c "
from cerebro.core.database import async_session_factory
from cerebro.core.user_service import UserService
import asyncio

async def create_dev_user():
    async with async_session_factory() as db:
        user_service = UserService(db)
        try:
            await user_service.create_user(
                username='admin@cerebro.dev',
                email='admin@cerebro.dev', 
                password='cerebro123',
                is_admin=True
            )
            print('✅ Created admin@cerebro.dev (password: cerebro123)')
        except Exception as e:
            print(f'User may already exist: {e}')

asyncio.run(create_dev_user())
"

# Test API
echo "Testing API..."
uv run python -c "
import asyncio
from cerebro.api.main import app
print('✅ API imports successfully')
"

echo ""
echo "🎉 Setup Complete!"
echo "================================"
echo "Next steps:"
echo "1. Start API: make serve"
echo "2. Explore API docs: http://localhost:8000/docs"
echo ""
echo "Default login: admin@cerebro.dev / cerebro123"
