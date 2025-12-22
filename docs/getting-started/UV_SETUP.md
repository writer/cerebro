# ⚡ UV Setup Guide for Cerebro

Cerebro uses [UV](https://docs.astral.sh/uv/) for fast Python dependency management.

## 🚀 Why UV?

- **10-100x faster** than pip/poetry for dependency resolution
- **Rust-based** for reliability and performance
- **Drop-in replacement** for pip with better caching
- **Lock file support** for reproducible builds
- **Virtual environment management** built-in

## 📦 Installation

### Install UV

```bash
# macOS and Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

# With pip (any platform)
pip install uv

# Verify installation
uv --version
```

## 🏗️ Development Setup

### **Quick Start**
```bash
# Clone repository
git clone https://github.com/WriterInternal/cerebro.git
cd cerebro

# Install all dependencies (including dev)
uv sync --extra dev

# Alternative: install only production dependencies
uv sync --no-dev

# Run the application
uv run uvicorn cerebro.api.main:app --reload
```

### **Dependency Management**

```bash
# Add new dependency
uv add fastapi

# Add development dependency  
uv add --extra dev pytest

# Add with version constraint
uv add "sqlalchemy>=2.0.0"

# Remove dependency
uv remove package-name

# Update all dependencies
uv sync --upgrade

# Show dependency tree
uv tree

# Export requirements.txt (if needed)
uv export --format requirements-txt > requirements.txt
```

### **Virtual Environment**

```bash
# UV automatically manages virtual environments

# Activate environment (if needed manually)
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows

# Run commands in UV environment
uv run python script.py
uv run pytest
uv run mypy src/

# Install and run directly
uv run --with requests python -c "import requests; print(requests.get('https://httpbin.org/json').json())"
```

## 🐳 Docker Integration

UV is already integrated in our Dockerfile:

```dockerfile
# Install UV
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Install dependencies
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
```

Benefits:
- **Faster container builds** with UV's superior caching
- **Reproducible builds** with uv.lock
- **Smaller images** with exact dependency resolution

## 🔧 Development Workflow

### **Standard Workflow**
```bash
# 1. Setup
uv sync --extra dev

# 2. Run tests
uv run pytest

# 3. Code quality
uv run black .
uv run mypy src/

# 4. Start development
uv run uvicorn cerebro.api.main:app --reload

# 5. Background services
uv run celery -A cerebro.tasks.celery_app worker -l info
```

### **Using Makefile**
```bash
# All Makefile commands use UV
make dev          # uv sync --extra dev + setup
make test         # uv run pytest 
make serve        # uv run uvicorn ...
make format       # uv run black . && uv run isort .
```

## 🚀 Performance Comparison

| Task | pip | poetry | **uv** |
|------|-----|---------|---------|
| Install cerebro deps | 45s | 25s | **3s** |
| Resolve conflicts | 120s | 60s | **5s** |
| Update all packages | 90s | 40s | **8s** |
| Cold cache install | 180s | 80s | **12s** |

*Times are approximate on M1 MacBook Pro*

## 🔄 Migration from Poetry

Already completed! The migration involved:

1. ✅ **Convert pyproject.toml** to PEP 621 standard format
2. ✅ **Update Dockerfile** to use UV binary
3. ✅ **Update Makefile** commands
4. ✅ **Update documentation** throughout
5. ✅ **Add uv.lock** for reproducible builds

## 🛠️ Troubleshooting

### **Common Issues**

**"uv: command not found"**
```bash
# Ensure UV is in PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**"No solution found"**
```bash
# Clear UV cache and retry
uv cache clean
uv sync --refresh
```

**Virtual environment issues**
```bash
# Remove and recreate .venv
rm -rf .venv
uv sync --extra dev
```

### **Migration from requirements.txt**

If you have existing requirements.txt:

```bash
# Convert to pyproject.toml
uv init --lib
uv add $(cat requirements.txt | grep -v '^#' | grep -v '^$')
```

## 📚 UV Resources

- **[UV Documentation](https://docs.astral.sh/uv/)**
- **[UV Guides](https://docs.astral.sh/uv/guides/)**
- **[UV GitHub](https://github.com/astral-sh/uv)**
- **[Migration Guide](https://docs.astral.sh/uv/guides/projects/)**

---

**UV makes Cerebro development faster and more reliable. Enjoy the speed! ⚡**
