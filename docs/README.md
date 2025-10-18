# Cerebro Documentation

**Welcome to Cerebro** – Security System of Record with intelligent agents and enterprise compliance support.

---

## 📚 Documentation Index

### 🚀 Getting Started

New to Cerebro? Start here:

- **[Quick Start Guide](getting-started/QUICKSTART.md)** - Get up and running quickly
- **[Installation](../README.md#installation)** - Backend + frontend installation steps
- **[First Tasks](getting-started/QUICKSTART.md#first-collection)** - Your first security collection

### 📖 User Guide

Learn how to use Cerebro:

- **[API Reference](user-guide/API.md)** - REST + SSE endpoints
- **[Query Engine](user-guide/QUERY_ENGINE.md)** - SQL and natural language queries
- **[CEL Rules](user-guide/CEL_RULES.md)** - Common Expression Language rule engine
- **[Compliance Features](user-guide/COMPLIANCE_FEATURES.md)** - SOC 2, CIS, NIST CSF 2.0
- **[Troubleshooting](user-guide/TROUBLESHOOTING.md)** - Common issues and resolutions

### 🔌 Integrations

Connect Cerebro with your tools:

- **[Slack](integrations/slack/SETUP.md)** - Real-time security notifications
- **[Email](integrations/email/SETUP.md)** - SMTP email notifications with HTML templates
- **[Webhooks](integrations/webhooks/SETUP.md)** - Generic HTTP webhooks with custom payloads
- **[OCSF](integrations/ocsf/OCSF_INTEGRATION.md)** - Open Cybersecurity Schema Framework
- **[NIST CSF 2.0](integrations/nist-csf/)** - Framework implementation
- **[Cloud Providers](integrations/providers/README.md)** - AWS, GCP, Azure, Okta, GitHub

### 👨‍💻 Developer Guide

Build on Cerebro:

- **[Development Setup](developer-guide/DEVELOPMENT.md)** - Local development environment
- **[Database Schema](developer-guide/DATABASE_SCHEMA.md)** - PostgreSQL schema reference
- **[Deployment](developer-guide/DEPLOYMENT.md)** - Production deployment guide
- **[Contributing](developer-guide/DEVELOPMENT.md#contributing)** - How to contribute

### 🤖 AI Agents

Intelligent security automation:

- **[Agent Overview](agents/README.md)** - Introduction to Cerebro agents
- **[Claude Integration](agents/claude-integration.md)** - Claude AI integration
- **[Knowledge Base](agents/KNOWLEDGE_BASE_SYSTEM.md)** - Context and memory system
- **[Tool Development](agents/tool-development.md)** - Building custom agent tools
- **[API Reference](agents/API_INTEGRATION.md)** - Agent API endpoints

### 🏗️ Architecture

System design and internals:

- **[Architecture Overview](architecture/claude-sdk-integration.md)** - High-level system design
- **[Notification System](SLACK_INTEGRATION_IMPLEMENTATION.md)** - Multi-channel notifications
- **[Agent System](agents/claude-integration.md)** - Intelligent agent architecture
- **[Security](developer-guide/DEVELOPMENT.md#security)** - Security considerations

### 📦 Additional Resources

- **[Examples](../examples/README.md)** - Sample code and scenarios
- **[Tests](../tests/README.md)** - Testing guide
- **[Archive](archive/)** - Historical documents and session notes

---

## 🔗 Quick Links

| Resource | Description |
|----------|-------------|
| [GitHub Repository](https://github.com/WriterInternal/cerebro) | Source code and issues |
| [API Documentation](http://localhost:8000/docs) | Interactive API docs (when running) |
| [Quick Start](getting-started/QUICKSTART.md) | Get started in 10 minutes |
| [Slack Integration](integrations/slack/SETUP.md) | Set up Slack notifications |
| [Troubleshooting](user-guide/TROUBLESHOOTING.md) | Common issues |

---

## 📋 Feature Highlights

### ✅ Security Features

- **Multi-Cloud Support** - AWS, GCP, Azure, Okta, GitHub
- **Real-Time Monitoring** - Proactive security surveillance
- **Compliance Automation** - SOC 2, CIS, NIST CSF 2.0
- **Attack Path Analysis** - Lateral movement detection
- **Identity Governance** - Advanced IAM analysis

### 🤖 AI-Powered

- **Shared Toolchain** - Agents, CLI, and API call the same audited tools
- **Natural Language Queries** - Ask questions in plain English
- **Context-Aware** - Learns your environment automatically
- **Multi-Step Planning** - Complex workflows automated with approval gates

### 🔔 Integrations

- **Slack Notifications** ✅ - Real-time alerts
- **Email Notifications** ✅ - SMTP with HTML templates
- **Generic Webhooks** ✅ - Custom HTTP endpoints with Jinja2 templates
- **OCSF Export** ✅ - Standards-based event format
- **PagerDuty** (roadmap)

---

## 🆘 Getting Help

**Found a bug?** [Open an issue](https://github.com/WriterInternal/cerebro/issues)

**Need help?** Check the [Troubleshooting Guide](user-guide/TROUBLESHOOTING.md)

**Want to contribute?** See [Development Guide](developer-guide/DEVELOPMENT.md)

---

## 📄 License

MIT License - See [LICENSE](../LICENSE) for details

---

**Last Updated:** 2025-10-18
**Version:** 0.1.0
**Status:** ✅ Production Ready