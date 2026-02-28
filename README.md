🛡️ CodeSentinel

**AI-Powered Code Review Agent for CI/CD Pipelines**

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4-412991?style=for-the-badge&logo=openai&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![GitHub](https://img.shields.io/badge/GitHub-Webhook-181717?style=for-the-badge&logo=github&logoColor=white)

---

## 🧠 Overview

CodeSentinel is an **AI-powered code review agent** that analyzes Python code for quality issues, security vulnerabilities, and improvement opportunities. It uses **LLM-powered analysis** with **AST parsing** to provide structured, actionable review feedback.

Designed for **CI/CD integration** — receives webhook events from GitHub, reviews pull request code changes, and posts structured review comments automatically.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                   GitHub Webhook                     │
│              (Push / Pull Request Events)            │
└──────────────────────┬──────────────────────────────┘
                       │
              ┌────────▼─────────┐
              │  FastAPI Server   │
              │  /api/v1/review   │
              └────────┬─────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
┌──────────────┐ ┌───────────┐ ┌──────────────┐
│ Code Parser  │ │ LLM       │ │  Security    │
│ (AST-based)  │ │ Reviewer  │ │  Scanner     │
│              │ │           │ │              │
│ • Complexity │ │ • Quality │ │ • Injection  │
│ • Structure  │ │ • Style   │ │ • Hardcoded  │
│ • Functions  │ │ • Bugs    │ │   secrets    │
│ • Imports    │ │ • Suggest  │ │ • Eval/exec  │
└──────┬───────┘ └─────┬─────┘ └──────┬───────┘
       │               │              │
       └───────────────┼──────────────┘
                       │
              ┌────────▼─────────┐
              │ Report Generator │
              │ (Markdown/JSON)  │
              └──────────────────┘
```

---

## ✨ Features

- **AST-Based Analysis** — Parse Python code structure, detect complexity, identify patterns
- **LLM-Powered Review** — GPT-4 generates nuanced code quality feedback
- **Security Scanning** — Detect hardcoded secrets, eval/exec usage, SQL injection patterns
- **Structured Output** — Pydantic-validated review reports with severity levels
- **GitHub Webhook** — Receive PR events and auto-review code changes
- **Multiple Output Formats** — Markdown reports, JSON API responses
- **Configurable Rules** — Enable/disable specific review categories
- **Docker Ready** — Container deployment for CI/CD integration

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- OpenAI API key

### 1. Clone & Install
```bash
git clone https://github.com/yoshimitsu117/codesentinel.git
cd codesentinel
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure
```bash
cp .env.example .env
# Add your OpenAI API key
```

### 3. Run
```bash
uvicorn app.main:app --reload --port 8002
```

### 4. Review Code
```bash
curl -X POST http://localhost:8002/api/v1/review \
  -H "Content-Type: application/json" \
  -d '{
    "code": "def foo(x):\n  return eval(x)",
    "filename": "example.py",
    "language": "python"
  }'
```

---

## 🐳 Docker
```bash
docker-compose up --build
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/review` | Review a code snippet |
| `POST` | `/api/v1/review/file` | Upload and review a file |
| `POST` | `/api/v1/webhook/github` | GitHub webhook handler |
| `GET`  | `/api/v1/reports/{id}` | Get a review report |
| `GET`  | `/health` | Health check |

---

## 📋 Review Categories

| Category | Description | Severity |
|----------|-------------|----------|
| 🐛 **Bug Risk** | Potential bugs and logic errors | High |
| 🔒 **Security** | Vulnerabilities and unsafe patterns | Critical |
| 📐 **Complexity** | Cyclomatic complexity, deep nesting | Medium |
| 📝 **Style** | PEP 8, naming conventions, docstrings | Low |
| ⚡ **Performance** | Inefficient patterns, optimization tips | Medium |
| 🏗️ **Architecture** | Design patterns, SOLID principles | Medium |

---

## 📁 Project Structure

```
codesentinel/
├── app/
│   ├── main.py              # FastAPI server
│   ├── config.py             # Configuration
│   ├── analyzer/
│   │   ├── code_parser.py   # AST-based code parsing
│   │   ├── reviewer.py      # LLM-powered code review
│   │   └── security.py      # Security vulnerability scanner
│   ├── models/
│   │   ├── schemas.py       # Pydantic review schemas
│   │   └── prompts.py       # Structured review prompts
│   ├── integrations/
│   │   ├── github_webhook.py # GitHub webhook handler
│   │   └── formatter.py     # Output formatting
│   └── reports/
│       └── generator.py     # Report generation
├── tests/
│   └── test_analyzer.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Siddharth** — AI Engineer  
Building production-grade AI systems, not just demos.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=flat&logo=linkedin)](https://linkedin.com/in/siddharth-majhi)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat&logo=github)](https://github.com/yoshimitsu117)

