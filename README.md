# 🛡️ Security Advisor

An **MCP (Model Context Protocol) server** that orchestrates comprehensive security scans — SAST, SCA, and IaC — across any project and produces a unified **SARIF 2.1.0** report consumable by GitHub Advanced Security, VS Code, and other industry-standard tooling.

---

## Overview

Security Advisor exposes four MCP tools that an AI assistant (e.g., Claude, Gemini) can invoke to analyse a codebase:

| Tool | Description |
|---|---|
| `security_sast_skill` | Static Application Security Testing via **Semgrep** |
| `security_sca_skill` | Software Composition Analysis via **Trivy** (dependency vulnerabilities) |
| `security_iac_scan_skill` | Infrastructure-as-Code misconfiguration scan via **Trivy** (Terraform, K8s, Docker) |
| `security_advisor_skill` | **Master skill** — runs all three scans in parallel and exports a unified SARIF report |

### How It Works

```
AI Assistant
    │
    └─► security_advisor_skill(project_path)
             │
             ├─► security_sast_skill      →  Semgrep JSON
             ├─► security_sca_skill       →  Trivy vuln JSON
             └─► security_iac_scan_skill  →  Trivy config JSON
                          │
                          ▼
                  build_sarif_report()      ← pkg/sarif_report.py
                          │
                          ▼
          <project_path>/Security-Advisor-Report.sarif
```

---

## Prerequisites

Ensure the following are installed and available on your `PATH` before running Security Advisor.

### System Tools

| Tool | Version | Install |
|---|---|---|
| **Python** | ≥ 3.14 | [python.org](https://www.python.org/downloads/) |
| **uv** | latest | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| **Semgrep** | latest | `pip install semgrep` or `brew install semgrep` |
| **Trivy** | latest | `brew install trivy` or see [trivy.dev](https://trivy.dev/latest/getting-started/installation/) |

### Verify Prerequisites

```bash
python3 --version   # Should be 3.14+
uv --version
semgrep --version
trivy --version
```

---

## Project Structure

```
security-advisor/
├── main.py               # MCP server entry point — exposes all scan tools
├── pkg/
│   ├── __init__.py
│   └── sarif_report.py   # SARIF 2.1.0 builder (parses Semgrep + Trivy JSON)
├── pyproject.toml        # Project metadata and dependencies
├── uv.lock               # Locked dependency manifest
├── .python-version       # Pinned Python version (3.14)
└── README.md
```

---

## Installation

### 1. Clone the repository

```bash
git clone <repository-url>
cd security-advisor
```

### 2. Create and activate a virtual environment with `uv`

```bash
uv venv
source .venv/bin/activate   # macOS / Linux
# .venv\Scripts\activate    # Windows
```

### 3. Install dependencies

```bash
uv pip install -e .
```

This installs:
- [`fastmcp`](https://github.com/jlowin/fastmcp) ≥ 3.2.4 — high-level MCP server framework
- [`mcp`](https://github.com/modelcontextprotocol/python-sdk) ≥ 1.27.1 — Model Context Protocol Python SDK

---

## Development

### Running the MCP Server Locally

```bash
uv run main.py
```

Or via the standard Python entrypoint:

```bash
python main.py
```

The server starts and listens for MCP tool calls over **stdio** (default FastMCP transport).

### Running with `fastmcp` dev mode

```bash
fastmcp dev main.py
```

This launches an interactive MCP inspector at `http://localhost:6274` so you can test tools manually.

---

## MCP Client Configuration

To connect Security Advisor to an AI assistant, add it to your MCP client config.

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "security-advisor": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/security-advisor",
        "run",
        "main.py"
      ]
    }
  }
}
```

### Gemini / Antigravity (`.gemini/settings.json`)

```json
{
  "mcpServers": {
    "security-advisor": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/security-advisor",
        "run",
        "main.py"
      ]
    }
  }
}
```

> **Tip:** Replace `/absolute/path/to/security-advisor` with the actual path on your machine.

---

## Usage

### Via an AI Assistant

Once the MCP server is connected, instruct your assistant:

```
Run a full security analysis on /path/to/my-project
```

The assistant will invoke `security_advisor_skill`, which:
1. Runs Semgrep SAST, Trivy SCA, and Trivy IaC scans **in parallel**
2. Aggregates all findings into a SARIF 2.1.0 document
3. Writes the report to `<project_path>/Security-Advisor-Report.sarif`
4. Returns a human-readable summary

### Individual Tools

You can also invoke individual scan tools:

```
Run a SAST scan on /path/to/my-project
Run an SCA scan on /path/to/my-project
Run an IaC scan on /path/to/my-project
```

---

## SARIF Report

The exported **`Security-Advisor-Report.sarif`** is a valid [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) document containing three `runs`:

| Run | Tool | Findings |
|---|---|---|
| `runs[0]` | Semgrep | SAST code-level issues |
| `runs[1]` | Trivy | SCA dependency vulnerabilities |
| `runs[2]` | Trivy | IaC misconfigurations |

### Severity Mapping

| Tool Severity | SARIF Level |
|---|---|
| `CRITICAL`, `HIGH` | `error` |
| `MEDIUM` | `warning` |
| `LOW`, `INFO` | `note` |

### Viewing the Report

- **GitHub**: Upload to [Code Scanning](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github) via `gh` CLI or Actions
- **VS Code**: Install the [SARIF Viewer extension](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)
- **Any SARIF-compatible tool**: The file adheres to the official OASIS schema

```bash
# Upload to GitHub Code Scanning
gh api \
  --method POST \
  /repos/{owner}/{repo}/code-scanning/sarifs \
  --field commit_sha=$(git rev-parse HEAD) \
  --field ref=$(git symbolic-ref HEAD) \
  --field sarif=@Security-Advisor-Report.sarif
```

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `fastmcp` | ≥ 3.2.4 | MCP server framework |
| `mcp` | ≥ 1.27.1 | Model Context Protocol Python SDK |

External CLI tools (not Python packages):

| Tool | Purpose |
|---|---|
| `semgrep` | SAST scanning |
| `trivy` | SCA + IaC scanning |

---

## Contributing

1. Fork the repository and create a feature branch
2. Make your changes and ensure the server starts cleanly (`uv run main.py`)
3. Test manually using `fastmcp dev main.py`
4. Open a pull request with a clear description of the changes

---

## License

This project is licensed under the **MIT License**.
