# 🛡️ Security Advisor

An **MCP (Model Context Protocol) server** that orchestrates comprehensive security scans — SAST, SCA, and IaC — across any project and produces a unified **SARIF 2.1.0** report consumable by GitHub Advanced Security, VS Code, and other industry-standard tooling.

Project site: [GitHub Pages documentation](https://adityabyreddy.github.io/security-advisor/)

---

## Overview

Security Advisor exposes five MCP tools that an AI assistant (e.g., Claude, Gemini) can invoke to analyse a codebase:

| Tool | Description |
|---|---|
| `security_sast_skill` | Static Application Security Testing via **Semgrep** |
| `security_sca_skill` | Software Composition Analysis via **Trivy** (dependency vulnerabilities) |
| `security_iac_scan_skill` | Infrastructure-as-Code misconfiguration scan via **Trivy** (Terraform, K8s, Docker) |
| `security_container_skill` | Container image security scan via **DockerScan v2.0** (CIS benchmark, secrets, CVEs, supply-chain, runtime) |
| `security_advisor_skill` | **Master skill** — runs all scans in parallel and exports a unified SARIF report |
| `security_publish_to_vulnerability_manager_skill` | Runs scans, converts findings to `vulnerability_schema.json` payload, and uploads to Vulnerability Manager for a target Organization/Project/Service/Version |

### How It Works

```
AI Assistant
    │
    └─► security_advisor_skill(project_path, image="nginx:latest")
             │
             ├─► security_sast_skill          →  Semgrep JSON
             ├─► security_sca_skill            →  Trivy vuln JSON
             ├─► security_iac_scan_skill       →  Trivy config JSON
             └─► security_container_skill      →  DockerScan JSON  (optional)
                          │
                          ▼
                  build_sarif_report()          ← pkg/sarif_report.py
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
| **DockerScan** | v2.0+ | See [DockerScan Installation](#dockerscan-installation) below |

### Verify Prerequisites

```bash
python3 --version   # Should be 3.14+
uv --version
semgrep --version
trivy --version
dockerscan --version
```

### DockerScan Installation

DockerScan v2.0 is a single Go binary — no Python/pip required.

```bash
# macOS (Apple Silicon)
curl -L https://github.com/cr0hn/dockerscan/releases/latest/download/dockerscan-darwin-arm64 -o dockerscan
chmod +x dockerscan && sudo mv dockerscan /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/cr0hn/dockerscan/releases/latest/download/dockerscan-darwin-amd64 -o dockerscan
chmod +x dockerscan && sudo mv dockerscan /usr/local/bin/

# Linux (amd64)
curl -L https://github.com/cr0hn/dockerscan/releases/latest/download/dockerscan-linux-amd64 -o dockerscan
chmod +x dockerscan && sudo mv dockerscan /usr/local/bin/
```

> **First-time setup** — download the NVD CVE database (~30 MB, updated daily) before scanning:
> ```bash
> dockerscan update-db
> ```

---

## Project Structure

```
security-advisor/
├── main.py               # MCP server entry point — exposes all scan tools
├── pkg/
│   ├── __init__.py
│   ├── sarif_report.py   # SARIF 2.1.0 builder (parses Semgrep + Trivy + DockerScan JSON)
│   └── container_scanner.py  # DockerScan CLI wrapper and output parser
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

To also scan a Docker container image, provide the `image` parameter:

```
Run a full security analysis on /path/to/my-project and scan the nginx:latest container image
```

The assistant will invoke `security_advisor_skill` with `image="nginx:latest"`, running DockerScan in parallel and including its findings in the unified SARIF report.

### Individual Tools

You can also invoke individual scan tools:

```
Run a SAST scan on /path/to/my-project
Run an SCA scan on /path/to/my-project
Run an IaC scan on /path/to/my-project
Scan the nginx:latest Docker image for security issues
```

### Publish Scan Results To Vulnerability Manager

Use the dedicated publish action when you want Security Advisor to both scan and upload findings into Vulnerability Manager:

```
Run Security Advisor on /path/to/my-project and publish results to Vulnerability Manager
organization=Acme
project=Payments
service=checkout-api
version=v1.4.2
```

The action will:

1. Run SAST, SCA, IaC (and optional container) scans.
2. Convert findings into `vulnerability_schema.json`-compatible JSON.
3. Resolve or create the Organization → Project → Service → Version hierarchy.
4. Upload the payload to `/api/versions/{version_id}/vulnerabilities/upload`.

Optional parameters:

### Authentication

Vulnerability Manager now requires JWT authorization for API requests.

Use these environment variables to control the shared basic-auth login credentials and token signing secret:

- `SECURITY_ADVISOR_AUTH_USERNAME` - login username, defaults to `admin`
- `SECURITY_ADVISOR_AUTH_PASSWORD` - login password, defaults to `admin`
- `SECURITY_ADVISOR_JWT_SECRET` - JWT signing secret, defaults to `change-me-in-production`
- `SECURITY_ADVISOR_ACCESS_TOKEN_EXPIRE_MINUTES` - token lifetime, defaults to `60`

The MCP publish action logs in with the basic-auth credentials, receives a JWT from `/api/auth/token`, and uses that bearer token for all manager API calls.

The first admin account is bootstrapped from these same credentials on startup if no admin user exists yet.

### User Management

Admin users can manage users through the API:

- `GET /api/users`
- `POST /api/users`
- `GET /api/users/{user_id}`
- `PUT /api/users/{user_id}`
- `DELETE /api/users/{user_id}`

User records include `name`, `email`, `username`, `password`, `role`, and `api_key`. Passwords and API keys are stored hashed; the raw API key is returned when a user is created or regenerated.

- `vulnerability_manager_url` (default: `http://127.0.0.1:8000`)
- `image` (for optional container scan)

---

## SARIF Report

The exported **`Security-Advisor-Report.sarif`** is a valid [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) document containing up to four `runs`:

| Run | Tool | Findings | Present when |
|---|---|---|---|
| `runs[0]` | Semgrep | SAST code-level issues | Always |
| `runs[1]` | Trivy | SCA dependency vulnerabilities | Always |
| `runs[2]` | Trivy | IaC misconfigurations | Always |
| `runs[3]` | DockerScan | Container image findings | When `image` is provided |

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
| `dockerscan` | Container image security scanning (CIS, secrets, CVEs, supply-chain, runtime) |


---

## Contributing

1. Fork the repository and create a feature branch
2. Make your changes and ensure the server starts cleanly (`uv run main.py`)
3. Test manually using `fastmcp dev main.py`
4. Open a pull request with a clear description of the changes

---

## License

This project is licensed under the **MIT License**.
