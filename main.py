from mcp.server.fastmcp import FastMCP
import subprocess
import json
import asyncio
import os
from pkg.sarif_report import build_sarif_report
from pkg.container_scanner import (
    run_dockerscan,
    parse_dockerscan_output,
    build_human_summary as build_container_summary,
)

# Initialize the MCP Server
mcp = FastMCP("SecurityAdvisor")

# ---------------------------------------------------------------------------
# Individual scan skills
# ---------------------------------------------------------------------------

# 1. SAST Skill
@mcp.tool()
async def security_sast_skill(path: str) -> str:
    """Runs Semgrep locally for Static Analysis."""
    cmd = ["semgrep", "scan", "--config=auto", "--json", path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

# 2. SCA Skill
@mcp.tool()
async def security_sca_skill(path: str) -> str:
    """Runs Trivy locally to find vulnerable 3rd party libraries."""
    cmd = ["trivy", "fs", "--scanners", "vuln", "--format", "json", path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

# 3. IaC Skill
@mcp.tool()
async def security_iac_scan_skill(path: str) -> str:
    """Scans Terraform, K8s, and Docker files for misconfigurations."""
    cmd = ["trivy", "config", "--format", "json", path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

# 4. Container Image Skill
@mcp.tool()
async def security_container_skill(image: str) -> str:
    """
    Scans a Docker container image using DockerScan v2.0.

    Runs five scanning modules in parallel against the named image:
    - CIS Docker Benchmark v1.7.0 (80+ compliance checks)
    - Supply-chain attack detection (mining, backdoors, image signing)
    - Secrets detection (40+ patterns, entropy analysis)
    - CVE / vulnerability scanning (2024-2025 NVD database)
    - Runtime security analysis (capabilities, seccomp, AppArmor, namespaces)

    Parameters
    ----------
    image : str
        Docker image reference to scan, e.g. ``nginx:latest`` or
        ``ghcr.io/myorg/myapp:v1.2.3``.

    Returns a Markdown-formatted summary with severity-level breakdown.
    Requires ``dockerscan`` on PATH and the CVE database initialised
    via ``dockerscan update-db``.
    """
    try:
        raw = await asyncio.get_event_loop().run_in_executor(
            None, run_dockerscan, image
        )
        parsed = parse_dockerscan_output(raw)
        return build_container_summary(parsed)
    except FileNotFoundError as exc:
        return (
            f"## Container Scan Error\n\n"
            f"{exc}\n\n"
            "Install dockerscan from https://github.com/cr0hn/dockerscan/releases"
        )
    except (RuntimeError, ValueError) as exc:
        return f"## Container Scan Error\n\n{exc}"

# ---------------------------------------------------------------------------
# THE MASTER SKILL: Security Advisor
# ---------------------------------------------------------------------------

@mcp.tool()
async def security_advisor_skill(project_path: str, image: str = "") -> str:
    """
    The Master Skill: Orchestrates SAST, SCA, IaC, and (optionally) container
    image scans to provide a unified security posture report.

    Generates a SARIF 2.1.0 report and exports it to
    <project_path>/Security-Advisor-Report.sarif.

    Parameters
    ----------
    project_path : str
        Absolute path to the project directory to scan.
    image : str, optional
        Docker image reference to scan (e.g. ``nginx:latest``). When supplied,
        a DockerScan container analysis is run in parallel with the code scans
        and its findings are included in the unified SARIF report.
    """
    # Build the coroutine list — always run the three code-level scans
    code_coros = [
        security_sast_skill(project_path),
        security_sca_skill(project_path),
        security_iac_scan_skill(project_path),
    ]

    container_raw = ""
    if image.strip():
        # Run all four scans concurrently
        sast_raw, sca_raw, iac_raw, _ = await asyncio.gather(
            *code_coros,
            security_container_skill(image),   # summary (for logging); raw JSON fetched below
        )
        # Fetch raw dockerscan JSON separately for SARIF aggregation
        try:
            container_raw = await asyncio.get_event_loop().run_in_executor(
                None, run_dockerscan, image
            )
        except (FileNotFoundError, RuntimeError):
            container_raw = ""
    else:
        sast_raw, sca_raw, iac_raw = await asyncio.gather(*code_coros)

    # Parse raw JSON safely (tools may return empty strings on error)
    sast_json = json.loads(sast_raw) if sast_raw.strip() else {}
    sca_json  = json.loads(sca_raw)  if sca_raw.strip()  else {}
    iac_json  = json.loads(iac_raw)  if iac_raw.strip()  else {}

    sast_count = len(sast_json.get("results", []))
    sca_count  = len(sca_json.get("Results",  []))
    iac_count  = len(iac_json.get("Results",  []))

    # Build the unified SARIF report (container_raw="" if no image was given)
    sarif_report = build_sarif_report(sast_raw, sca_raw, iac_raw, container_raw)

    # Export SARIF file to the target project's root directory
    sarif_path = os.path.join(project_path, "Security-Advisor-Report.sarif")
    with open(sarif_path, "w", encoding="utf-8") as f:
        json.dump(sarif_report, f, indent=2)

    # Optionally include container finding count in the summary
    container_line = ""
    if image.strip() and container_raw.strip():
        try:
            container_json  = json.loads(container_raw)
            container_count = container_json.get("summary", {}).get("total_findings", "N/A")
        except (json.JSONDecodeError, AttributeError):
            container_count = "N/A"
        container_line = (
            f"- **Container Scan Results (`{image}`):** {container_count} findings.\n"
        )

    # Human-readable summary returned to the AI assistant
    report = (
        "## Security Advisor Analysis Report\n"
        f"- **SAST Results:** {sast_count} issues found.\n"
        f"- **SCA Results:** {sca_count} vulnerability sets found.\n"
        f"- **IaC Results:** {iac_count} misconfiguration sets found.\n"
        f"{container_line}"
        f"\n📄 **SARIF report exported to:** `{sarif_path}`\n\n"
        "Please review the detailed logs for specific remediation steps."
    )
    return report

if __name__ == "__main__":
    mcp.run()