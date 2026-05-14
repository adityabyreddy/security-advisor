from mcp.server.fastmcp import FastMCP
import subprocess
import json
import asyncio
import os
from pkg.sarif_report import build_sarif_report

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

# ---------------------------------------------------------------------------
# 🌟 THE MASTER SKILL: Security Advisor
# ---------------------------------------------------------------------------

@mcp.tool()
async def security_advisor_skill(project_path: str) -> str:
    """
    The Master Skill: Orchestrates SAST, SCA, and IaC scans 
    to provide a unified security posture report.

    Generates a SARIF 2.1.0 report and exports it to
    <project_path>/Security-Advisor-Report.sarif.
    """
    # Run all three scans in parallel
    sast_raw, sca_raw, iac_raw = await asyncio.gather(
        security_sast_skill(project_path),
        security_sca_skill(project_path),
        security_iac_scan_skill(project_path),
    )

    # Parse raw JSON safely (tools may return empty strings on error)
    sast_json = json.loads(sast_raw) if sast_raw.strip() else {}
    sca_json  = json.loads(sca_raw)  if sca_raw.strip()  else {}
    iac_json  = json.loads(iac_raw)  if iac_raw.strip()  else {}

    sast_count = len(sast_json.get("results", []))
    sca_count  = len(sca_json.get("Results",  []))
    iac_count  = len(iac_json.get("Results",  []))

    # Build the SARIF report
    sarif_report = build_sarif_report(sast_raw, sca_raw, iac_raw)

    # Export SARIF file to the target project's root directory
    sarif_path = os.path.join(project_path, "Security-Advisor-Report.sarif")
    with open(sarif_path, "w", encoding="utf-8") as f:
        json.dump(sarif_report, f, indent=2)

    # Human-readable summary returned to the AI assistant
    report = (
        "## Security Advisor Analysis Report\n"
        f"- **SAST Results:** {sast_count} issues found.\n"
        f"- **SCA Results:** {sca_count} vulnerability sets found.\n"
        f"- **IaC Results:** {iac_count} misconfiguration sets found.\n\n"
        f"📄 **SARIF report exported to:** `{sarif_path}`\n\n"
        "Please review the detailed logs for specific remediation steps."
    )
    return report

if __name__ == "__main__":
    mcp.run()