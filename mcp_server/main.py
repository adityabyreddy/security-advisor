from mcp.server.fastmcp import FastMCP
import subprocess
import json
import asyncio
import os
import uuid
import base64
from urllib import error as urlerror
from urllib import request as urlrequest
from mcp_server.sarif_report import build_sarif_report
from mcp_server.container_scanner import (
    run_dockerscan,
    parse_dockerscan_output,
    build_human_summary as build_container_summary,
)

# Initialize the MCP Server
mcp = FastMCP("SecurityAdvisor")

_APPLICATION_JSON = "application/json"
_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_AUTH_USERNAME = os.getenv("SECURITY_ADVISOR_AUTH_USERNAME", "admin")
_AUTH_PASSWORD = os.getenv("SECURITY_ADVISOR_AUTH_PASSWORD", "admin")


def _normalize_severity(value: str | None) -> str:
    if not value:
        return "INFO"
    normalized = str(value).upper()
    if normalized in _VALID_SEVERITIES:
        return normalized
    fallback_map = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "WARN": "MEDIUM",
        "UNKNOWN": "INFO",
    }
    return fallback_map.get(normalized, "INFO")


def _safe_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return []


def _basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _http_json(
    method: str,
    url: str,
    payload: dict | None = None,
    headers: dict[str, str] | None = None,
) -> dict | list:
    data = None
    request_headers = {"Accept": _APPLICATION_JSON}
    if headers:
        request_headers.update(headers)
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = _APPLICATION_JSON

    req = urlrequest.Request(url=url, method=method, data=data, headers=request_headers)
    try:
        with urlrequest.urlopen(req, timeout=30) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urlerror.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} for {method} {url}: {body}") from exc
    except urlerror.URLError as exc:
        raise RuntimeError(f"Network error calling {method} {url}: {exc.reason}") from exc


def _login_to_vulnerability_manager(base_url: str) -> str:
    response = _http_json(
        "POST",
        f"{base_url.rstrip('/')}/api/auth/token",
        headers={"Authorization": _basic_auth_header(_AUTH_USERNAME, _AUTH_PASSWORD)},
    )
    token = response.get("access_token") if isinstance(response, dict) else None
    if not token:
        raise RuntimeError("Manager login did not return an access token")
    return str(token)


def _upload_schema_payload(base_url: str, version_id: int, payload: dict, token: str) -> dict:
    boundary = f"----SecurityAdvisorBoundary{uuid.uuid4().hex}"
    schema_json = json.dumps(payload, indent=2).encode("utf-8")

    body = b""
    body += f"--{boundary}\r\n".encode("utf-8")
    body += b'Content-Disposition: form-data; name="file"; filename="vulnerabilities.json"\r\n'
    body += f"Content-Type: {_APPLICATION_JSON}\r\n\r\n".encode("utf-8")
    body += schema_json
    body += b"\r\n"
    body += f"--{boundary}--\r\n".encode("utf-8")

    url = f"{base_url.rstrip('/')}/api/versions/{version_id}/vulnerabilities/upload"
    headers = {
        "Accept": "application/json",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Authorization": f"Bearer {token}",
    }
    req = urlrequest.Request(url=url, method="POST", data=body, headers=headers)
    try:
        with urlrequest.urlopen(req, timeout=60) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urlerror.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} for POST {url}: {body}") from exc
    except urlerror.URLError as exc:
        raise RuntimeError(f"Network error calling POST {url}: {exc.reason}") from exc


def _get_or_create_organization(base_url: str, organization_name: str, token: str) -> int:
    orgs = _http_json(
        "GET",
        f"{base_url.rstrip('/')}/api/organizations",
        headers={"Authorization": f"Bearer {token}"},
    )
    for org in orgs:
        if str(org.get("name", "")).strip().lower() == organization_name.strip().lower():
            return int(org["id"])

    created = _http_json(
        "POST",
        f"{base_url.rstrip('/')}/api/organizations",
        {"name": organization_name},
        headers={"Authorization": f"Bearer {token}"},
    )
    return int(created["id"])


def _get_or_create_project(base_url: str, org_id: int, project_name: str, token: str) -> int:
    projects = _http_json(
        "GET",
        f"{base_url.rstrip('/')}/api/organizations/{org_id}/projects",
        headers={"Authorization": f"Bearer {token}"},
    )
    for project in projects:
        if str(project.get("name", "")).strip().lower() == project_name.strip().lower():
            return int(project["id"])

    created = _http_json(
        "POST",
        f"{base_url.rstrip('/')}/api/organizations/{org_id}/projects",
        {"name": project_name},
        headers={"Authorization": f"Bearer {token}"},
    )
    return int(created["id"])


def _get_or_create_service(base_url: str, project_id: int, service_name: str, token: str) -> int:
    services = _http_json(
        "GET",
        f"{base_url.rstrip('/')}/api/projects/{project_id}/services",
        headers={"Authorization": f"Bearer {token}"},
    )
    for service in services:
        if str(service.get("name", "")).strip().lower() == service_name.strip().lower():
            return int(service["id"])

    created = _http_json(
        "POST",
        f"{base_url.rstrip('/')}/api/projects/{project_id}/services",
        {"name": service_name},
        headers={"Authorization": f"Bearer {token}"},
    )
    return int(created["id"])


def _get_or_create_version(base_url: str, service_id: int, version_name: str, token: str) -> int:
    versions = _http_json(
        "GET",
        f"{base_url.rstrip('/')}/api/services/{service_id}/versions",
        headers={"Authorization": f"Bearer {token}"},
    )
    for version in versions:
        if str(version.get("name", "")).strip().lower() == version_name.strip().lower():
            return int(version["id"])

    created = _http_json(
        "POST",
        f"{base_url.rstrip('/')}/api/services/{service_id}/versions",
        {"name": version_name},
        headers={"Authorization": f"Bearer {token}"},
    )
    return int(created["id"])


def _extract_cvss_score(finding: dict) -> float | None:
    cvss_obj = finding.get("CVSS")
    if isinstance(cvss_obj, dict):
        for _, score_data in cvss_obj.items():
            if isinstance(score_data, dict):
                score = score_data.get("V3Score")
                if isinstance(score, (int, float)):
                    return float(score)
    score = finding.get("CVSSScore")
    if isinstance(score, (int, float)):
        return float(score)
    return None


def _convert_sast_findings(sast_json: dict) -> list[dict]:
    items: list[dict] = []
    for finding in sast_json.get("results", []):
        extra = finding.get("extra", {})
        metadata = extra.get("metadata", {})
        path = finding.get("path", "")
        line = finding.get("start", {}).get("line")
        affected_component = f"{path}:{line}" if path and line else path
        cwe = metadata.get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None

        items.append(
            {
                "title": extra.get("message") or finding.get("check_id") or "Semgrep finding",
                "description": extra.get("message") or "Semgrep finding detected.",
                "severity": _normalize_severity(extra.get("severity")),
                "status": "OPEN",
                "cwe_id": str(cwe) if cwe else None,
                "affected_component": affected_component or None,
                "remediation": "Review rule guidance and apply secure coding remediation.",
                "source_tool": "Semgrep",
                "references": _safe_list(metadata.get("references")),
            }
        )
    return items


def _build_sca_item(finding: dict, target: str) -> dict:
    cve_id = finding.get("VulnerabilityID")
    cwe_ids = _safe_list(finding.get("CweIDs") or finding.get("CWEIDs"))
    installed_version = finding.get("InstalledVersion")
    pkg_name = finding.get("PkgName")
    component = "@".join([v for v in [pkg_name, installed_version] if v])
    return {
        "title": finding.get("Title") or cve_id or "Dependency vulnerability",
        "description": finding.get("Description")
        or finding.get("Title")
        or "Dependency vulnerability detected.",
        "severity": _normalize_severity(finding.get("Severity")),
        "status": "OPEN",
        "cvss_score": _extract_cvss_score(finding),
        "cve_id": cve_id if isinstance(cve_id, str) and cve_id.startswith("CVE-") else None,
        "cwe_id": cwe_ids[0] if cwe_ids else None,
        "affected_component": component or target or None,
        "remediation": (
            f"Upgrade to {finding.get('FixedVersion')}"
            if finding.get("FixedVersion")
            else None
        ),
        "source_tool": "Trivy",
        "references": _safe_list(finding.get("References")),
    }


def _convert_sca_findings(sca_json: dict) -> list[dict]:
    items: list[dict] = []
    for target_block in sca_json.get("Results", []):
        target = target_block.get("Target", "")
        for finding in target_block.get("Vulnerabilities", []) or []:
            items.append(_build_sca_item(finding, target))
    return items


def _convert_iac_findings(iac_json: dict) -> list[dict]:
    items: list[dict] = []
    for target_block in iac_json.get("Results", []):
        target = target_block.get("Target", "")
        for finding in target_block.get("Misconfigurations", []) or []:
            items.append(
                {
                    "title": finding.get("Title") or finding.get("ID") or "IaC misconfiguration",
                    "description": finding.get("Description")
                    or finding.get("Message")
                    or "Infrastructure misconfiguration detected.",
                    "severity": _normalize_severity(finding.get("Severity")),
                    "status": "OPEN",
                    "affected_component": target or None,
                    "remediation": finding.get("Resolution") or finding.get("Remediation") or None,
                    "source_tool": "Trivy",
                    "references": _safe_list(finding.get("References")),
                }
            )
    return items


def _convert_gemini_findings(gemini_json: dict) -> list[dict]:
    items: list[dict] = []
    for finding in gemini_json.get("findings", []):
        file_path = finding.get("file_path", "")
        line_number = finding.get("line_number")
        affected_component = (
            f"{file_path}:{line_number}" if file_path and line_number else file_path or None
        )
        items.append(
            {
                "title": finding.get("issue") or "Gemini code review finding",
                "description": (
                    f"[{finding.get('category', 'GENERAL')}] {finding.get('issue', '')}"
                ).strip("[] ") or "Gemini code review finding.",
                "severity": _normalize_severity(finding.get("severity")),
                "status": "OPEN",
                "affected_component": affected_component,
                "remediation": finding.get("suggestion") or None,
                "source_tool": "Gemini Code Review",
            }
        )
    return items


def _convert_container_findings(container_raw: str) -> list[dict]:
    if not container_raw.strip():
        return []

    items: list[dict] = []
    parsed_container = parse_dockerscan_output(container_raw)
    image = parsed_container.get("image", "")
    for finding in parsed_container.get("findings", []):
        items.append(
            {
                "title": finding.get("title") or finding.get("id") or "Container finding",
                "description": finding.get("description") or "Container security finding detected.",
                "severity": _normalize_severity(finding.get("severity")),
                "status": "OPEN",
                "affected_component": image or None,
                "remediation": finding.get("remediation") or None,
                "source_tool": "DockerScan",
                "references": _safe_list(finding.get("references")),
            }
        )
    return items


def _clean_vulnerability_items(vulnerabilities: list[dict]) -> list[dict]:
    allowed_keys = {
        "title",
        "description",
        "severity",
        "status",
        "cvss_score",
        "cve_id",
        "cwe_id",
        "affected_component",
        "remediation",
        "source_tool",
        "references",
    }
    cleaned = []
    for vuln in vulnerabilities:
        item = {}
        for key in allowed_keys:
            value = vuln.get(key)
            if value is None:
                continue
            if isinstance(value, str) and not value.strip():
                continue
            if key == "references" and not value:
                continue
            item[key] = value
        cleaned.append(item)
    return cleaned


def _convert_to_upload_payload(
    sast_raw: str,
    sca_raw: str,
    iac_raw: str,
    container_raw: str = "",
) -> dict:
    sast_json = json.loads(sast_raw) if sast_raw.strip() else {}
    sca_json = json.loads(sca_raw) if sca_raw.strip() else {}
    iac_json = json.loads(iac_raw) if iac_raw.strip() else {}

    vulnerabilities: list[dict] = []
    vulnerabilities.extend(_convert_sast_findings(sast_json))
    vulnerabilities.extend(_convert_sca_findings(sca_json))
    vulnerabilities.extend(_convert_iac_findings(iac_json))
    vulnerabilities.extend(_convert_container_findings(container_raw))

    return {"vulnerabilities": _clean_vulnerability_items(vulnerabilities)}

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

# 4. Gemini Code Review Skill
@mcp.tool()
async def security_gemini_code_review_skill(path: str) -> str:
    """
    Runs Gemini CLI code review on the current branch's changes.

    Executes ``gemini`` in non-interactive mode with the code-review skill,
    parses the JSON output, and returns a vulnerability-schema-compatible JSON
    payload (``{"vulnerabilities": [...]}``) ready for upload to Vulnerability
    Manager.

    Parameters
    ----------
    path : str
        Absolute path to the git repository root to review.
    """
    cmd = [
        "gemini",
        "-p", "activate the code review skill and review code changes in current branch",
        "--yolo",
        "-e", "code-review",
        "--output-format", "json",
    ]
    result = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: subprocess.run(
            cmd, capture_output=True, text=True, cwd=path
        ),
    )

    raw_output = result.stdout.strip()
    if not raw_output:
        error_detail = result.stderr.strip()
        return json.dumps(
            {"error": "Gemini code review produced no output.", "stderr": error_detail}
        )

    # Gemini may prefix streaming text before the JSON block; extract the
    # last {...} or [...] block to be safe.
    try:
        gemini_json = json.loads(raw_output)
    except json.JSONDecodeError:
        # Try to extract a JSON object from within the output
        start = raw_output.rfind("{")
        end = raw_output.rfind("}") + 1
        if start != -1 and end > start:
            try:
                gemini_json = json.loads(raw_output[start:end])
            except json.JSONDecodeError:
                return json.dumps(
                    {"error": "Could not parse Gemini output as JSON.", "raw": raw_output}
                )
        else:
            return json.dumps(
                {"error": "Could not parse Gemini output as JSON.", "raw": raw_output}
            )

    vulnerabilities = _convert_gemini_findings(gemini_json)
    payload = {"vulnerabilities": _clean_vulnerability_items(vulnerabilities)}
    return json.dumps(payload, indent=2)


# 5. Container Image Skill
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


@mcp.tool()
async def security_publish_to_vulnerability_manager_skill(
    project_path: str,
    organization: str,
    project: str,
    service: str,
    version: str,
    vulnerability_manager_url: str = "http://127.0.0.1:8000",
    image: str = "",
) -> str:
    """
    Runs Security Advisor scans, converts findings to vulnerability_schema.json-compatible
    payload, and uploads findings into Vulnerability Manager.

    Parameters
    ----------
    project_path : str
        Absolute path to the project directory to scan.
    organization : str
        Vulnerability Manager organization name.
    project : str
        Vulnerability Manager project name.
    service : str
        Vulnerability Manager service name.
    version : str
        Vulnerability Manager version name.
    vulnerability_manager_url : str, optional
        Base URL for the Vulnerability Manager API, default is
        ``http://127.0.0.1:8000``.
    image : str, optional
        Docker image reference for container scanning.
    """
    code_coros = [
        security_sast_skill(project_path),
        security_sca_skill(project_path),
        security_iac_scan_skill(project_path),
    ]

    container_raw = ""
    if image.strip():
        sast_raw, sca_raw, iac_raw, _ = await asyncio.gather(
            *code_coros,
            security_container_skill(image),
        )
        try:
            container_raw = await asyncio.get_event_loop().run_in_executor(
                None, run_dockerscan, image
            )
        except (FileNotFoundError, RuntimeError):
            container_raw = ""
    else:
        sast_raw, sca_raw, iac_raw = await asyncio.gather(*code_coros)

    payload = _convert_to_upload_payload(sast_raw, sca_raw, iac_raw, container_raw)
    vulnerability_count = len(payload.get("vulnerabilities", []))
    if vulnerability_count == 0:
        return (
            "## Vulnerability Manager Publish\n"
            "No findings were generated by the scan tools, so nothing was uploaded."
        )

    try:
        token = _login_to_vulnerability_manager(vulnerability_manager_url)
        org_id = _get_or_create_organization(vulnerability_manager_url, organization, token)
        project_id = _get_or_create_project(vulnerability_manager_url, org_id, project, token)
        service_id = _get_or_create_service(vulnerability_manager_url, project_id, service, token)
        version_id = _get_or_create_version(vulnerability_manager_url, service_id, version, token)
        upload_result = _upload_schema_payload(vulnerability_manager_url, version_id, payload, token)
    except RuntimeError as exc:
        return f"## Vulnerability Manager Publish Error\n\n{exc}"

    uploaded_count = upload_result.get("created", vulnerability_count)
    return (
        "## Vulnerability Manager Publish\n"
        f"- Organization: **{organization}**\n"
        f"- Project: **{project}**\n"
        f"- Service: **{service}**\n"
        f"- Version: **{version}**\n"
        f"- Findings converted to schema payload: **{vulnerability_count}**\n"
        f"- Findings uploaded: **{uploaded_count}**"
    )

@mcp.tool()
async def security_gemini_publish_to_vulnerability_manager_skill(
    path: str,
    organization: str,
    project: str,
    service: str,
    version: str,
    vulnerability_manager_url: str = "http://127.0.0.1:8000",
) -> str:
    """
    Runs Gemini CLI code review, converts findings to vulnerability_schema.json-compatible
    payload, and uploads them into Vulnerability Manager.

    Parameters
    ----------
    path : str
        Absolute path to the git repository root to review.
    organization : str
        Vulnerability Manager organization name.
    project : str
        Vulnerability Manager project name.
    service : str
        Vulnerability Manager service name.
    version : str
        Vulnerability Manager version name.
    vulnerability_manager_url : str, optional
        Base URL for the Vulnerability Manager API, default is
        ``http://127.0.0.1:8000``.
    """
    raw_result = await security_gemini_code_review_skill(path)

    try:
        result_json = json.loads(raw_result)
    except json.JSONDecodeError:
        return f"## Gemini Publish Error\n\nCould not parse Gemini code review output as JSON."

    if "error" in result_json:
        return (
            f"## Gemini Publish Error\n\n"
            f"{result_json.get('error', 'Unknown error')}\n\n"
            f"{result_json.get('stderr', '')}"
        ).strip()

    vulnerability_count = len(result_json.get("vulnerabilities", []))
    if vulnerability_count == 0:
        return (
            "## Gemini Code Review Publish\n"
            "No findings were produced by Gemini code review, so nothing was uploaded."
        )

    try:
        token = _login_to_vulnerability_manager(vulnerability_manager_url)
        org_id = _get_or_create_organization(vulnerability_manager_url, organization, token)
        project_id = _get_or_create_project(vulnerability_manager_url, org_id, project, token)
        service_id = _get_or_create_service(vulnerability_manager_url, project_id, service, token)
        version_id = _get_or_create_version(vulnerability_manager_url, service_id, version, token)
        upload_result = _upload_schema_payload(vulnerability_manager_url, version_id, result_json, token)
    except RuntimeError as exc:
        return f"## Gemini Publish Error\n\n{exc}"

    uploaded_count = upload_result.get("created", vulnerability_count)
    return (
        "## Gemini Code Review Publish\n"
        f"- Organization: **{organization}**\n"
        f"- Project: **{project}**\n"
        f"- Service: **{service}**\n"
        f"- Version: **{version}**\n"
        f"- Findings converted to schema payload: **{vulnerability_count}**\n"
        f"- Findings uploaded: **{uploaded_count}**"
    )


if __name__ == "__main__":
    mcp.run()