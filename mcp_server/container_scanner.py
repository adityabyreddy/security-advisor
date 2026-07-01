"""
pkg/container_scanner.py
------------------------
Thin wrapper around the dockerscan v2.0 CLI binary.

Invocation pattern:
    dockerscan -q --format json <image>

Exit codes (from dockerscan docs):
    0  – no findings / clean
    1  – warnings found
    2  – critical findings found
    Any non-zero exit is still a valid scan result; the JSON is still
    written to stdout, so we always attempt to parse it.
"""

from __future__ import annotations

import json
import shutil
import subprocess


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def run_dockerscan(image: str) -> str:
    """
    Run ``dockerscan -q --format json <image>`` and return raw stdout.

    Raises
    ------
    FileNotFoundError
        If the ``dockerscan`` binary is not on PATH.
    RuntimeError
        If the process fails in an unexpected way (stderr present, no stdout).
    """
    if not shutil.which("dockerscan"):
        raise FileNotFoundError(
            "dockerscan binary not found on PATH. "
            "Install it from https://github.com/cr0hn/dockerscan/releases "
            "and run `dockerscan update-db` before using this skill."
        )

    cmd = ["dockerscan", "-q", "--format", "json", image]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # dockerscan exits with 1 (warnings) or 2 (critical) when findings exist.
    # That is still a valid, parseable result — only bail out when there is
    # no usable stdout at all.
    if not result.stdout.strip():
        err = result.stderr.strip() or "(no output)"
        raise RuntimeError(
            f"dockerscan produced no output for image '{image}'. "
            f"stderr: {err}\n"
            "Ensure the CVE database is initialised with `dockerscan update-db`."
        )

    return result.stdout


def parse_dockerscan_output(raw: str) -> dict:
    """
    Parse the JSON emitted by dockerscan and return a normalised dict::

        {
            "image":  "<name>",
            "summary": {
                "total_findings": <int>,
                "by_severity": {
                    "CRITICAL": <int>,
                    "HIGH":     <int>,
                    "MEDIUM":   <int>,
                    "LOW":      <int>,
                    "INFO":     <int>,
                }
            },
            "findings": [
                {
                    "id":          "<rule-id>",
                    "scanner":     "<cis|secrets|supply-chain|vulnerabilities|runtime>",
                    "severity":    "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
                    "title":       "<short title>",
                    "description": "<detail>",
                    "remediation": "<remediation hint>",
                    "references":  ["<url>", ...],
                },
                ...
            ]
        }
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Could not parse dockerscan JSON output: {exc}") from exc

    # ── Normalise the summary ────────────────────────────────────────────────
    summary_raw = data.get("summary", {})
    by_sev_raw  = summary_raw.get("by_severity", {})

    by_severity: dict[str, int] = {
        "CRITICAL": int(by_sev_raw.get("CRITICAL", 0)),
        "HIGH":     int(by_sev_raw.get("HIGH",     0)),
        "MEDIUM":   int(by_sev_raw.get("MEDIUM",   0)),
        "LOW":      int(by_sev_raw.get("LOW",       0)),
        "INFO":     int(by_sev_raw.get("INFO",      0)),
    }
    total = int(summary_raw.get("total_findings", sum(by_severity.values())))

    # ── Normalise individual findings ────────────────────────────────────────
    findings = []
    for f in data.get("findings", []):
        findings.append({
            "id":          str(f.get("id",          f.get("rule_id", "unknown"))),
            "scanner":     str(f.get("scanner",     "unknown")),
            "severity":    str(f.get("severity",    "INFO")).upper(),
            "title":       str(f.get("title",       f.get("name", ""))),
            "description": str(f.get("description", "")),
            "remediation": str(f.get("remediation", f.get("fix", ""))),
            "references":  list(f.get("references", f.get("refs", []))),
        })

    return {
        "image":   str(data.get("image", "")),
        "summary": {"total_findings": total, "by_severity": by_severity},
        "findings": findings,
    }


def build_human_summary(parsed: dict) -> str:
    """
    Return a Markdown-formatted human-readable summary of the scan result.
    """
    image   = parsed.get("image", "(unknown)")
    summary = parsed.get("summary", {})
    total   = summary.get("total_findings", 0)
    by_sev  = summary.get("by_severity", {})

    lines = [
        f"## 🐳 Container Image Scan — `{image}`\n",
        f"**Total findings:** {total}\n",
        "### Severity Breakdown\n",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = by_sev.get(sev, 0)
        if count:
            lines.append(f"| {sev} | {count} |")

    if total == 0:
        lines.append("\n✅ No security findings detected.")
    else:
        lines.append(
            "\n⚠️ Review the SARIF report for detailed remediation guidance."
        )

    return "\n".join(lines)
