from datetime import datetime, timezone
import json

# ---------------------------------------------------------------------------
# SARIF 2.1.0 builder
# ---------------------------------------------------------------------------

def _severity_to_sarif_level(severity: str) -> str:
    """Map a tool-specific severity string to a SARIF notification level."""
    mapping = {
        "critical": "error",
        "high":     "error",
        "medium":   "warning",
        "low":      "note",
        "info":     "note",
    }
    return mapping.get(severity.lower(), "warning")


def _parse_sast_results(sast_json: dict) -> tuple[list, list]:
    """Convert Semgrep JSON output to SARIF rules + results."""
    rules, results = [], []
    seen_rule_ids: set[str] = set()

    for finding in sast_json.get("results", []):
        rule_id   = finding.get("check_id", "unknown-rule")
        message   = finding.get("extra", {}).get("message", "No message.")
        severity  = finding.get("extra", {}).get("severity", "warning")
        file_path = finding.get("path", "")
        start     = finding.get("start", {})
        end       = finding.get("end", {})

        if rule_id not in seen_rule_ids:
            seen_rule_ids.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": message[:200]},
                "helpUri": finding.get("extra", {}).get("metadata", {}).get("references", [None])[0],
                "properties": {"tags": ["SAST", "semgrep"]},
            })

        results.append({
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(severity),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine":   start.get("line", 1),
                        "startColumn": start.get("col", 1),
                        "endLine":     end.get("line", start.get("line", 1)),
                        "endColumn":   end.get("col", 1),
                    },
                }
            }],
        })

    return rules, results


def _parse_trivy_results(trivy_json: dict, scan_type: str) -> tuple[list, list]:
    """Convert Trivy JSON output (vuln or config) to SARIF rules + results."""
    rules, results = [], []
    seen_rule_ids: set[str] = set()
    tags = ["SCA", "trivy"] if scan_type == "sca" else ["IaC", "trivy"]

    for target_block in trivy_json.get("Results", []):
        target   = target_block.get("Target", "")
        findings = target_block.get("Vulnerabilities") or target_block.get("Misconfigurations") or []

        for finding in findings:
            # Vulnerabilities use VulnerabilityID; Misconfigurations use ID
            rule_id   = finding.get("VulnerabilityID") or finding.get("ID", "unknown")
            title     = finding.get("Title") or finding.get("Description", rule_id)
            desc      = finding.get("Description", title)
            severity  = finding.get("Severity", "UNKNOWN")
            pkg_name  = finding.get("PkgName", "")
            fixed_ver = finding.get("FixedVersion", "")
            refs      = finding.get("References") or finding.get("References", [])

            if rule_id not in seen_rule_ids:
                seen_rule_ids.add(rule_id)
                help_uri = refs[0] if refs else None
                rules.append({
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": title[:200]},
                    "fullDescription":  {"text": desc[:1000]},
                    **({"helpUri": help_uri} if help_uri else {}),
                    "properties": {"tags": tags},
                })

            message_parts = [f"{title} in `{pkg_name or target}`."]
            if fixed_ver:
                message_parts.append(f"Fixed in version: {fixed_ver}.")

            results.append({
                "ruleId": rule_id,
                "level": _severity_to_sarif_level(severity),
                "message": {"text": " ".join(message_parts)},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": target, "uriBaseId": "%SRCROOT%"},
                    }
                }],
            })

    return rules, results


def build_sarif_report(sast_raw: str, sca_raw: str, iac_raw: str) -> dict:
    """
    Aggregate SAST, SCA, and IaC scan outputs into a single SARIF 2.1.0 document.
    Returns the SARIF document as a Python dict.
    """
    sast_json = json.loads(sast_raw) if sast_raw.strip() else {}
    sca_json  = json.loads(sca_raw)  if sca_raw.strip()  else {}
    iac_json  = json.loads(iac_raw)  if iac_raw.strip()  else {}

    sast_rules, sast_results = _parse_sast_results(sast_json)
    sca_rules,  sca_results  = _parse_trivy_results(sca_json,  "sca")
    iac_rules,  iac_results  = _parse_trivy_results(iac_json,  "iac")

    sarif: dict = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            # ── SAST run (Semgrep) ──────────────────────────────────────────
            {
                "tool": {
                    "driver": {
                        "name":           "Semgrep",
                        "informationUri": "https://semgrep.dev",
                        "version":        "latest",
                        "rules":          sast_rules,
                    }
                },
                "results":   sast_results,
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                }],
            },
            # ── SCA run (Trivy – vulnerabilities) ──────────────────────────
            {
                "tool": {
                    "driver": {
                        "name":           "Trivy",
                        "informationUri": "https://trivy.dev",
                        "version":        "latest",
                        "rules":          sca_rules,
                    }
                },
                "results":   sca_results,
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                }],
            },
            # ── IaC run (Trivy – misconfigurations) ────────────────────────
            {
                "tool": {
                    "driver": {
                        "name":           "Trivy",
                        "informationUri": "https://trivy.dev",
                        "version":        "latest",
                        "rules":          iac_rules,
                    }
                },
                "results":   iac_results,
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                }],
            },
        ],
    }
    return sarif