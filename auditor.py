#!/usr/bin/env python3
"""
Cloud Security Auditor

This script audits an AWS account for common misconfigurations using boto3. It checks
for publicly accessible S3 buckets, overly permissive security groups, and IAM users
without Multi‑Factor Authentication (MFA). Results can be exported in CSV, JSON,
and HTML formats.

Prerequisites:
  - Python 3.7+
  - boto3 (install with ``pip install boto3``)
  - AWS credentials configured via environment variables, ``~/.aws/credentials``,
    or an assigned IAM role.

Usage example:
    python auditor.py --formats csv json html --output-prefix findings

This will produce ``findings.csv``, ``findings.json``, and ``findings.html`` in the
current working directory.
"""

import argparse
import boto3
import csv
import json
import os
from typing import Dict, List


def audit_s3_public() -> List[Dict[str, str]]:
    """Identify S3 buckets that are publicly accessible via ACLs or policies.

    The check is deliberately simple: it looks for ACL grants to the ``AllUsers`` or
    ``AuthenticatedUsers`` groups and treats those as public. More comprehensive
    evaluations (e.g., parsing bucket policies) could be added later.
    """
    findings: List[Dict[str, str]] = []
    s3 = boto3.client("s3")
    buckets = s3.list_buckets().get("Buckets", [])
    for bucket in buckets:
        bucket_name = bucket.get("Name")
        if not bucket_name:
            continue
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            grants = acl.get("Grants", [])
            for grant in grants:
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI")
                permission = grant.get("Permission")
                if uri in (
                    "http://acs.amazonaws.com/groups/global/AllUsers",
                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                ):
                    findings.append(
                        {
                            "resource_type": "S3 Bucket",
                            "resource_id": bucket_name,
                            "issue": "Bucket ACL grants public access",
                            "permission": permission,
                        }
                    )
                    # one finding per bucket is enough; skip additional grants
                    break
        except Exception:
            # If we cannot retrieve the ACL, skip to the next bucket
            continue
    return findings


def audit_security_groups() -> List[Dict[str, str]]:
    """Find security groups with inbound rules open to the world (0.0.0.0/0).

    Rules that allow traffic from any IP address pose a significant security risk.
    This function flags any security group with an inbound rule whose CIDR is
    ``0.0.0.0/0``. It includes the port range and protocol in the details.
    """
    findings: List[Dict[str, str]] = []
    ec2 = boto3.client("ec2")
    response = ec2.describe_security_groups()
    for sg in response.get("SecurityGroups", []):
        group_id = sg.get("GroupId", "")
        group_name = sg.get("GroupName", "")
        for permission in sg.get("IpPermissions", []):
            ip_ranges = permission.get("IpRanges", [])
            for rng in ip_ranges:
                cidr = rng.get("CidrIp")
                if cidr == "0.0.0.0/0":
                    from_port = permission.get("FromPort")
                    to_port = permission.get("ToPort")
                    protocol = permission.get("IpProtocol")
                    # Construct a human‑readable port description
                    if from_port is None and to_port is None:
                        port_desc = "All"
                    elif from_port == to_port:
                        port_desc = str(from_port)
                        
                    else:
                        port_desc = f"{from_port}-{to_port}"
                    findings.append(
                        {
                            "resource_type": "Security Group",
                            "resource_id": group_id,
                            "issue": f"Inbound rule open to 0.0.0.0/0 on ports {port_desc}",
                            "group_name": group_name,
                            "protocol": protocol or "all",
                        }
                    )
    return findings


def audit_iam_users_mfa() -> List[Dict[str, str]]:
    """List IAM users who do not have an MFA device configured.

    MFA adds an additional layer of security for IAM users. This audit flags
    users who do not have any MFA devices associated with their account.
    """
    findings: List[Dict[str, str]] = []
    iam = boto3.client("iam")
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            username = user.get("UserName")
            if not username:
                continue
            mfa_devices = iam.list_mfa_devices(UserName=username)
            if len(mfa_devices.get("MFADevices", [])) == 0:
                findings.append(
                    {
                        "resource_type": "IAM User",
                        "resource_id": username,
                        "issue": "User does not have MFA enabled",
                    }
                )
    return findings


def write_csv(findings: List[Dict[str, str]], output_path: str) -> None:
    """Write findings to a CSV file."""
    if not findings:
        # Ensure we still create an empty file with headers if there are no findings
        keys = []
        with open(output_path, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=keys)
            writer.writeheader()
        return
    keys = sorted({key for finding in findings for key in finding.keys()})
    with open(output_path, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=keys)
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding)


def write_json(findings: List[Dict[str, str]], output_path: str) -> None:
    """Write findings to a JSON file."""
    with open(output_path, "w") as f:
        json.dump(findings, f, indent=2)


def write_html(findings: List[Dict[str, str]], output_path: str) -> None:
    """Write findings to a simple HTML table."""
    keys = sorted({key for finding in findings for key in finding.keys()})
    html_parts: List[str] = []
    html_parts.append("<html><head><title>Cloud Security Auditor Report</title>")
    html_parts.append(
        "<style>table { border-collapse: collapse; width: 100%; }"
        "th, td { border: 1px solid #ddd; padding: 8px; }"
        "th { background-color: #f2f2f2; }</style>"
    )
    html_parts.append("</head><body>")
    html_parts.append("<h1>Cloud Security Auditor Findings</h1>")
    html_parts.append("<table><thead><tr>")
    for key in keys:
        html_parts.append(f"<th>{key}</th>")
    html_parts.append("</tr></thead><tbody>")
    for finding in findings:
        html_parts.append("<tr>")
        for key in keys:
            value = finding.get(key, "")
            html_parts.append(f"<td>{value}</td>")
        html_parts.append("</tr>")
    html_parts.append("</tbody></table>")
    html_parts.append("</body></html>")
    with open(output_path, "w") as f:
        f.write("".join(html_parts))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit AWS for common security misconfigurations."
    )
    parser.add_argument(
        "--formats",
        nargs="+",
        default=["csv"],
        help="Output formats: choose from csv, json, html. Specify multiple to generate all.",
    )
    parser.add_argument(
        "--output-prefix",
        default="findings",
        help="Filename prefix for output (default: findings). Extensions will be appended.",
    )
    args = parser.parse_args()

    # Collect findings from all audits
    findings: List[Dict[str, str]] = []
    findings.extend(audit_s3_public())
    findings.extend(audit_security_groups())
    findings.extend(audit_iam_users_mfa())

    # Generate requested output formats
    for fmt in args.formats:
        fmt_lower = fmt.lower()
        out_path = f"{args.output_prefix}.{fmt_lower}"
        if fmt_lower == "csv":
            write_csv(findings, out_path)
        elif fmt_lower == "json":
            write_json(findings, out_path)
        elif fmt_lower == "html":
            write_html(findings, out_path)
        else:
            raise ValueError(f"Unsupported format: {fmt}")

    print(f"Audit complete. Generated {len(findings)} findings.")


if __name__ == "__main__":
    main()
