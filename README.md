# Cloud Security Auditor

Cloud Security Auditor is a lightweight auditing tool that checks your AWS account for
common security misconfigurations. It uses the [`boto3`](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) AWS SDK for Python to inspect
your resources and produces human -․ and machine‑readable reports.

## Features

- **Public S3 buckets** – Detects buckets whose access control lists grant access to
  `AllUsers` or `AuthenticatedUsers`, which usually means anyone on the internet
  can read or write your data.
- **Overly permissive security groups** – Flags inbound rules on EC2 security
  groups that allow traffic from `0.0.0.0/0`, i.e. the entire internet.
- **IAM users without MFA** – Lists IAM user accounts that do not have a
  Multi‑Factor Authentication device configured.

## Requirements

- Python 3.7 or later
- [`boto3`](https://pypi.org/project/boto3/) (install with `pip install boto3`)
- AWS credentials configured (via environment variables, `~/.aws/credentials`, or
  an IAM role on the host where the script runs)

## Usage

Clone or download this repository, then run the auditor script. You can specify
one or more output formats using the `--formats` flag. The supported formats
are `csv`, `json`, and `html`.

````bash
python auditor.py --formats csv json html --output-prefix findings
````

The example above generates three files in the current working directory:

- `findings.csv` – a comma‑separated values report
- `findings.json` – a structured JSON report
- `findings.html` – a simple HTML table that you can open in a browser

If you only need one format, pass a single value to `--formats`.

### Example

To produce only a CSV report named `audit_report.csv`:

````bash
python auditor.py --formats csv --output-prefix audit_report
````

## Docs

The `docs/` directory contains a placeholder file for your architecture diagram or
other visuals. Replace it with your own diagrams to document how this tool
integrates into your environment.

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE) for
details.
