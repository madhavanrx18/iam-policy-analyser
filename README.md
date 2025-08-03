# AWS IAM Policy Analyzer

A command-line tool to analyze AWS IAM roles and their attached policies for security risks, overprivilege, and misconfigurations.


## Features

* **Role Inspection**
  Retrieve attached and inline IAM policies for any IAM role.

* **Policy Risk Analysis**
  Detect:

  * Overprivileged permissions (e.g., `*`)
  * Risky actions (e.g., `iam:PassRole`, `kms:*`)
  * Privilege escalation vectors
  * Wildcard usage in actions/resources

* **Trust Relationship Analysis**
  Identify:

  * Cross-account trust
  * Wildcard principals
  * Service trust configurations

* **Permission Simulation**
  Uses IAM’s policy simulator API to test if specific actions on resources are permitted.

* **Optional CloudTrail Usage Analysis** *(future extension)*
  Incorporate recent usage data to identify unused permissions (least privilege).

* **Exportable Results**
  Outputs in human-readable or JSON format. Can be saved to disk.



## Getting Started

### Requirements

* Python 3.7+
* AWS credentials with IAM read permissions
* boto3 (`pip install boto3`)



## Usage

```bash
python iam_analyzer.py --role <RoleName> [options]
```

### Options

| Option                          | Description                                                     |
| ------------------------------- | --------------------------------------------------------------- |
| `--role`                        | (Required) IAM Role name to analyze                             |
| `--actions`                     | Space-separated list of actions to simulate                     |
| `--resource` / `--resources`    | Space-separated list of resources to simulate                   |
| `--detect-overprivilege`        | Analyze for overprivileged permissions                          |
| `--unused`                      | Analyze unused permissions using CloudTrail logs (if available) |
| `--usage-days`                  | Number of days to fetch CloudTrail logs (default: 30)           |
| `--least-privilege-suggestions` | Provide least-privilege suggestions (optional)                  |
| `--export <file>`               | Export results to a JSON file                                   |
| `--json`                        | Output results in raw JSON                                      |
| `--profile`                     | Use a specific AWS CLI profile                                  |
| `--region`                      | AWS region to use (default: us-east-1)                          |

---

### Example Commands

```bash
# Analyze for overprivileged policies
python iam_analyzer.py --role DeveloperRole --detect-overprivilege

# Simulate permission for specific S3 actions
python iam_analyzer.py --role DataPipelineRole \
  --actions s3:GetObject s3:PutObject \
  --resource arn:aws:s3:::my-bucket/*

# Export analysis to JSON
python iam_analyzer.py --role AuditRole --json --export results.json
```



## Tech Stack & Design Rationale

| Component            | Purpose                                                       |
| -------------------- | ------------------------------------------------------------- |
| Python               | Chosen for its scripting speed and support for AWS automation |
| boto3                | AWS SDK for accessing IAM, STS, and CloudTrail                |
| argparse             | CLI interface without external dependencies                   |
| re, datetime, typing | Built-in modules for parsing and policy logic                 |
| sys, json            | Error handling and export functionality                       |

> Minimal dependencies keep the tool lightweight and easy to deploy.


## Contribution
- Kudos to you on reading the documentation, if you have any idea that would be apt for our project lets connect.
