# AWS IAM Policy Analyzer

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A security analysis tool for AWS IAM roles that identifies overprivileged permissions, security risks, and provides recommendations for implementing least privilege access.

## Features

### Security Analysis
- **Policy Analysis**: Inspection of inline and managed policies
- **Trust Relationship Analysis**: Evaluation of role assumption permissions
- **Permission Simulation**: Test specific actions against resources
- **CloudTrail Integration**: Usage-based analysis of actual permissions
- **Severity Scoring**: Risk assessment with numerical scoring

### Risk Detection
- **Overprivilege Detection**: Identifies wildcard permissions and excessive access
- **Privilege Escalation**: Detects permissions that could lead to privilege escalation
- **Cross-Account Access**: Flags risky cross-account trust relationships
- **Risky Actions**: Highlights dangerous permissions (IAM:*, S3:*, EC2:*, etc.)
- **Wildcard Analysis**: Distinguishes between legitimate and problematic wildcard usage

### Recommendations
- **Least Privilege Suggestions**: Recommendations for policy optimization
- **Usage-Based Analysis**: CloudTrail integration to identify unused permissions
- **Priority-Based Remediation**: Categorized recommendations by severity
- **Best Practice Guidance**: Security recommendations

### Reporting
- **Human-Readable Reports**: Detailed analysis reports
- **JSON Export**: Structured data for integration
- **Severity Metrics**: Quantified risk assessment
- **Usage Statistics**: CloudTrail-based utilization metrics

## Installation

### Prerequisites

```bash
pip install boto3

# AWS credentials must be configured via:
# - AWS CLI: aws configure
# - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
# - IAM roles (for EC2/Lambda execution)
# - AWS SSO profiles
```

### Setup

```bash
git clone https://github.com/yourusername/aws-iam-analyzer.git
cd aws-iam-analyzer
chmod +x iam_analyzer.py
```

## Usage

### Basic Commands

```bash
# Security assessment
python iam_analyzer.py --role MyRole --detect-overprivilege

# Full analysis with recommendations
python iam_analyzer.py --role MyRole --unused --least-privilege-suggestions

# Test specific permissions
python iam_analyzer.py --role MyRole --actions s3:GetObject --resource "arn:aws:s3:::bucket/*"
```

### Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--role` | IAM role name to analyze (required) | `--role MyRole` |
| `--actions` | Actions to simulate permissions for | `--actions s3:GetObject ec2:DescribeInstances` |
| `--resource` | Resources for permission simulation | `--resource "arn:aws:s3:::bucket/*"` |
| `--detect-overprivilege` | Enable overprivilege detection | `--detect-overprivilege` |
| `--unused` | Analyze CloudTrail for unused permissions | `--unused` |
| `--usage-days` | Days of CloudTrail history to analyze (1-90) | `--usage-days 60` |
| `--least-privilege-suggestions` | Generate optimization recommendations | `--least-privilege-suggestions` |
| `--export` | Export results to JSON file | `--export results.json` |
| `--json` | Output in JSON format | `--json` |
| `--profile` | AWS profile to use | `--profile production` |
| `--region` | AWS region | `--region us-west-2` |

### Example Workflows

#### Security Audit
```bash
# Basic assessment
python iam_analyzer.py --role ProductionRole --detect-overprivilege

# Comprehensive analysis
python iam_analyzer.py --role ProductionRole --unused --least-privilege-suggestions --usage-days 90

# Export for reporting
python iam_analyzer.py --role ProductionRole --detect-overprivilege --export audit.json
```

#### Permission Testing
```bash
# Test S3 permissions
python iam_analyzer.py --role DataRole \
  --actions s3:GetObject s3:PutObject \
  --resource "arn:aws:s3:::data-bucket/*"

# Test EC2 permissions
python iam_analyzer.py --role AutoScalingRole \
  --actions ec2:RunInstances ec2:TerminateInstances \
  --resource "*"
```

## Understanding Output

### Risk Levels

| Level | Severity Score | Description |
|-------|----------------|-------------|
| **CRITICAL** | 20+ | Immediate attention required |
| **HIGH** | 10-19 | Significant security risks |
| **MEDIUM** | 5-9 | Moderate security concerns |
| **INFO** | 1-4 | Best practice recommendations |

### Report Sections

**Trust Relationships**
- Wildcard trusts that allow assumption by any principal
- Cross-account trusts with external accounts
- Service trusts for AWS services

**Policy Analysis**
- Overprivileged statements with excessive permissions
- Risky permissions that could compromise security
- Privilege escalation opportunities
- Wildcard usage analysis

**CloudTrail Usage**
- Actually used permissions based on logs
- Unused permissions that could be removed
- Permission errors indicating access issues

**Recommendations**
- Priority-based suggestions for improvement
- Specific actions to implement least privilege
- Best practice guidance

## Advanced Usage

### Multi-Account Analysis
```bash
# Different AWS profile
python iam_analyzer.py --role MyRole --profile prod-account

# Different region
python iam_analyzer.py --role MyRole --region eu-west-1
```

### CI/CD Integration
```bash
#!/bin/bash
ROLE_NAME="DeploymentRole"

python iam_analyzer.py --role $ROLE_NAME --detect-overprivilege --json > analysis.json
EXIT_CODE=$?

if [ $EXIT_CODE -eq 2 ]; then
    echo "CRITICAL security issues found"
    exit 1
elif [ $EXIT_CODE -eq 1 ]; then
    echo "WARNING: Security issues found"
fi
```

## Required Permissions

The tool requires these IAM permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetRole",
                "iam:ListAttachedRolePolicies",
                "iam:ListRolePolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetRolePolicy",
                "iam:SimulatePrincipalPolicy",
                "sts:GetCallerIdentity",
                "cloudtrail:LookupEvents"
            ],
            "Resource": "*"
        }
    ]
}
```

### CloudTrail Requirements
- CloudTrail must be enabled
- Events logged for the analysis period
- `cloudtrail:LookupEvents` permission required

## Exit Codes

- `0`: No major security issues
- `1`: Warning-level issues found
- `2`: Critical issues requiring immediate attention

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Submit a pull request

### Development Setup
```bash
git clone https://github.com/yourusername/aws-iam-analyzer.git
cd aws-iam-analyzer
pip install -r requirements-dev.txt
python -m pytest tests/
```

## Contribution
- Kudos to you on reading the documentatio, lets connect if you got any ideas for the project 
## Limitations

- Requires CloudTrail for usage analysis
- Analysis limited to single role per execution
- CloudTrail history limited to 90 days
- May not detect all privilege escalation paths

---

**Disclaimer**: This tool is for security analysis. Test in non-production environments first.
