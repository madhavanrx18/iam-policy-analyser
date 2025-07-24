import argparse
import json
import sys
import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from botocore.exceptions import ClientError, BotoCoreError
import re
from collections import defaultdict


class Colors:
    # colour codes
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


class IAMAnalyzer:

    
    def __init__(self, profile: Optional[str] = None, region: str = 'us-east-1'):
        """Initialize the analyzer with AWS session"""
        try:
            if profile:
                self.session = boto3.Session(profile_name=profile)
            else:
                self.session = boto3.Session()
            
            self.iam_client = self.session.client('iam')
            self.sts_client = self.session.client('sts')
            self.cloudtrail_client = self.session.client('cloudtrail', region_name=region)
            
            # over-privilege
            self.risky_actions = {
                'iam:*', 'iam:PassRole', 'sts:AssumeRole', 'kms:*', 'kms:Decrypt',
                'ec2:*', 's3:*', 'lambda:*', 'dynamodb:*', 'rds:*',
                'secretsmanager:*', 'ssm:*', 'logs:*'
            }
            
            # slightly less over privileged
            self.privilege_escalation_actions = {
                'iam:CreateRole', 'iam:AttachRolePolicy', 'iam:PutRolePolicy',
                'iam:CreateUser', 'iam:AttachUserPolicy', 'iam:PutUserPolicy',
                'iam:CreateAccessKey', 'sts:AssumeRole', 'iam:PassRole'
            }
            
        except Exception as e:
            print(f"{Colors.RED}Error initializing AWS session: {e}{Colors.RESET}")
            sys.exit(1)

    def get_role_info(self, role_name: str) -> Dict[str, Any]:
        
        # role info
        try:
            #role details
            role_response = self.iam_client.get_role(RoleName=role_name)
            role = role_response['Role']
            
            # attached managed policies
            attached_policies = self.iam_client.list_attached_role_policies(RoleName=role_name)
            
            # inline policies
            inline_policies = self.iam_client.list_role_policies(RoleName=role_name)
            
            return {
                'role': role,
                'attached_policies': attached_policies['AttachedPolicies'],
                'inline_policies': inline_policies['PolicyNames']
            }
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                raise ValueError(f"Role '{role_name}' not found")
            else:
                raise Exception(f"Error fetching role info: {e}")

    def get_policy_document(self, policy_arn: str = None, policy_name: str = None, 
                           role_name: str = None) -> Dict[str, Any]:

        # fetch policy document for managed and inline
        try:
            if policy_arn:
                # Managed policy
                policy = self.iam_client.get_policy(PolicyArn=policy_arn)
                version = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy['Policy']['DefaultVersionId']
                )
                return version['PolicyVersion']['Document']
            elif policy_name and role_name:
                # Inline policy
                policy = self.iam_client.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                return policy['PolicyDocument']
        except ClientError as e:
            print(f"{Colors.YELLOW}Warning: Could not fetch policy document: {e}{Colors.RESET}")
            return {}

    def simulate_permissions(self, role_arn: str, actions: List[str], 
                           resources: List[str]) -> List[Dict[str, Any]]:
        # real work starts
        # simulate policy action using api

        try:
            results = []
            # batch request
            for i in range(0, len(actions), 50): 
                batch_actions = actions[i:i+50]
                response = self.iam_client.simulate_principal_policy(
                    PolicySourceArn=role_arn,
                    ActionNames=batch_actions,
                    ResourceArns=resources
                )
                results.extend(response['EvaluationResults'])
            
            return results
        except ClientError as e:
            print(f"{Colors.RED}Error simulating permissions: {e}{Colors.RESET}")
            return []

    def analyze_policy_document(self, policy_doc: Dict[str, Any], 
                              policy_name: str) -> Dict[str, Any]:
        
        # analysis of policy document

        analysis = {
            'policy_name': policy_name,
            'overprivileged_statements': [],
            'risky_permissions': [],
            'privilege_escalation_risk': False,
            'wildcard_usage': [],
            'cross_account_access': []
        }
        
        statements = policy_doc.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for i, statement in enumerate(statements):
            effect = statement.get('Effect', 'Allow')
            actions = statement.get('Action', [])
            resources = statement.get('Resource', [])
            principals = statement.get('Principal', {})
            
            
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            
            # wildcard is hazardous to cloud

            if '*' in actions or any('*' in action for action in actions):
                analysis['wildcard_usage'].append({
                    'statement_index': i,
                    'type': 'action',
                    'values': actions
                })
            
            if '*' in resources or any('*' in resource for resource in resources):
                analysis['wildcard_usage'].append({
                    'statement_index': i,
                    'type': 'resource',
                    'values': resources
                })
            
            # over-privilege statement

            if effect == 'Allow':
            
                if '*' in actions or any(action == '*' for action in actions):
                    analysis['overprivileged_statements'].append({
                        'statement_index': i,
                        'reason': 'Allows all actions (*)',
                        'actions': actions,
                        'resources': resources
                    })
                
                # risky actions
                for action in actions:
                    if any(re.match(risky.replace('*', '.*'), action) for risky in self.risky_actions):
                        analysis['risky_permissions'].append({
                            'statement_index': i,
                            'action': action,
                            'resources': resources
                        })
                    
                    
                    if action in self.privilege_escalation_actions:
                        analysis['privilege_escalation_risk'] = True
            
            # cross account access
            
            if principals:
                if isinstance(principals, dict):
                    aws_principals = principals.get('AWS', [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    
                    for principal in aws_principals:
                        if ':' in principal and 'arn:aws:iam::' in principal:
                            account_id = principal.split(':')[4]
                            current_account = self.sts_client.get_caller_identity()['Account']
                            if account_id != current_account:
                                analysis['cross_account_access'].append({
                                    'statement_index': i,
                                    'principal': principal,
                                    'account_id': account_id
                                })
        
        return analysis

   
    def analyze_trust_relationships(self, role_info: Dict[str, Any]) -> Dict[str, Any]:
        
        trust_policy = role_info['role']['AssumeRolePolicyDocument']
        
        analysis = {
            'trusted_entities': [],
            'cross_account_trusts': [],
            'service_trusts': [],
            'wildcard_trusts': [],
            'potential_risks': []
        }
        
        statements = trust_policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') == 'Allow' and 'Principal' in statement:
                principal = statement['Principal']
                
                if isinstance(principal, str) and principal == '*':
                    analysis['wildcard_trusts'].append({
                        'statement': statement,
                        'risk_level': 'HIGH',
                        'description': 'Role can be assumed by any principal'
                    })
                
                elif isinstance(principal, dict):
                    # user account as principal
                    aws_principals = principal.get('AWS', [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    
                    for aws_principal in aws_principals:
                        if aws_principal == '*':
                            analysis['wildcard_trusts'].append({
                                'principal': aws_principal,
                                'risk_level': 'HIGH'
                            })
                        elif ':root' in aws_principal:
                            account_id = aws_principal.split(':')[4]
                            current_account = self.sts_client.get_caller_identity()['Account']
                            if account_id != current_account:
                                analysis['cross_account_trusts'].append({
                                    'account_id': account_id,
                                    'principal': aws_principal
                                })
                        
                        analysis['trusted_entities'].append(aws_principal)
                    
                    # service account as principal

                    service_principals = principal.get('Service', [])
                    if isinstance(service_principals, str):
                        service_principals = [service_principals]
                    
                    for service_principal in service_principals:
                        analysis['service_trusts'].append(service_principal)
                        analysis['trusted_entities'].append(service_principal)
        
        return analysis

    
    def print_analysis_report(self, analysis_results: Dict[str, Any], 
                            human_readable: bool = True):
        
        if not human_readable:
            print(json.dumps(analysis_results, indent=2, default=str))
            return
        
        role_name = analysis_results.get('role_name', 'Unknown')
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}AWS IAM POLICY ANALYSIS REPORT{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}Role:{Colors.RESET} {role_name}")
        print(f"{Colors.BOLD}Analysis Date:{Colors.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.BOLD}Account:{Colors.RESET} {analysis_results.get('account_id', 'Unknown')}")
        
        # Trust Relationships
        trust_analysis = analysis_results.get('trust_analysis', {})
        print(f"\n{Colors.BOLD}{Colors.CYAN}TRUST RELATIONSHIPS{Colors.RESET}")
        print("-" * 40)
        
        if trust_analysis.get('wildcard_trusts'):
            print(f"{Colors.RED}HIGH RISK: Wildcard trust relationships found{Colors.RESET}")
            for trust in trust_analysis['wildcard_trusts']:
                print(f"  - {trust}")
        
        if trust_analysis.get('cross_account_trusts'):
            print(f"{Colors.YELLOW}WARNING: Cross-account trusts:{Colors.RESET}")
            for trust in trust_analysis['cross_account_trusts']:
                print(f"  - Account: {trust['account_id']}")
        
        if trust_analysis.get('service_trusts'):
            print(f"{Colors.GREEN}INFO: Service trusts:{Colors.RESET}")
            for service in trust_analysis['service_trusts']:
                print(f"  - {service}")
        
        # Policy Analysis
        policy_analyses = analysis_results.get('policy_analysis', [])
        print(f"\n{Colors.BOLD}{Colors.CYAN}POLICY ANALYSIS{Colors.RESET}")
        print("-" * 40)
        
        total_risks = 0
        for policy_analysis in policy_analyses:
            policy_name = policy_analysis['policy_name']
            print(f"\n{Colors.BOLD}Policy: {policy_name}{Colors.RESET}")
            
            if policy_analysis['overprivileged_statements']:
                print(f"{Colors.RED}HIGH RISK: Overprivileged statements: {len(policy_analysis['overprivileged_statements'])}{Colors.RESET}")
                total_risks += len(policy_analysis['overprivileged_statements'])
            
            if policy_analysis['risky_permissions']:
                print(f"{Colors.YELLOW}WARNING: Risky permissions: {len(policy_analysis['risky_permissions'])}{Colors.RESET}")
                total_risks += len(policy_analysis['risky_permissions'])
            
            if policy_analysis['privilege_escalation_risk']:
                print(f"{Colors.RED}HIGH RISK: Privilege escalation risk detected{Colors.RESET}")
                total_risks += 1
            
            if policy_analysis['wildcard_usage']:
                print(f"{Colors.YELLOW}WARNING: Wildcard usage: {len(policy_analysis['wildcard_usage'])} instances{Colors.RESET}")
                total_risks += len(policy_analysis['wildcard_usage'])
        
        # Permission Simulation Results
        simulation_results = analysis_results.get('simulation_results', [])
        if simulation_results:
            print(f"\n{Colors.BOLD}{Colors.CYAN}PERMISSION SIMULATION{Colors.RESET}")
            print("-" * 40)
            
            allowed_count = sum(1 for result in simulation_results if result.get('EvalDecision') == 'allowed')
            denied_count = len(simulation_results) - allowed_count
            
            print(f"{Colors.GREEN}ALLOWED: {allowed_count} actions{Colors.RESET}")
            print(f"{Colors.RED}DENIED: {denied_count} actions{Colors.RESET}")
        
        # CloudTrail Analysis
        cloudtrail_analysis = analysis_results.get('cloudtrail_analysis', {})
        if 'used_actions' in cloudtrail_analysis:
            print(f"\n{Colors.BOLD}{Colors.CYAN}USAGE ANALYSIS (CloudTrail){Colors.RESET}")
            print("-" * 40)
            print(f"Analysis period: {cloudtrail_analysis['analysis_period_days']} days")
            print(f"Total events: {cloudtrail_analysis['total_events']}")
            print(f"Unique actions used: {len(cloudtrail_analysis['used_actions'])}")
        
        # Suggestions
        suggestions = analysis_results.get('suggestions', [])
        if suggestions:
            print(f"\n{Colors.BOLD}{Colors.CYAN}RECOMMENDATIONS{Colors.RESET}")
            print("-" * 40)
            for i, suggestion in enumerate(suggestions, 1):
                print(f"{i}. {suggestion}")
        
        # Summary
        print(f"\n{Colors.BOLD}{Colors.CYAN}SECURITY SUMMARY{Colors.RESET}")
        print("-" * 40)
        if total_risks == 0:
            print(f"{Colors.GREEN}SECURE: No major security risks detected{Colors.RESET}")
        elif total_risks <= 3:
            print(f"{Colors.YELLOW}MODERATE: {total_risks} potential security issues found{Colors.RESET}")
        else:
            print(f"{Colors.RED}HIGH RISK: {total_risks} security risks detected - Review required{Colors.RESET}")

    def run_analysis(self, role_name: str, actions: List[str] = None, 
                    resources: List[str] = None, detect_overprivilege: bool = False,
                    analyze_usage: bool = False, usage_days: int = 30) -> Dict[str, Any]:
        """Run comprehensive IAM role analysis"""
        
        print(f"{Colors.CYAN}Analyzing IAM role: {role_name}{Colors.RESET}")
        
        try:
            # Get role information
            role_info = self.get_role_info(role_name)
            role_arn = role_info['role']['Arn']
            
            # Get current account ID
            account_id = self.sts_client.get_caller_identity()['Account']
            
            analysis_results = {
                'role_name': role_name,
                'role_arn': role_arn,
                'account_id': account_id,
                'analysis_timestamp': datetime.now().isoformat(),
                'trust_analysis': {},
                'policy_analysis': [],
                'simulation_results': [],
                'cloudtrail_analysis': {},
                'suggestions': []
            }
            
            # Analyze trust relationships
            print(f"{Colors.CYAN}  -> Analyzing trust relationships...{Colors.RESET}")
            analysis_results['trust_analysis'] = self.analyze_trust_relationships(role_info)
            
            # Analyze policies
            print(f"{Colors.CYAN}  -> Analyzing attached policies...{Colors.RESET}")
            
            # Analyze managed policies
            for policy in role_info['attached_policies']:
                policy_doc = self.get_policy_document(policy_arn=policy['PolicyArn'])
                policy_analysis = self.analyze_policy_document(policy_doc, policy['PolicyName'])
                analysis_results['policy_analysis'].append(policy_analysis)
            
            # Analyze inline policies
            for policy_name in role_info['inline_policies']:
                policy_doc = self.get_policy_document(policy_name=policy_name, role_name=role_name)
                policy_analysis = self.analyze_policy_document(policy_doc, policy_name)
                analysis_results['policy_analysis'].append(policy_analysis)
            
            # Simulate permissions if requested
            if actions and resources:
                print(f"{Colors.CYAN}  -> Simulating permissions...{Colors.RESET}")
                simulation_results = self.simulate_permissions(role_arn, actions, resources)
                analysis_results['simulation_results'] = simulation_results
            
                        
            # Add general security suggestions
            total_policies = len(role_info['attached_policies']) + len(role_info['inline_policies'])
            if total_policies > 10:
                analysis_results['suggestions'].append(f"Consider consolidating {total_policies} policies for better management")
            
            return analysis_results
            
        except Exception as e:
            print(f"{Colors.RED}Error during analysis: {e}{Colors.RESET}")
            return {'error': str(e)}


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="AWS IAM Policy Analyzer - Analyze and verify IAM role permissions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --role DeveloperRole --detect-overprivilege
  %(prog)s --role DataPipelineRole --actions s3:GetObject s3:PutObject --resource arn:aws:s3:::my-bucket/*
  %(prog)s --role AdminRole --unused --least-privilege-suggestions --export analysis.json
        """
    )
    
    parser.add_argument('--role', required=True, help='IAM role name to analyze')
    parser.add_argument('--actions', nargs='+', help='Actions to simulate (space-separated)')
    parser.add_argument('--resource', '--resources', nargs='+', 
                       help='Resources for permission simulation (space-separated)')
    parser.add_argument('--detect-overprivilege', action='store_true',
                       help='Detect overprivileged statements and risky permissions')
    parser.add_argument('--unused', action='store_true',
                       help='Analyze CloudTrail logs to detect unused permissions')
    parser.add_argument('--usage-days', type=int, default=30,
                       help='Number of days to analyze CloudTrail logs (default: 30)')
    parser.add_argument('--least-privilege-suggestions', action='store_true',
                       help='Generate least-privilege policy suggestions')
    parser.add_argument('--export', help='Export results to JSON file')
    parser.add_argument('--json', action='store_true',
                       help='Output results in JSON format')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--region', default='us-east-1', help='AWS region (default: us-east-1)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.actions and not args.resource:
        print(f"{Colors.RED}Error: --resource is required when using --actions{Colors.RESET}")
        sys.exit(1)
    
    # Initialize analyzer
    analyzer = IAMAnalyzer(profile=args.profile, region=args.region)
    
    # Run analysis
    analysis_results = analyzer.run_analysis(
        role_name=args.role,
        actions=args.actions,
        resources=args.resource,
        detect_overprivilege=args.detect_overprivilege,
        analyze_usage=args.unused or args.least_privilege_suggestions,
        usage_days=args.usage_days
    )
    
    # Handle errors
    if 'error' in analysis_results:
        print(f"{Colors.RED}Analysis failed: {analysis_results['error']}{Colors.RESET}")
        sys.exit(1)
    
    # Export results if requested
    if args.export:
        try:
            with open(args.export, 'w') as f:
                json.dump(analysis_results, f, indent=2, default=str)
            print(f"{Colors.GREEN}Results exported to: {args.export}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}Error exporting results: {e}{Colors.RESET}")
    
    # Print results
    analyzer.print_analysis_report(analysis_results, human_readable=not args.json)


if __name__ == '__main__':
    main()