import argparse
import json
import sys
import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from botocore.exceptions import ClientError, BotoCoreError
import fnmatch
from collections import defaultdict
import time


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
            
            # Cache account ID to avoid repeated API calls
            self.account_id = self.sts_client.get_caller_identity()['Account']
            
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
            
            # Legitimate wildcard patterns that are commonly acceptable
            self.legitimate_wildcard_patterns = {
                'arn:aws:s3:::*/\*',  # S3 object access
                'arn:aws:logs:*:*:log-group:*/log-stream:*',  # CloudWatch Logs
                'arn:aws:dynamodb:*:*:table/*/index/*',  # DynamoDB indexes
            }
            
        except Exception as e:
            print(f"{Colors.RED}Error initializing AWS session: {e}{Colors.RESET}")
            sys.exit(1)

    def get_role_info(self, role_name: str) -> Dict[str, Any]:
        """Get comprehensive role information"""
        try:
            # role details
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
        """Fetch policy document for managed and inline policies"""
        try:
            if policy_arn:
                # managed policy
                policy = self.iam_client.get_policy(PolicyArn=policy_arn)
                version = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy['Policy']['DefaultVersionId']
                )
                return version['PolicyVersion']['Document']
            elif policy_name and role_name:
                # inline policy
                policy = self.iam_client.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                return policy['PolicyDocument']
        except ClientError as e:
            print(f"{Colors.YELLOW}Warning: Could not fetch policy document: {e}{Colors.RESET}")
            return {}

    def validate_resources(self, resources: List[str]) -> bool:
        """Validate that resources are properly formatted ARNs"""
        arn_pattern = r'^arn:aws:[a-zA-Z0-9\-]+:[a-zA-Z0-9\-]*:\d*:[a-zA-Z0-9\-_/\*\.]+$|^\*$'
        import re
        
        for resource in resources:
            if not re.match(arn_pattern, resource):
                print(f"{Colors.YELLOW}Warning: Resource '{resource}' may not be a valid ARN{Colors.RESET}")
                return False
        return True

    def simulate_permissions(self, role_arn: str, actions: List[str], 
                           resources: List[str]) -> List[Dict[str, Any]]:
        """Simulate policy actions using AWS API with validation"""
        
        # Validate resources
        if not self.validate_resources(resources):
            print(f"{Colors.YELLOW}Warning: Some resources may not be valid ARNs{Colors.RESET}")
        
        try:
            results = []
            # batch request to avoid API limits
            for i in range(0, len(actions), 50): 
                batch_actions = actions[i:i+50]
                response = self.iam_client.simulate_principal_policy(
                    PolicySourceArn=role_arn,
                    ActionNames=batch_actions,
                    ResourceArns=resources
                )
                results.extend(response['EvaluationResults'])
                
                # Add small delay to avoid throttling
                if len(actions) > 50:
                    time.sleep(0.1)
            
            return results
        except ClientError as e:
            print(f"{Colors.RED}Error simulating permissions: {e}{Colors.RESET}")
            return []

    def is_legitimate_wildcard(self, resource: str) -> bool:
        # check if wildcard usage is legitimate
        for pattern in self.legitimate_wildcard_patterns:
            if fnmatch.fnmatch(resource, pattern):
                return True
        return False

    def analyze_policy_document(self, policy_doc: Dict[str, Any], 
                              policy_name: str) -> Dict[str, Any]:
        # analysis of policy document
        
        analysis = {
            'policy_name': policy_name,
            'overprivileged_statements': [],
            'risky_permissions': [],
            'privilege_escalation_risk': False,
            'wildcard_usage': [],
            'cross_account_access': [],
            'legitimate_wildcards': [],
            'severity_score': 0
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
            
            # analyze wildcard usage with legitimacy check
            action_wildcards = []
            for action in actions:
                if '*' in action:
                    action_wildcards.append(action)
            
            if action_wildcards:
                analysis['wildcard_usage'].append({
                    'statement_index': i,
                    'type': 'action',
                    'values': action_wildcards,
                    'severity': 'HIGH' if '*' in action_wildcards else 'MEDIUM'
                })
                analysis['severity_score'] += 3 if '*' in action_wildcards else 2
            
            resource_wildcards = []
            legitimate_resource_wildcards = []
            for resource in resources:
                if '*' in resource:
                    if self.is_legitimate_wildcard(resource):
                        legitimate_resource_wildcards.append(resource)
                    else:
                        resource_wildcards.append(resource)
            
            if resource_wildcards:
                analysis['wildcard_usage'].append({
                    'statement_index': i,
                    'type': 'resource',
                    'values': resource_wildcards,
                    'severity': 'HIGH' if '*' in resource_wildcards else 'MEDIUM'
                })
                analysis['severity_score'] += 2
            
            if legitimate_resource_wildcards:
                analysis['legitimate_wildcards'].append({
                    'statement_index': i,
                    'type': 'resource',
                    'values': legitimate_resource_wildcards
                })
            
            # analyze over-privileged statements
            if effect == 'Allow':
                if '*' in actions or any(action == '*' for action in actions):
                    analysis['overprivileged_statements'].append({
                        'statement_index': i,
                        'reason': 'Allows all actions (*)',
                        'actions': actions,
                        'resources': resources,
                        'severity': 'CRITICAL'
                    })
                    analysis['severity_score'] += 5
                
                # check risky actions using fnmatch for proper wildcard matching
                for action in actions:
                    for risky_pattern in self.risky_actions:
                        if fnmatch.fnmatch(action, risky_pattern):
                            analysis['risky_permissions'].append({
                                'statement_index': i,
                                'action': action,
                                'pattern_matched': risky_pattern,
                                'resources': resources,
                                'severity': 'HIGH'
                            })
                            analysis['severity_score'] += 2
                            break
                    
                    # check privilege escalation risk
                    if action in self.privilege_escalation_actions:
                        analysis['privilege_escalation_risk'] = True
                        analysis['severity_score'] += 3
            
            # analyze cross-account access
            if principals:
                if isinstance(principals, dict):
                    aws_principals = principals.get('AWS', [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    
                    for principal in aws_principals:
                        if ':' in principal and 'arn:aws:iam::' in principal:
                            account_id = principal.split(':')[4]
                            if account_id != self.account_id:
                                analysis['cross_account_access'].append({
                                    'statement_index': i,
                                    'principal': principal,
                                    'account_id': account_id,
                                    'severity': 'MEDIUM'
                                })
                                analysis['severity_score'] += 1
        
        return analysis

    def analyze_trust_relationships(self, role_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze trust relationships with the cached account ID"""
        
        trust_policy = role_info['role']['AssumeRolePolicyDocument']
        
        analysis = {
            'trusted_entities': [],
            'cross_account_trusts': [],
            'service_trusts': [],
            'wildcard_trusts': [],
            'potential_risks': [],
            'severity_score': 0
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
                        'risk_level': 'CRITICAL',
                        'description': 'Role can be assumed by any principal'
                    })
                    analysis['severity_score'] += 5
                
                elif isinstance(principal, dict):
                    # AWS account principals
                    aws_principals = principal.get('AWS', [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    
                    for aws_principal in aws_principals:
                        if aws_principal == '*':
                            analysis['wildcard_trusts'].append({
                                'principal': aws_principal,
                                'risk_level': 'CRITICAL',
                                'description': 'Wildcard AWS principal trust'
                            })
                            analysis['severity_score'] += 5
                        elif ':root' in aws_principal:
                            account_id = aws_principal.split(':')[4]
                            if account_id != self.account_id:
                                analysis['cross_account_trusts'].append({
                                    'account_id': account_id,
                                    'principal': aws_principal,
                                    'risk_level': 'MEDIUM'
                                })
                                analysis['severity_score'] += 2
                        
                        analysis['trusted_entities'].append(aws_principal)
                    
                    # Service principals
                    service_principals = principal.get('Service', [])
                    if isinstance(service_principals, str):
                        service_principals = [service_principals]
                    
                    for service_principal in service_principals:
                        analysis['service_trusts'].append(service_principal)
                        analysis['trusted_entities'].append(service_principal)
        
        return analysis

    def analyze_cloudtrail_usage(self, role_arn: str, days: int = 30) -> Dict[str, Any]:
        # Analyze CloudTrail logs to identify unused permissions
        
        print(f"{Colors.CYAN}  -> Analyzing CloudTrail usage for last {days} days...{Colors.RESET}")
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days)
        
        analysis = {
            'analysis_period_days': days,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'total_events': 0,
            'used_actions': set(),
            'error_events': [],
            'most_common_actions': {},
            'resources_accessed': set()
        }
        
        try:
            paginator = self.cloudtrail_client.get_paginator('lookup_events')
            
            # Look for events where this role was the user identity
            page_iterator = paginator.paginate(
                LookupAttributes=[
                    {
                        'AttributeKey': 'Username',
                        'AttributeValue': role_arn.split('/')[-1]  # Extract role name from ARN
                    }
                ],
                StartTime=start_time,
                EndTime=end_time
            )
            
            action_counts = defaultdict(int)
            
            for page in page_iterator:
                events = page.get('Events', [])
                analysis['total_events'] += len(events)
                
                for event in events:
                    event_name = event.get('EventName', '')
                    if event_name:
                        analysis['used_actions'].add(event_name)
                        action_counts[event_name] += 1
                    
                    # track error events
                    if event.get('ErrorCode'):
                        analysis['error_events'].append({
                            'event_name': event_name,
                            'error_code': event.get('ErrorCode'),
                            'error_message': event.get('ErrorMessage', ''),
                            'event_time': event.get('EventTime', '').isoformat() if event.get('EventTime') else ''
                        })
                    
                    # extract resources accessed
                    resources = event.get('Resources', [])
                    for resource in resources:
                        resource_name = resource.get('ResourceName', '')
                        if resource_name:
                            analysis['resources_accessed'].add(resource_name)
            
            
            analysis['used_actions'] = list(analysis['used_actions'])
            analysis['resources_accessed'] = list(analysis['resources_accessed'])
            
            
            analysis['most_common_actions'] = dict(
                sorted(action_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            )
            
            print(f"{Colors.GREEN}  -> Found {analysis['total_events']} events with {len(analysis['used_actions'])} unique actions{Colors.RESET}")
            
        except ClientError as e:
            error_msg = f"CloudTrail analysis failed: {e}"
            print(f"{Colors.RED}  -> {error_msg}{Colors.RESET}")
            analysis['error'] = error_msg
        
        return analysis

    def generate_least_privilege_suggestions(self, policy_analysis: List[Dict[str, Any]], 
                                           cloudtrail_analysis: Dict[str, Any] = None) -> List[str]:

        
        suggestions = []
        
        # analyze current policies
        total_risky_permissions = 0
        total_wildcards = 0
        has_admin_access = False
        
        for policy in policy_analysis:
            total_risky_permissions += len(policy.get('risky_permissions', []))
            total_wildcards += len(policy.get('wildcard_usage', []))
            
            # check for admin-level access
            for stmt in policy.get('overprivileged_statements', []):
                if '*' in stmt.get('actions', []):
                    has_admin_access = True
        
        # generate suggestions based on analysis
        if has_admin_access:
            suggestions.append("CRITICAL: Remove wildcard (*) actions. Create specific policies for required services only.")
        
        if total_risky_permissions > 0:
            suggestions.append(f"HIGH: Found {total_risky_permissions} risky permissions. Review and scope down to specific resources.")
        
        if total_wildcards > 5:
            suggestions.append(f"MEDIUM: {total_wildcards} wildcard usages detected. Replace with specific resource ARNs where possible.")
        
        # cloudTrail-based suggestions
        if cloudtrail_analysis and 'used_actions' in cloudtrail_analysis:
            used_actions = set(cloudtrail_analysis['used_actions'])
            
            if len(used_actions) == 0:
                suggestions.append("INFO: No CloudTrail events found. Role may be unused or logging may be incomplete.")
            elif len(used_actions) < 10:
                suggestions.append(f"INFO: Only {len(used_actions)} unique actions used in CloudTrail. Consider creating a minimal policy.")
                
                # suggest a basic policy structure
                common_actions = list(used_actions)[:5]
                if common_actions:
                    suggestions.append(f"SUGGESTION: Start with these commonly used actions: {', '.join(common_actions)}")
        
        # general best practices
        suggestions.extend([
            "Use condition statements to further restrict access (e.g., IP ranges, time-based, MFA)",
            "Consider using AWS managed policies where appropriate instead of custom policies",
            "Regularly review and audit role permissions using AWS Access Advisor",
            "Implement policy versioning and change tracking for compliance"
        ])
        
        return suggestions

    def print_analysis_report(self, analysis_results: Dict[str, Any], 
                            human_readable: bool = True):
        # print comprehensive analysis report
        
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
        
        # trust Relationships
        trust_analysis = analysis_results.get('trust_analysis', {})
        print(f"\n{Colors.BOLD}{Colors.CYAN}TRUST RELATIONSHIPS{Colors.RESET}")
        print("-" * 40)
        
        if trust_analysis.get('wildcard_trusts'):
            print(f"{Colors.RED}CRITICAL RISK: Wildcard trust relationships found{Colors.RESET}")
            for trust in trust_analysis['wildcard_trusts']:
                print(f"  - Risk Level: {trust.get('risk_level', 'UNKNOWN')}")
                print(f"  - Description: {trust.get('description', 'N/A')}")
        
        if trust_analysis.get('cross_account_trusts'):
            print(f"{Colors.YELLOW}WARNING: Cross-account trusts:{Colors.RESET}")
            for trust in trust_analysis['cross_account_trusts']:
                print(f"  - Account: {trust['account_id']} (Risk: {trust.get('risk_level', 'MEDIUM')})")
        
        if trust_analysis.get('service_trusts'):
            print(f"{Colors.GREEN}INFO: Service trusts:{Colors.RESET}")
            for service in trust_analysis['service_trusts']:
                print(f"  - {service}")
        
        # policy Analysis
        policy_analyses = analysis_results.get('policy_analysis', [])
        print(f"\n{Colors.BOLD}{Colors.CYAN}POLICY ANALYSIS{Colors.RESET}")
        print("-" * 40)
        
        total_risks = 0
        total_severity_score = 0
        
        for policy_analysis in policy_analyses:
            policy_name = policy_analysis['policy_name']
            severity_score = policy_analysis.get('severity_score', 0)
            total_severity_score += severity_score
            
            print(f"\n{Colors.BOLD}Policy: {policy_name} (Severity Score: {severity_score}){Colors.RESET}")
            
            if policy_analysis['overprivileged_statements']:
                count = len(policy_analysis['overprivileged_statements'])
                print(f"{Colors.RED}CRITICAL RISK: {count} overprivileged statement(s){Colors.RESET}")
                total_risks += count
            
            if policy_analysis['risky_permissions']:
                count = len(policy_analysis['risky_permissions'])
                print(f"{Colors.YELLOW}HIGH RISK: {count} risky permission(s){Colors.RESET}")
                total_risks += count
            
            if policy_analysis['privilege_escalation_risk']:
                print(f"{Colors.RED}CRITICAL RISK: Privilege escalation risk detected{Colors.RESET}")
                total_risks += 1
            
            wildcard_count = len(policy_analysis.get('wildcard_usage', []))
            legitimate_count = len(policy_analysis.get('legitimate_wildcards', []))
            
            if wildcard_count > 0:
                print(f"{Colors.YELLOW}WARNING: {wildcard_count} problematic wildcard usage(s){Colors.RESET}")
                total_risks += wildcard_count
            
            if legitimate_count > 0:
                print(f"{Colors.GREEN}INFO: {legitimate_count} legitimate wildcard usage(s){Colors.RESET}")
        
        # permission Simulation Results
        simulation_results = analysis_results.get('simulation_results', [])
        if simulation_results:
            print(f"\n{Colors.BOLD}{Colors.CYAN}PERMISSION SIMULATION{Colors.RESET}")
            print("-" * 40)
            
            allowed_count = sum(1 for result in simulation_results if result.get('EvalDecision') == 'allowed')
            denied_count = len(simulation_results) - allowed_count
            
            print(f"{Colors.GREEN}ALLOWED: {allowed_count} actions{Colors.RESET}")
            print(f"{Colors.RED}DENIED: {denied_count} actions{Colors.RESET}")
            
            # show some examples of denied actions
            denied_actions = [r.get('ActionName', 'Unknown') for r in simulation_results 
                             if r.get('EvalDecision') == 'denied'][:5]
            if denied_actions:
                print(f"{Colors.CYAN}Sample denied actions: {', '.join(denied_actions)}{Colors.RESET}")
        
        
        cloudtrail_analysis = analysis_results.get('cloudtrail_analysis', {})
        if 'used_actions' in cloudtrail_analysis:
            print(f"\n{Colors.BOLD}{Colors.CYAN}USAGE ANALYSIS (CloudTrail){Colors.RESET}")
            print("-" * 40)
            print(f"Analysis period: {cloudtrail_analysis['analysis_period_days']} days")
            print(f"Total events: {cloudtrail_analysis['total_events']}")
            print(f"Unique actions used: {len(cloudtrail_analysis['used_actions'])}")
            print(f"Unique resources accessed: {len(cloudtrail_analysis.get('resources_accessed', []))}")
            
            # show most common actions
            most_common = cloudtrail_analysis.get('most_common_actions', {})
            if most_common:
                print(f"{Colors.CYAN}Most common actions:{Colors.RESET}")
                for action, count in list(most_common.items())[:5]:
                    print(f"  - {action}: {count} times")
            
            # show error events
            error_events = cloudtrail_analysis.get('error_events', [])
            if error_events:
                print(f"{Colors.RED}Permission errors found: {len(error_events)}{Colors.RESET}")
                for error in error_events[:3]:
                    print(f"  - {error.get('event_name', 'Unknown')}: {error.get('error_code', 'Unknown error')}")
        
        # Least Privilege Suggestions
        suggestions = analysis_results.get('suggestions', [])
        if suggestions:
            print(f"\n{Colors.BOLD}{Colors.CYAN}LEAST PRIVILEGE RECOMMENDATIONS{Colors.RESET}")
            print("-" * 40)
            for i, suggestion in enumerate(suggestions, 1):
                # Color code suggestions by priority
                if suggestion.startswith('CRITICAL:'):
                    color = Colors.RED
                elif suggestion.startswith('HIGH:'):
                    color = Colors.YELLOW
                elif suggestion.startswith('MEDIUM:'):
                    color = Colors.CYAN
                else:
                    color = Colors.WHITE
                
                print(f"{i}. {color}{suggestion}{Colors.RESET}")
        
        # Security Summary
        print(f"\n{Colors.BOLD}{Colors.CYAN}SECURITY SUMMARY{Colors.RESET}")
        print("-" * 40)
        print(f"Total Severity Score: {total_severity_score}")
        
        if total_severity_score == 0:
            print(f"{Colors.GREEN}EXCELLENT: No major security risks detected{Colors.RESET}")
        elif total_severity_score <= 5:
            print(f"{Colors.GREEN}GOOD: Low risk profile - Minor improvements recommended{Colors.RESET}")
        elif total_severity_score <= 15:
            print(f"{Colors.YELLOW}MODERATE: {total_risks} potential security issues - Review recommended{Colors.RESET}")
        elif total_severity_score <= 30:
            print(f"{Colors.RED}HIGH RISK: {total_risks} security risks detected - Immediate review required{Colors.RESET}")
        else:
            print(f"{Colors.RED}CRITICAL: {total_risks} severe security risks - URGENT remediation required{Colors.RESET}")

    def run_analysis(self, role_name: str, actions: List[str] = None, 
                    resources: List[str] = None, detect_overprivilege: bool = False,
                    analyze_usage: bool = False, usage_days: int = 30, 
                    least_privilege_suggestions: bool = False) -> Dict[str, Any]:
        """Run comprehensive IAM role analysis"""
        
        print(f"{Colors.CYAN}Analyzing IAM role: {role_name}{Colors.RESET}")
        
        try:
            # Get role information
            role_info = self.get_role_info(role_name)
            role_arn = role_info['role']['Arn']
            
            analysis_results = {
                'role_name': role_name,
                'role_arn': role_arn,
                'account_id': self.account_id,
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
                if policy_doc:  # Only analyze if we got the document
                    policy_analysis = self.analyze_policy_document(policy_doc, policy['PolicyName'])
                    analysis_results['policy_analysis'].append(policy_analysis)
            
            # Analyze inline policies
            for policy_name in role_info['inline_policies']:
                policy_doc = self.get_policy_document(policy_name=policy_name, role_name=role_name)
                if policy_doc:  # Only analyze if we got the document
                    policy_analysis = self.analyze_policy_document(policy_doc, policy_name)
                    analysis_results['policy_analysis'].append(policy_analysis)
            
            # Simulate permissions if requested
            if actions and resources:
                print(f"{Colors.CYAN}  -> Simulating permissions...{Colors.RESET}")
                simulation_results = self.simulate_permissions(role_arn, actions, resources)
                analysis_results['simulation_results'] = simulation_results
            
            # CloudTrail usage analysis
            if analyze_usage:
                cloudtrail_analysis = self.analyze_cloudtrail_usage(role_arn, usage_days)
                analysis_results['cloudtrail_analysis'] = cloudtrail_analysis
            
            # Generate least privilege suggestions
            if least_privilege_suggestions or analyze_usage:
                print(f"{Colors.CYAN}  -> Generating least privilege suggestions...{Colors.RESET}")
                suggestions = self.generate_least_privilege_suggestions(
                    analysis_results['policy_analysis'], 
                    analysis_results.get('cloudtrail_analysis')
                )
                analysis_results['suggestions'] = suggestions
            
            # Add general security suggestions based on analysis
            general_suggestions = []
            total_policies = len(role_info['attached_policies']) + len(role_info['inline_policies'])
            
            if total_policies > 10:
                general_suggestions.append(f"MEDIUM: Consider consolidating {total_policies} policies for better management")
            
            if total_policies == 0:
                general_suggestions.append("WARNING: Role has no policies attached - it may be unused")
            
            # Check for unused role based on CloudTrail
            if analyze_usage and analysis_results.get('cloudtrail_analysis', {}).get('total_events', 0) == 0:
                general_suggestions.append("INFO: No CloudTrail events found - role may be unused or require longer analysis period")
            
            # Add trust relationship warnings
            trust_score = analysis_results['trust_analysis'].get('severity_score', 0)
            if trust_score > 10:
                general_suggestions.append("CRITICAL: Trust relationships pose significant security risks")
            
            # Extend existing suggestions
            analysis_results['suggestions'].extend(general_suggestions)
            
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
  %(prog)s --role TestRole --actions ec2:DescribeInstances --resource "*" --json
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
    
    # Validate usage days
    if args.usage_days < 1 or args.usage_days > 90:
        print(f"{Colors.RED}Error: --usage-days must be between 1 and 90{Colors.RESET}")
        sys.exit(1)
    
    # Initialize analyzer
    try:
        analyzer = IAMAnalyzer(profile=args.profile, region=args.region)
    except Exception as e:
        print(f"{Colors.RED}Failed to initialize analyzer: {e}{Colors.RESET}")
        sys.exit(1)
    
    # Run analysis
    analysis_results = analyzer.run_analysis(
        role_name=args.role,
        actions=args.actions,
        resources=args.resource,
        detect_overprivilege=args.detect_overprivilege,
        analyze_usage=args.unused,
        usage_days=args.usage_days,
        least_privilege_suggestions=args.least_privilege_suggestions
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
    
    # Exit with appropriate code based on severity
    total_severity = 0
    for policy in analysis_results.get('policy_analysis', []):
        total_severity += policy.get('severity_score', 0)
    
    trust_severity = analysis_results.get('trust_analysis', {}).get('severity_score', 0)
    total_severity += trust_severity
    
    if total_severity > 20:
        sys.exit(2)  # Critical issues found
    elif total_severity > 10:
        sys.exit(1)  # Warning issues found
    else:
        sys.exit(0)  # No major issues


if __name__ == '__main__':
    main()