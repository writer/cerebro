#!/usr/bin/env python3
"""
Demo script showing Steampipe-inspired SQL queries in Cerebro.

This demonstrates the Zero-ETL approach to security data querying.
"""

import asyncio
import json
from datetime import datetime

from cerebro.query.engine import QueryEngine
from cerebro.providers.tables import register_all_provider_tables


async def demo_queries():
    """Demonstrate various SQL queries against security tables."""
    print("🔍 Cerebro Security Query Engine Demo")
    print("=" * 50)
    
    # Initialize query engine and register tables
    query_engine = QueryEngine()
    register_all_provider_tables()
    
    # List available tables
    print("\n📋 Available Security Tables:")
    tables = await query_engine.list_tables()
    for table in tables:
        print(f"  • {table['name']} ({table['provider']}) - {table['columns']} columns")
    
    print(f"\nTotal tables: {len(tables)}")
    
    # Demo queries
    demo_sql_queries = [
        {
            "name": "List AWS EC2 Instances",
            "description": "Get EC2 instances with security group information",
            "sql": "SELECT instance_id, instance_type, state, public_ip, security_groups FROM aws_ec2_instance LIMIT 5"
        },
        {
            "name": "Find Okta Users Without MFA",
            "description": "Identify users who don't have MFA enabled",
            "sql": "SELECT username, email, status, mfa_enabled, last_login FROM okta_user WHERE mfa_enabled = false LIMIT 10"
        },
        {
            "name": "GitHub High-Severity Vulnerabilities",
            "description": "Find critical vulnerability alerts in GitHub repositories",
            "sql": "SELECT repository, state, severity, created_at FROM github_vulnerability_alert WHERE severity = 'high' ORDER BY created_at DESC LIMIT 5"
        },
        {
            "name": "AWS IAM Users Analysis",
            "description": "Get IAM users with password usage information",
            "sql": "SELECT user_name, arn, password_last_used, mfa_enabled FROM aws_iam_user ORDER BY password_last_used DESC LIMIT 5"
        },
        {
            "name": "GitHub Secret Scanning Alerts",
            "description": "Find unresolved secret scanning alerts",
            "sql": "SELECT repository, secret_type, state, created_at FROM github_secret_scanning_alert WHERE state = 'open' LIMIT 5"
        },
        {
            "name": "Cross-Provider Resource Count",
            "description": "Count resources by provider",
            "sql": "SELECT 'aws' as provider, COUNT(*) as resource_count FROM aws_ec2_instance"
        }
    ]
    
    print("\n🚀 Executing Demo Queries:")
    print("=" * 50)
    
    for i, query_demo in enumerate(demo_sql_queries, 1):
        print(f"\n{i}. {query_demo['name']}")
        print(f"   Description: {query_demo['description']}")
        print(f"   SQL: {query_demo['sql']}")
        
        try:
            result = await query_engine.execute_query(query_demo['sql'])
            
            if result.errors:
                print(f"   ❌ Errors: {', '.join(result.errors)}")
                continue
                
            print(f"   ✅ Completed in {result.execution_time_ms:.2f}ms")
            print(f"   📊 Returned {result.total_rows} rows")
            
            if result.rows:
                print("   📋 Results:")
                # Display first few results
                for j, row in enumerate(result.rows[:3]):
                    print(f"      Row {j+1}: {row}")
                    
                if len(result.rows) > 3:
                    print(f"      ... and {len(result.rows) - 3} more rows")
            else:
                print("   📋 No results")
                
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    # Demonstrate table schema inspection
    print(f"\n🔍 Table Schema Inspection:")
    print("=" * 50)
    
    table_name = "aws_ec2_instance"
    table_info = await query_engine.describe_table(table_name)
    
    if table_info:
        print(f"Table: {table_info['name']} ({table_info['provider']})")
        print(f"Description: {table_info['description']}")
        print(f"Columns ({len(table_info['columns'])}):")
        
        for col in table_info['columns'][:10]:  # Show first 10 columns
            required = " (required)" if col['required'] else ""
            filterable = " [filterable]" if col['filterable'] else ""
            print(f"  • {col['name']}: {col['type']}{required}{filterable}")
            print(f"    {col['description']}")
        
        if len(table_info['columns']) > 10:
            print(f"  ... and {len(table_info['columns']) - 10} more columns")
    
    # Demonstrate advanced filtering
    print(f"\n🎯 Advanced Query Features:")
    print("=" * 50)
    
    advanced_queries = [
        {
            "name": "Time-based filtering",
            "sql": "SELECT username, last_login FROM okta_user WHERE last_login > '2024-01-01' ORDER BY last_login DESC LIMIT 3"
        },
        {
            "name": "JSON field querying", 
            "sql": "SELECT instance_id, tags FROM aws_ec2_instance WHERE tags LIKE '%WebServer%' LIMIT 3"
        },
        {
            "name": "Status filtering",
            "sql": "SELECT repository, state, severity FROM github_vulnerability_alert WHERE state = 'open' AND severity IN ('high', 'critical') LIMIT 3"
        }
    ]
    
    for query_demo in advanced_queries:
        print(f"\n• {query_demo['name']}:")
        print(f"  SQL: {query_demo['sql']}")
        
        try:
            result = await query_engine.execute_query(query_demo['sql'])
            print(f"  ✅ {result.total_rows} rows in {result.execution_time_ms:.2f}ms")
            
            if result.rows:
                for row in result.rows[:2]:
                    print(f"    {row}")
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    print(f"\n✨ Demo completed!")
    print("This demonstrates Cerebro's Zero-ETL approach to security data querying.")
    print("All data is fetched in real-time from provider APIs through SQL interface.")


def main():
    """Run the demo."""
    print("Starting Cerebro Query Engine Demo...")
    asyncio.run(demo_queries())


if __name__ == "__main__":
    main()
