import asyncio
from cerebro.findings.producers import producer_registry
from cerebro.domain.entities import ResourceEntity, ConfigEntity
from datetime import datetime


async def test_findings():
    # Test GitHub producer
    resource = ResourceEntity(
        external_id='test/repo',
        resource_type='github.repo',
        provider='github',
        name='test-repo'
    )

    config = ConfigEntity(
        resource_external_id='test/repo',
        captured_at=datetime.utcnow(),
        normalized_config={
            'visibility': 'public',
            'branchProtection': {'requirePR': False},
            'archived': False
        }
    )

    findings = producer_registry.evaluate_resource(resource, config)
    print(f'Generated {len(findings)} findings for test resource')

    for finding in findings:
        print(f'  - {finding.title} (severity: {finding.severity})')


asyncio.run(test_findings())
