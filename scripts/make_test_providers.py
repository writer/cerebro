import asyncio
from cerebro.infrastructure.provider_registry import get_provider_registry
from cerebro.core.config import settings

async def test_providers():
    registry = get_provider_registry()
    for provider_name in registry.list_providers():
        try:
            if provider_name == 'github' and settings.github_token:
                provider = registry.create_provider('github', account_id='test', org_name='test')
                result = await provider.authenticate()
                print(f'✅ GitHub: {result}')
            elif provider_name == 'aws' and settings.aws_access_key_id:
                provider = registry.create_provider('aws', account_id='test', aws_account_id='123456789012')
                result = await provider.authenticate()
                print(f'✅ AWS: {result}')
            else:
                print(f'⏩ {provider_name}: Skipped (no credentials)')
        except Exception as e:
            print(f'❌ {provider_name}: {e}')

asyncio.run(test_providers())