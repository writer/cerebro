"""Background tasks for JWT key rotation and maintenance."""

import asyncio
import logging
import threading
from datetime import timedelta
from typing import Dict, Any

from cerebro.tasks.celery_app import celery_app
from cerebro.core.database import async_session_factory
from cerebro.core.security.key_store import JWTKeyStore
from cerebro.core.security.jwt import JWTService
from cerebro.core.config import settings

logger = logging.getLogger(__name__)


def _run_coro_sync(coro):
    """Execute an async coroutine from sync context, even inside active loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result: Dict[str, Any] = {}
    error: Dict[str, BaseException] = {}

    def _runner():
        try:
            result["value"] = asyncio.run(coro)
        except BaseException as exc:  # pragma: no cover - propagate to caller
            error["exception"] = exc

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    thread.join()

    if "exception" in error:
        raise error["exception"]

    return result.get("value")


@celery_app.task(bind=True, name="jwt_key_rotation")
def rotate_jwt_keys_task(self=None, *args, **_) -> Dict[str, Any]:
    """
    Celery task to rotate JWT signing keys.
    
    This task should be scheduled to run periodically (e.g., every hour)
    to check if key rotation is needed and perform it automatically.
    """
    
    task_ctx = args[0] if args else self

    async def _rotate_keys():
        result = {
            "rotation_performed": False,
            "keys_cleaned": 0,
            "error": None
        }
        
        try:
            async with async_session_factory() as db:
                key_store = JWTKeyStore(db)
                
                logger.info("Checking if JWT key rotation is needed")
                
                # Rotate keys if needed
                rotated = await key_store.rotate_keys_if_needed()
                result["rotation_performed"] = rotated
                
                if rotated:
                    logger.info("JWT key rotation completed successfully")
                else:
                    logger.debug("JWT key rotation not needed at this time")
                
                # Clean up expired keys
                cleaned_count = await key_store.cleanup_expired_keys()
                result["keys_cleaned"] = cleaned_count
                
                if cleaned_count > 0:
                    logger.info(f"Cleaned up {cleaned_count} expired JWT keys")
                
        except Exception as e:
            error_msg = f"JWT key rotation task failed: {e}"
            logger.error(error_msg)
            result["error"] = str(e)
            if task_ctx is not None and hasattr(task_ctx, "retry"):
                raise task_ctx.retry(exc=e, countdown=300, max_retries=3)
            raise
        
        return result
    
    return _run_coro_sync(_rotate_keys())


@celery_app.task(bind=True, name="jwt_revocation_cleanup")
def cleanup_jwt_revocations_task(self=None, *args, **_) -> Dict[str, Any]:
    """
    Celery task to clean up expired JWT revocations from Redis.
    
    This helps maintain Redis memory usage by removing expired revocation entries.
    """
    task_ctx = args[0] if args else self

    async def _cleanup_revocations():
        result = {
            "expired_revocations": 0,
            "error": None
        }
        
        try:
            async with async_session_factory() as db:
                key_store = JWTKeyStore(db)
                jwt_service = JWTService(key_store)
                
                logger.info("Cleaning up expired JWT revocations")
                
                expired_count = await jwt_service.cleanup_expired_revocations()
                result["expired_revocations"] = expired_count
                
                if expired_count > 0:
                    logger.info(f"Cleaned up {expired_count} expired JWT revocations")
                else:
                    logger.debug("No expired JWT revocations found")
                
        except Exception as e:
            error_msg = f"JWT revocation cleanup task failed: {e}"
            logger.error(error_msg)
            result["error"] = str(e)
            if task_ctx is not None and hasattr(task_ctx, "retry"):
                raise task_ctx.retry(exc=e, countdown=300, max_retries=3)
            raise
        
        return result

    return _run_coro_sync(_cleanup_revocations())


@celery_app.task(bind=True, name="jwt_health_check")
def jwt_health_check_task(self=None, *_, **__) -> Dict[str, Any]:
    """
    Health check task for JWT infrastructure.
    
    Verifies that key rotation and token services are working properly.
    """
    async def _health_check():
        result = {
            "current_key_exists": False,
            "verification_keys_count": 0,
            "redis_connection": False,
            "next_rotation_due": None,
            "error": None
        }
        
        try:
            async with async_session_factory() as db:
                key_store = JWTKeyStore(db)
                jwt_service = JWTService(key_store)
                
                # Check current signing key
                current_key = await key_store.get_current_signing_key()
                result["current_key_exists"] = current_key is not None
                
                if current_key:
                    next_rotation = current_key.created_at + timedelta(hours=settings.jwt_rotation_period_hours)
                    result["next_rotation_due"] = next_rotation.isoformat()
                
                # Check verification keys
                verification_keys = await key_store.get_verification_keys()
                result["verification_keys_count"] = len(verification_keys)
                
                # Test Redis connection
                try:
                    redis_client = await jwt_service._get_redis()
                    await redis_client.ping()
                    result["redis_connection"] = True
                except Exception:
                    result["redis_connection"] = False
                    logger.warning("Redis connection test failed in JWT health check")
                
        except Exception as e:
            error_msg = f"JWT health check failed: {e}"
            logger.error(error_msg)
            result["error"] = str(e)
        
        return result
    
    return _run_coro_sync(_health_check())


# Schedule periodic tasks
@celery_app.on_after_configure.connect
def setup_periodic_jwt_tasks(sender, **kwargs):
    """Set up periodic JWT maintenance tasks."""
    
    # Key rotation check - run every hour
    sender.add_periodic_task(
        3600.0,  # 1 hour
        rotate_jwt_keys_task.s(),
        name='jwt-key-rotation-check'
    )
    
    # Revocation cleanup - run every 6 hours
    sender.add_periodic_task(
        21600.0,  # 6 hours
        cleanup_jwt_revocations_task.s(),
        name='jwt-revocation-cleanup'
    )
    
    # Health check - run every 15 minutes
    sender.add_periodic_task(
        900.0,  # 15 minutes
        jwt_health_check_task.s(),
        name='jwt-health-check'
    )
    
    logger.info("Configured periodic JWT maintenance tasks")
