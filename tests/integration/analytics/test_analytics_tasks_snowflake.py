import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool


SNOWFLAKE_DATABASE_URL_ENV = "SNOWFLAKE_DATABASE_URL"


@pytest.mark.integration
def test_snowflake_connection() -> None:
    url_value = os.getenv(SNOWFLAKE_DATABASE_URL_ENV)
    if not url_value:
        pytest.skip("SNOWFLAKE_DATABASE_URL not set; skipping Snowflake integration tests")

    url = make_url(url_value)
    engine = create_engine(
        url,
        poolclass=NullPool,
        pool_pre_ping=True,
        connect_args={
            "client_session_keep_alive": True,
        },
    )

    try:
        with engine.connect() as conn:
            assert conn.execute(text("SELECT 1")).scalar_one() == 1
    finally:
        engine.dispose()
