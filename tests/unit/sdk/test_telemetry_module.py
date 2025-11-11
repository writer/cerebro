import logging

from prometheus_client import CollectorRegistry

from cerebro_sdk.telemetry import (
    configure_logging,
    create_counter,
    create_histogram,
    get_logger,
    time_operation,
)


def test_configure_logging_and_get_logger():
    configure_logging(level="DEBUG", json_output=False)
    logger = get_logger("sdk.test")
    assert logger.level in (logging.DEBUG, logging.NOTSET)


def test_prometheus_helpers():
    registry = CollectorRegistry()
    counter = create_counter("sdk_test_counter", "help", registry=registry)
    histogram = create_histogram("sdk_test_hist", "help", registry=registry)

    counter.inc()
    with time_operation(histogram):
        pass

    assert registry.get_sample_value("sdk_test_counter_total") == 1.0
