import logging

import pytest


@pytest.fixture
def clean_logger():
    logger = logging.getLogger("sentinelx")
    saved = (logger.handlers[:], logger.propagate, logger.level)
    logger.handlers = []
    yield logger
    logger.handlers, logger.propagate, logger.level = saved
