import warnings

import pytest
from flask import request_finished

from watermarking_methods.add_after_eof import AddAfterEOF


@pytest.fixture
def toy_eof_method(monkeypatch):
    """Register the test-only EOF method for isolated HTTP and RMAP fixtures."""
    import watermarking_utils

    monkeypatch.setitem(watermarking_utils.METHODS, AddAfterEOF.name, AddAfterEOF())


@pytest.fixture(autouse=True)
def close_http_responses():
    """Close response resources after each in-process HTTP test."""
    responses = []

    def record_response(sender, response, **kwargs):
        responses.append(response)

    with request_finished.connected_to(record_response):
        yield

    # Flask test clients do not close streamed send_file handles automatically.
    for response in responses:
        response.close()


def pytest_unconfigure():
    """Handle the known SWIG metadata warning during interpreter shutdown."""
    # Pytest restores its filters before SWIG releases its final module reference.
    warnings.filterwarnings(
        "ignore",
        message="builtin type swigvarlink has no __module__ attribute",
        category=DeprecationWarning,
    )
