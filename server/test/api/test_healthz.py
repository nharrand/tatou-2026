from server import app


def test_healthz_returns_json_with_status_200():
    client = app.test_client()
    resp = client.get("/healthz")

    assert resp.status_code == 200
    assert resp.is_json
