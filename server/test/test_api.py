from server import app

def test_healthz_route():
    client = app.test_client()
    resp = client.get("/healthz")

    assert resp.status_code == 200
    assert resp.is_json
    
def test_delete_document_requires_authentication():
    client = app.test_client()

    resp = client.delete("/api/delete-document/1")

    assert resp.status_code == 401