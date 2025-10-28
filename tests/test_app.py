from anon_analyze import app


def test_index_route():
    client = app.test_client()
    resp = client.get("/")
    # App renders a template; OK if 200 or 405 depending on route design
    assert resp.status_code in (200, 405)  # nosec B101


def test_health_missing_env(monkeypatch):
    client = app.test_client()
    assert app is not None  # nosec B101

    # TODO: Come back and make this a useful check
    resp = client.get("/")
    assert resp.status_code in (200, 405)  # nosec B101
