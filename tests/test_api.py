"""HTTP API and web shell. Runs wherever FastAPI is installed (always in CI)."""

import logging

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from server.app import app  # noqa: E402

client = TestClient(app)


def test_health():
    body = client.get("/api/health").json()
    assert body["status"] == "ok" and body["registry_version"]


def test_check_impersonation():
    response = client.post("/api/check", json={"text": "Update KYC: https://sbi-kyc-update.top/login"})
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "impersonation_signals"
    assert body["links"][0]["registrable"] == "sbi-kyc-update.top"
    assert {s["id"] for s in body["links"][0]["signals"]} >= {"brand_token", "lure_words"}


def test_check_official():
    body = client.post("/api/check", json={"text": "https://kotak.bank.in"}).json()
    assert body["verdict"] == "official"
    assert body["links"][0]["official_for"] == "Kotak Mahindra Bank"


def test_check_without_link():
    body = client.post("/api/check", json={"text": "Your OTP is 123456"}).json()
    assert body["verdict"] is None and body["links"] == []


@pytest.mark.parametrize("payload", [{"text": ""}, {}, {"text": "x" * 5001}, {"text": 5}])
def test_rejects_bad_input(payload):
    assert client.post("/api/check", json=payload).status_code == 422


def test_security_headers_on_every_response():
    for path in ["/", "/api/health", "/static/app.js"]:
        headers = client.get(path).headers
        assert "default-src 'self'" in headers["content-security-policy"]
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["referrer-policy"] == "no-referrer"
        assert headers["x-frame-options"] == "DENY"


def test_index_and_static_assets():
    page = client.get("/")
    assert page.status_code == 200 and "Is this link really your bank?" in page.text
    for asset in ["/static/app.js", "/static/styles.css"]:
        assert client.get(asset).status_code == 200


def test_page_loads_nothing_from_other_origins():
    page = client.get("/").text
    assert "googleapis" not in page and "cdn" not in page.lower()
    for asset in ["/static/app.js", "/static/styles.css"]:
        body = client.get(asset).text
        assert "http://" not in body and "@import" not in body


def test_registry_endpoint():
    body = client.get("/api/registry").json()
    assert len(body["sha256"]) == 64
    assert any(ns["suffix"] == "bank.in" for ns in body["namespaces"])
    assert any(e["name"] == "Kotak Mahindra Bank" for e in body["entities"])


def test_pasted_text_is_not_logged(caplog):
    secret = "UNIQUE-MARKER-9f3a https://sbi-kyc-update.top"
    with caplog.at_level(logging.DEBUG):
        client.post("/api/check", json={"text": secret})
    assert "UNIQUE-MARKER-9f3a" not in caplog.text


def test_unknown_path_is_404():
    assert client.get("/api/nope").status_code == 404
