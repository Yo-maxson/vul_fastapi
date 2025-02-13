from fastapi.testclient import TestClient

from app.main import app
import pytest
client = TestClient(app)


@pytest.mark.asyncio
async def test_get_cve():
    response = client.get("/info_cve/?cve_name=CVE-2025-0435")
    assert response.status_code == 200
    assert response.json() == {
        "name": "CVE-2025-0435",
        "baseScore": 6.5,
        "vectorString_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "link": "https://www.cve.org/CVERecord?id=CVE-2025-0435",
        "publicated": True,
        "datePublished": "2025-01-15",
        "dateUpdated": "2025-01-15"
    }