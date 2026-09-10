import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoints(async_client: AsyncClient):
    # Test root /health
    res1 = await async_client.get("/health")
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["status"] in ["healthy", "degraded", "online"]

    # Test /api/v1/health
    res2 = await async_client.get("/api/v1/health")
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["status"] in ["healthy", "degraded", "online"]


@pytest.mark.asyncio
async def test_paste_analysis_and_retrieval(async_client: AsyncClient, sample_emails):
    sample = sample_emails.get("clean_newsletter.eml")
    assert sample is not None

    # 1. Post raw email text
    response = await async_client.post(
        "/api/v1/analysis/paste",
        json={"raw_email_text": sample["content"]}
    )
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert data["subject"] is not None
    assert data["risk_assessment"] is not None
    assert data["raw_headers"] is not None
    analysis_id = data["id"]

    # 2. Retrieve analysis by ID
    get_res = await async_client.get(f"/api/v1/analysis/{analysis_id}")
    assert get_res.status_code == 200
    get_data = get_res.json()
    assert get_data["id"] == analysis_id
    assert get_data["raw_headers"] is not None

    # 3. Retrieve scans list
    list_res = await async_client.get("/api/v1/analysis/?limit=10")
    assert list_res.status_code == 200
    items = list_res.json()
    assert any(item["id"] == analysis_id for item in items)

    # 4. Retrieve JSON report
    json_rep_res = await async_client.get(f"/api/v1/reports/{analysis_id}/json")
    assert json_rep_res.status_code == 200
    rep_data = json_rep_res.json()
    assert "report_id" in rep_data or "case_id" in rep_data or "id" in rep_data

    # 5. Retrieve PDF report
    pdf_rep_res = await async_client.get(f"/api/v1/reports/{analysis_id}/pdf")
    assert pdf_rep_res.status_code == 200
    assert pdf_rep_res.headers.get("content-type") == "application/pdf"
    assert len(pdf_rep_res.content) > 500

    # 6. Delete analysis
    del_res = await async_client.delete(f"/api/v1/analysis/{analysis_id}")
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "deleted"

    # Verify deleted
    verify_del = await async_client.get(f"/api/v1/analysis/{analysis_id}")
    assert verify_del.status_code == 404


@pytest.mark.asyncio
async def test_nonexistent_analysis_404(async_client: AsyncClient):
    res = await async_client.get("/api/v1/analysis/nonexistent-case-id-12345")
    assert res.status_code == 404
