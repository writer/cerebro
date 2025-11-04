def test_security_center_overview_includes_vendor_and_customer_data(client, test_org, admin_token):
    org_id = test_org.org_id

    vendor_payload = {
        "name": "Acme Cloud",
        "website_url": "https://acme.example.com",
        "category": "security_vendor",
        "primary_contact": "security@acme.example.com",
        "industry": "SaaS",
        "country": "US",
        "data_processing_locations": ["us-east-1"],
        "certifications": ["SOC2"],
        "data_types_processed": ["PII"],
        "business_criticality": "high",
    }

    vendor_response = client.post(
        f"/api/v1/vendors/organizations/{org_id}/vendors",
        json=vendor_payload,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert vendor_response.status_code == 200, vendor_response.text

    customer_payload = {
        "name": "Galaxy Industries",
        "account_manager": "csm-jane",
        "segment": "enterprise",
        "primary_contact": "galaxy@customer.com",
        "region": "na",
        "seats_committed": 240,
        "support_tickets_open": 2,
        "metadata": {"success_programs": ["design_partner"]},
    }

    customer_response = client.post(
        f"/api/v1/customers/organizations/{org_id}/customers",
        json=customer_payload,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert customer_response.status_code == 200, customer_response.text

    overview_response = client.get(
        f"/api/v1/security-center/organizations/{org_id}/overview",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert overview_response.status_code == 200
    overview = overview_response.json()

    assert "metrics" in overview
    assert "vendorInsights" in overview
    assert "customerInsights" in overview
    assert len(overview["vendorInsights"]) >= 1
    assert len(overview["customerInsights"]) >= 1

    vendor_summary = overview["vendorInsights"][0]
    assert vendor_summary["name"] == "Acme Cloud"
    customer_summary = overview["customerInsights"][0]
    assert customer_summary["name"] == "Galaxy Industries"


def test_security_center_entity_listings(client, test_org, admin_token):
    org_id = test_org.org_id

    client.post(
        f"/api/v1/vendors/organizations/{org_id}/vendors",
        json={
            "name": "Future Corp",
            "website_url": "https://future.example.com",
            "category": "cloud_provider",
            "business_criticality": "medium",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    client.post(
        f"/api/v1/customers/organizations/{org_id}/customers",
        json={
            "name": "Nebula Systems",
            "account_manager": "csm-alex",
            "segment": "smb",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    vendor_list = client.get(
        f"/api/v1/security-center/organizations/{org_id}/vendors",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert vendor_list.status_code == 200
    vendors = vendor_list.json()
    assert vendors["count"] >= 1

    customer_list = client.get(
        f"/api/v1/security-center/organizations/{org_id}/customers",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert customer_list.status_code == 200
    customers = customer_list.json()
    assert customers["count"] >= 1
