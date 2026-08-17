from tests.conftest import user_id, make_scan, make_report


def test_download_report_not_found(client, admin_token):
    res = client.get("/api/reports/999999/download", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 404


def test_download_report_forbidden_other_client(client, db, analyst_token, client_token, other_client_token):
    # scan/report belong to "testclient2"; "testclient" must not be able to download it.
    analyst_id = user_id(db, "testanalyst")
    other_client_id = user_id(db, "testclient2")
    scan = make_scan(db, user_id=analyst_id, client_id=other_client_id, target="10.0.0.20")
    report = make_report(db, scan.id, pdf_path=None)

    res = client.get(f"/api/reports/{report.id}/download", headers={"Authorization": f"Bearer {client_token}"})
    assert res.status_code == 404


def test_download_report_client_owns_scan(client, db, tmp_path, analyst_token, client_token):
    analyst_id = user_id(db, "testanalyst")
    my_client_id = user_id(db, "testclient")
    scan = make_scan(db, user_id=analyst_id, client_id=my_client_id, target="10.0.0.21")

    pdf_file = tmp_path / "report.pdf"
    pdf_file.write_bytes(b"%PDF-1.4 fake report content")
    report = make_report(db, scan.id, pdf_path=str(pdf_file))

    res = client.get(f"/api/reports/{report.id}/download", headers={"Authorization": f"Bearer {client_token}"})
    assert res.status_code == 200
    assert res.content == b"%PDF-1.4 fake report content"


def test_download_report_analyst_unrestricted(client, db, tmp_path, analyst_token, client_token):
    # By design (mirrors list_reports), only the "client" role is scoped to its own
    # scans — an analyst/admin can download any report. This test pins that intended
    # behavior so a future change doesn't accidentally over-restrict analysts.
    analyst_id = user_id(db, "testanalyst")
    someone_elses_client_id = user_id(db, "testclient")
    scan = make_scan(db, user_id=analyst_id, client_id=someone_elses_client_id, target="10.0.0.22")

    pdf_file = tmp_path / "report.pdf"
    pdf_file.write_bytes(b"%PDF-1.4 analyst visible")
    report = make_report(db, scan.id, pdf_path=str(pdf_file))

    res = client.get(f"/api/reports/{report.id}/download", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res.status_code == 200


def test_list_reports_scoped_to_client(client, db, analyst_token, client_token, other_client_token):
    from app.models.scan import Scan

    analyst_id = user_id(db, "testanalyst")
    my_client_id = user_id(db, "testclient")
    other_client_id = user_id(db, "testclient2")

    my_scan = make_scan(db, user_id=analyst_id, client_id=my_client_id, target="10.0.0.30")
    my_report = make_report(db, my_scan.id)
    other_scan = make_scan(db, user_id=analyst_id, client_id=other_client_id, target="10.0.0.31")
    make_report(db, other_scan.id)

    res = client.get("/api/reports/", headers={"Authorization": f"Bearer {client_token}"})
    assert res.status_code == 200
    reports = res.json()
    report_ids = [r["id"] for r in reports]
    assert my_report.id in report_ids
    # None of the returned reports should belong to a scan of the other client.
    for r in reports:
        scan = db.get(Scan, r["scan_id"])
        assert scan.client_id == my_client_id
