"""Unit tests for the vulnerability analyzer rules."""
from unittest.mock import MagicMock
from app.services.vuln_analyzer import analyze_host
from app.models.scan import Port, Host
from app.models.vulnerability import Severity


def _make_host_with_ports(ports: list[tuple]) -> tuple:
    """ports: list of (port_number, service)"""
    host = MagicMock(spec=Host)
    host.id = 1
    host.ports = [MagicMock(spec=Port, port_number=p, service=s) for p, s in ports]
    host.vulnerabilities = []
    return host


def test_telnet_is_critical():
    host = _make_host_with_ports([(23, "telnet")])
    db = MagicMock()
    added = []
    db.add.side_effect = added.append
    analyze_host(host, db)
    assert any(v.severity == Severity.critical for v in added)


def test_http_is_medium():
    host = _make_host_with_ports([(80, "http")])
    db = MagicMock()
    added = []
    db.add.side_effect = added.append
    analyze_host(host, db)
    assert any(v.severity == Severity.medium for v in added)


def test_no_vuln_on_unknown_port():
    host = _make_host_with_ports([(12345, "unknown")])
    db = MagicMock()
    added = []
    db.add.side_effect = added.append
    analyze_host(host, db)
    assert len(added) == 0
