"""Background nmap scanner service."""
from datetime import datetime
import nmap
from sqlalchemy.orm import Session
from app.database.session import SessionLocal
from app.models.scan import Scan, Host, Port, ScanStatus
from app.services.vuln_analyzer import analyze_host


def run_scan(scan_id: int) -> None:
    db: Session = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = ScanStatus.running
        db.commit()

        nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
        nm = nmap.PortScanner(nmap_search_path=(nmap_path,))
        nm.scan(hosts=scan.target, arguments="-sV --open -T4")

        for ip in nm.all_hosts():
            host_info = nm[ip]
            hostname = host_info.hostname() or None
            os_match = None
            if "osmatch" in host_info and host_info["osmatch"]:
                os_match = host_info["osmatch"][0].get("name")

            host = Host(scan_id=scan.id, ip=ip, hostname=hostname, os=os_match)
            db.add(host)
            db.flush()  # get host.id

            for proto in host_info.all_protocols():
                for port_num, port_data in host_info[proto].items():
                    if port_data.get("state") != "open":
                        continue
                    port = Port(
                        host_id=host.id,
                        port_number=port_num,
                        protocol=proto,
                        service=port_data.get("name"),
                        version=f"{port_data.get('product','')} {port_data.get('version','')}".strip() or None,
                        state="open",
                    )
                    db.add(port)

            db.flush()
            analyze_host(host, db)

        scan.status = ScanStatus.completed
        scan.finished_at = datetime.utcnow()
        db.commit()

    except Exception as exc:
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = ScanStatus.failed
            scan.finished_at = datetime.utcnow()
            db.commit()
        raise exc
    finally:
        db.close()
