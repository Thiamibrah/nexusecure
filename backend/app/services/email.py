"""Email service — sends report PDF via SMTP (smtplib, zero extra deps)."""
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from app.config import settings
from app.utils.logger import logger


def send_report_email(to: str, username: str, scan_target: str, risk_score: float, pdf_path: str) -> bool:
    """Returns True if sent, False if SMTP not configured or failed."""
    if not settings.SMTP_HOST or not settings.SMTP_USER:
        logger.warning("[EMAIL] SMTP non configuré — email non envoyé à %s", to)
        return False

    try:
        msg = MIMEMultipart()
        msg["From"]    = settings.SMTP_FROM or settings.SMTP_USER
        msg["To"]      = to
        msg["Subject"] = f"[NexusSecure] Votre rapport d'audit — {scan_target}"

        color = "#dc3545" if risk_score >= 7 else "#fd7e14" if risk_score >= 4 else "#00c853"
        body = f"""
        <html><body style="font-family:sans-serif;color:#333">
          <h2 style="color:#1a73e8">NexusSecure — Rapport d'audit disponible</h2>
          <p>Bonjour <b>{username}</b>,</p>
          <p>Votre rapport d'audit de sécurité pour <code>{scan_target}</code> est disponible.</p>
          <p>Score de risque global : <b style="color:{color}">{risk_score} / 10</b></p>
          <p>Le rapport PDF est joint à cet email.</p>
          <hr>
          <small style="color:#999">NexusSecure — Plateforme d'audit réseau</small>
        </body></html>"""
        msg.attach(MIMEText(body, "html"))

        # Attach PDF
        with open(pdf_path, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="nexussecure_report.pdf"')
        msg.attach(part)

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.send_message(msg)

        logger.info("[EMAIL] Rapport envoyé à %s pour scan %s", to, scan_target)
        return True

    except Exception as e:
        logger.error("[EMAIL] Échec envoi à %s : %s", to, e)
        return False
