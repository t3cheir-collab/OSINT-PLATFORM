# app/services/email_service.py
import os
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

GMAIL_USER = os.getenv("MAIL_USERNAME", "")
GMAIL_PASS = os.getenv("MAIL_PASSWORD", "")   # Gmail App Password (16 chars, no spaces)
MAIL_FROM  = os.getenv("MAIL_FROM", GMAIL_USER)
APP_NAME   = "OSINT Intelligence Platform"
APP_URL    = os.getenv("APP_URL", "http://localhost:5173")


def _send(to: str, subject: str, html: str) -> bool:
    """Send email via Gmail SMTP TLS. Returns True on success."""
    if not GMAIL_USER or not GMAIL_PASS:
        logger.warning("MAIL_USERNAME / MAIL_PASSWORD not set - email not sent")
        logger.info(f"[DEV] Email to {to}: {subject}")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"{APP_NAME} <{MAIL_FROM}>"
        msg["To"]      = to
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.ehlo()
            server.starttls()
            server.login(GMAIL_USER, GMAIL_PASS)
            server.sendmail(MAIL_FROM, to, msg.as_string())
        logger.info(f"Email sent to {to}: {subject}")
        return True
    except Exception as e:
        logger.error(f"Email send failed to {to}: {e}")
        return False


def _base_template(title: str, body_html: str) -> str:
    return f"""
<!DOCTYPE html><html><body style="margin:0;padding:0;background:#0a0f1a;font-family:-apple-system,sans-serif;">
<div style="max-width:520px;margin:40px auto;background:#111827;border-radius:16px;border:1px solid #1f2937;overflow:hidden;">
  <div style="background:linear-gradient(135deg,#1e3a5f,#2563EB);padding:28px 32px;">
    <div style="font-size:11px;font-weight:800;color:rgba(255,255,255,.6);letter-spacing:.12em;text-transform:uppercase;margin-bottom:6px;">OSINT Intelligence Platform</div>
    <div style="font-size:22px;font-weight:900;color:white;">{title}</div>
  </div>
  <div style="padding:32px;">
    {body_html}
  </div>
  <div style="padding:16px 32px;border-top:1px solid #1f2937;font-size:11px;color:#374151;text-align:center;">
    This email was sent by {APP_NAME}. Do not reply to this email.
  </div>
</div>
</body></html>"""


def send_verification_email(to: str, code: str) -> bool:
    body = f"""
    <p style="color:#9CA3AF;font-size:14px;line-height:1.7;margin-bottom:24px;">
      Welcome! Please verify your email address to activate your account.
      Enter the code below in the app:
    </p>
    <div style="background:#1f2937;border:1px solid #3B82F633;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px;">
      <div style="font-size:36px;font-weight:900;color:#3B82F6;letter-spacing:.2em;font-family:monospace;">{code}</div>
      <div style="font-size:12px;color:#4B5563;margin-top:8px;">Expires in 10 minutes</div>
    </div>
    <p style="color:#6B7280;font-size:12px;">If you didn't create an account, you can safely ignore this email.</p>"""
    return _send(to, f"Verify your {APP_NAME} account", _base_template("Email Verification", body))


def send_mfa_email(to: str, code: str) -> bool:
    body = f"""
    <p style="color:#9CA3AF;font-size:14px;line-height:1.7;margin-bottom:24px;">
      Your login verification code is:
    </p>
    <div style="background:#1f2937;border:1px solid #3B82F633;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px;">
      <div style="font-size:36px;font-weight:900;color:#10B981;letter-spacing:.2em;font-family:monospace;">{code}</div>
      <div style="font-size:12px;color:#4B5563;margin-top:8px;">Expires in 10 minutes · Single use</div>
    </div>
    <p style="color:#6B7280;font-size:12px;">If you didn't attempt to log in, please change your password immediately.</p>"""
    return _send(to, f"Your {APP_NAME} login code", _base_template("Login Verification", body))


def send_password_reset_email(to: str, reset_url: str) -> bool:
    body = f"""
    <p style="color:#9CA3AF;font-size:14px;line-height:1.7;margin-bottom:24px;">
      We received a request to reset your password. Click the button below:
    </p>
    <div style="text-align:center;margin-bottom:24px;">
      <a href="{reset_url}" style="display:inline-block;background:linear-gradient(135deg,#2563EB,#3B82F6);color:white;text-decoration:none;padding:14px 32px;border-radius:10px;font-weight:800;font-size:14px;">
        Reset Password →
      </a>
    </div>
    <p style="color:#6B7280;font-size:12px;">This link expires in 1 hour. If you didn't request a reset, ignore this email.</p>
    <p style="color:#374151;font-size:11px;word-break:break-all;margin-top:12px;">Or copy this URL: {reset_url}</p>"""
    return _send(to, f"Reset your {APP_NAME} password", _base_template("Password Reset", body))