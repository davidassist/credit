from __future__ import annotations

from email.message import EmailMessage

import aiosmtplib

from app.core.config import settings


class EmailService:
    async def send_email(self, subject: str, recipient: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = settings.smtp_from_email
        message["To"] = recipient
        message["Subject"] = subject
        message.set_content(body)

        await aiosmtplib.send(
            message,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_username,
            password=settings.smtp_password,
            start_tls=True,
        )


email_service = EmailService()
