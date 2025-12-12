# auth_app/emails.py
from django.core.mail import send_mail
from django.conf import settings

def send_password_reset_email(email, reset_link):
    subject = "Reset your TaskNest password"
    message = f"""
    Hello,

    You requested to reset your password on TaskNest.
    Click the link below to set a new password:

    {reset_link}

    This link will expire in 1 hour.

    If you didn’t request this, please ignore this email.
    """
    send_mail(
        subject, 
        message.strip(), 
        settings.DEFAULT_FROM_EMAIL, 
        [email], 
        fail_silently=False,
    )

def send_verification_email(email, verify_link):
    subject = "Verify your TaskNest account"
    message = f"""
    Welcome to TaskNest!

    Please verify your email address by clicking the link below:
    {verify_link}

    Thank you,
    The TaskNest Team
    """
    send_mail(subject, message.strip(), settings.DEFAULT_FROM_EMAIL, [email], fail_silently=False)
