from .tokens import account_activation_token
from django.core.mail import EmailMessage
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string


def send_activation_email(user):
    try:
        subject = 'Activate Your Account'
        message = render_to_string('email_verification_email.html', {
            'user': user,
            'domain': 'http://localhost:8080',
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': account_activation_token.make_token(user),
        })
        email = EmailMessage(subject, message, to=[user.email])
        email.content_subtype = 'html'
        email.send()
        return True
    except Exception:
        return False


def send_password_reset_email(user):
    try:
        subject = 'Reset your password'
        message = render_to_string('password_reset_email.html', {
            'user': user,
            'domain': 'http://localhost:8080',
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': default_token_generator.make_token(user),
        })
        email = EmailMessage(subject, message, to=[user.email])
        email.content_subtype = 'html'
        email.send()
        return True
    except Exception:
        return False
