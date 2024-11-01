import re
import threading

from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from rest_framework.exceptions import ValidationError
from decouple import config
from twilio.rest import Client



email_regex = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
phone_regex = re.compile(r"^\+998\d{9}$")
username_regex = re.compile(r"^[a-zA-Z0-9_.-]+$")

def check_email_or_phone(email_or_phone):
    if phone_regex.fullmatch(email_or_phone):
        email_or_phone = "phone"
    elif email_regex.fullmatch(email_or_phone):
        email_or_phone = "email"
    else:
        data = {
            "success": False,
            "message": "Email yoki telefon raqamingiz xato"
        }
        raise ValidationError(data)
    return email_or_phone

def check_email_username_phone(param):

    if email_regex.fullmatch(param):
        return "email"
    elif phone_regex.fullmatch(param):
        return "phone"
    elif username_regex.fullmatch(param):
        return "username"
    else:
        raise ValidationError({
            "success": False,
            "message": "Email or phone number or username xato kiritildi"
        })


class EmailThread(threading.Thread):

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()


class Email:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            to=[data['to_email']]
        )
        if data.get('content_type') == "html":
            email.content_subtype = "html"
        EmailThread(email).start()


def send_email(email, code):
    html_content = render_to_string(
        'email/authentication/activate_account.html',
        {'code': code}
    )
    Email.send_email(
        {
            "subject": "Ro'yhatdan o'tish",
            "to_email": email,
            "body": html_content,
            "content_type": "html"
        }
    )

def send_phone(phone, code):
    account_sid = config('account_sid')
    auth_token = config('auth_token')
    client = Client(account_sid, auth_token)

    client.messages.create(
        body=f"Hey, we've sent your verification code. Please enter the code: {code}\n",
        from_="+998908802149",
        to=f"{phone}"
    )
