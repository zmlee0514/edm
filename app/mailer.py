import smtplib
from flask import render_template
from flask_mail import Message
from app.models import Newsletter, NewsletterState
from app.extensions import db, mailer

def send_email_with_newsletter(sender, newsletter_id):
    newsletter = Newsletter.query.get(newsletter_id)
    html = render_template("template-mail-newsletter.html", title=newsletter.title, content=newsletter.content)
    send_email_with_components(sender, [newsletter.user.account], "技職大玩JOB電子報", html)
    newsletter.state = NewsletterState.SENT
    db.session.commit()
    return "Email sent!"

def send_email_with_components(sender, recipients, subject, html):
    try:
        msg = Message(
            subject, sender=sender, recipients=recipients
        )
        msg.html = html
        mailer.send(msg)
    except smtplib.SMTPException as e:
        return "Failed to send email: " + str(e)