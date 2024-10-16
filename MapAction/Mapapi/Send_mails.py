from celery import shared_task
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import logging
logger = logging.getLogger(__name__)

@shared_task
def send_email(subject, template_name, context, to_email):
    logger.info(f"Début de l'envoi de l'email à {to_email} avec le sujet {subject}.")
    try:
        html_content = render_to_string(template_name, context)
        text_content = strip_tags(html_content)
        msg = EmailMultiAlternatives(subject, text_content, 'Map Action <contact@map-action.com>', [to_email])
        msg.attach_alternative(html_content, "text/html")
        msg.send()
        logger.info(f"Email envoyé avec succès à {to_email}.")
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi de l'email: {str(e)}")
        raise e
