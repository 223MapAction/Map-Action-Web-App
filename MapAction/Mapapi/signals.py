from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Collaboration, Notification
from .Send_mails import send_email
import logging

logger = logging.getLogger(__name__)

@receiver(post_save, sender=Collaboration)
def notify_organisation_on_collaboration(sender, instance, created, **kwargs):
    if created:
        incident = instance.incident
        user = incident.taken_by
        
        # Vérification que l'utilisateur et son email existent
        if user and user.email:
            try:
                # Envoi de l'email à l'organisation
                context = {
                    'incident_id': incident.id,
                    'organisation': user.organisation,
                }
                send_email.delay(
                    subject='Nouvelle demande de collaboration',
                    template_name='emails/collaboration_request.html',
                    context=context,
                    to_email=user.email
                )
                logger.info(f"Email envoyé à {user.email} pour la collaboration sur l'incident {incident.id}.")
                
                # Création de la notification pour l'organisation
                Notification.objects.create(
                    user=user,
                    message=f"Vous avez une nouvelle collaboration pour l'incident {incident.id}",
                    colaboration=instance
                )
                logger.info(f"Notification créée pour l'utilisateur {user.username}.")
                
            except Exception as e:
                logger.error(f"Erreur lors de l'envoi de l'email: {str(e)}")

