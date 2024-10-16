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
        requesting_user = instance.user  
        requesting_organisation = requesting_user.organisation  
        
        if user and user.email:
            try:
                context = {
                    'incident_id': incident.id,
                    'incident_title': incident.title,  
                    'incident_zone': incident.zone,  
                    'incident_creation_date': incident.created_at,  
                    'organisation': user.organisation,
                    'requesting_organisation': requesting_organisation 
                }
                
                # Envoi de l'email à l'organisation
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
                    message=f"L'organisation {requesting_organisation} souhaite collaborer sur l'incident {incident.title} (Zone: {incident.zone}, Date: {incident.created_at.strftime('%d-%m-%Y')})",
                    colaboration=instance
                )
                logger.info(f"Notification créée pour l'utilisateur {user.email}.")
                
            except Exception as e:
                logger.error(f"Erreur lors de l'envoi de l'email: {str(e)}")
        else:
            logger.error(f"Email non valide ou manquant pour l'utilisateur {user}. Collaboration annulée.")
            instance.delete()  
