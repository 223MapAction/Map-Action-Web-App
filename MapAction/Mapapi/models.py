
from django.db import models

# Create your models here.

from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin, Group, Permission)
from django.utils import timezone
# from django.utils.translation import ugettext_lazy as _
from importlib.resources import _
from datetime import datetime, timedelta

from django.conf import settings

ADMIN = 'admin'
VISITOR = 'visitor'
CITIZEN = 'citizen'
REPORTER = 'reporter'
BUSINESS = 'business'
ELU = 'elu'
DECLARED = 'declared'
RESOLVED = 'resolved'
IN_PROGRESS = "in_progress"
TAKEN = "taken_into_account"

USER_TYPES = (
    (ADMIN, ADMIN),
    (VISITOR, VISITOR),
    (REPORTER, REPORTER),
    (CITIZEN, CITIZEN),
    (BUSINESS, BUSINESS),
    (ELU, ELU)
)
ETAT_INCIDENT = (
    (DECLARED, DECLARED),
    (RESOLVED, RESOLVED),
    (IN_PROGRESS, IN_PROGRESS),
    (TAKEN, TAKEN)
)
ETAT_RAPPORT = (
    ("new", "new"),
    ("in_progress", "in_progress"),
    ("edit", "edit"),
    ("canceled", "canceled")
)


# Creation du model User pour les utilisateurs de l'application pour securiser l'entree des commandes

class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """
        Creates and saves a User with the given email and password.
        """
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_staff', True)

        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    groups = models.ManyToManyField(
        Group,
        related_name="mapapi_user_groups",
        blank=True,
        verbose_name="groups",
        help_text="The groups this user belongs to. A user will get all permissions granted to each of their groups.",
    ),
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="mapapi_user_user_permissions",
        blank=True,
        verbose_name="user permissions",
        help_text="Specific permissions for this user.",
    )

    email = models.EmailField(unique=True)
    first_name = models.CharField(_('first name'), max_length=255, blank=False)
    last_name = models.CharField(_('last name'), max_length=255, blank=False)
    phone = models.CharField(_('phone number'), max_length=20, blank=True, null=True)
    date_joined = models.DateTimeField(_('date joined'), auto_now_add=True)
    is_active = models.BooleanField(_('active'), default=True)
    is_staff = models.BooleanField(default=False)
    avatar = models.ImageField(default="avatars/default.png", upload_to='avatars/', null=True, blank=True)
    password_reset_count = models.DecimalField(max_digits=10, decimal_places=0, null=True, blank=True, default=0)
    address = models.CharField(_('adress'), max_length=255, blank=True, null=True)
    user_type = models.CharField(
        max_length=15, choices=USER_TYPES, blank=False, null=False, default=CITIZEN)
    community = models.ForeignKey('Communaute', db_column='user_communaute_id', related_name='user_communaute',
                                   on_delete=models.CASCADE, null=True, blank=True)
    provider = models.CharField(_('provider'), max_length=255, blank=True, null=True)
    organisation = models.CharField(max_length=255, blank=True,
                                    null=True)
    points = models.IntegerField(null=True, blank=True, default=0)
    zones = models.ManyToManyField('Zone', blank=True)
    objects = UserManager()

    USERNAME_FIELD = 'email'
    # these field are required on registering
    REQUIRED_FIELDS = ['first_name', 'last_name']

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def __str__(self):
        return self.email

    def get_full_name(self):
        '''
        Returns the first_name plus the last_name, with a space in between.
        '''
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        '''
        Returns the short name for the user.
        '''
        return self.first_name


class Incident(models.Model):
    title = models.CharField(max_length=250, blank=True,
                             null=True)
    zone = models.CharField(max_length=250, blank=False,
                            null=False)
    description = models.TextField(max_length=500, blank=True, null=True)
    photo = models.ImageField(upload_to='uploads/',null=True, blank=True)
    video = models.FileField(upload_to='uploads/',blank=True, null=True)
    audio = models.FileField(upload_to='uploads/',blank=True, null=True)
    user_id = models.ForeignKey('User', db_column='user_incid_id', related_name='user_incident',
                                on_delete=models.CASCADE, null=True)
    lattitude = models.CharField(max_length=250, blank=True,
                                 null=True)
    longitude = models.CharField(max_length=250, blank=True,
                                 null=True)
    etat = models.CharField(
        max_length=255, choices=ETAT_INCIDENT, blank=False, null=False, default=DECLARED)
    category_id = models.ForeignKey('Category', db_column='categ_incid_id', related_name='user_category',
                                    on_delete=models.CASCADE, null=True)
    indicateur_id = models.ForeignKey('Indicateur', db_column='indic_incid_id', related_name='user_indicateur',
                                      on_delete=models.CASCADE, null=True)
    slug = models.CharField(max_length=250, blank=True,
                            null=True)
    category_ids = models.ManyToManyField('Category', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.zone + ' '


class Evenement(models.Model):
    title = models.CharField(max_length=255, blank=True,
                             null=True)
    zone = models.CharField(max_length=255, blank=False,
                            null=False)
    description = models.TextField(max_length=500, blank=True, null=True)
    photo = models.ImageField(null=True, blank=True)
    date = models.DateTimeField(null=True)
    lieu = models.CharField(max_length=250, blank=False,
                            null=False)
    video = models.FileField(blank=True, null=True)
    audio = models.FileField(blank=True, null=True)
    user_id = models.ForeignKey('User', db_column='user_event_id', related_name='user_event', on_delete=models.CASCADE,
                                null=True)
    latitude = models.CharField(max_length=1000, blank=True, null=True)
    longitude = models.CharField(max_length=1000, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.zone + ' '


class Contact(models.Model):
    objet = models.CharField(max_length=250, blank=False,
                             null=False)
    message = models.TextField(max_length=500, blank=True, null=True)
    email = models.CharField(max_length=250, blank=True,
                             null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.objet + ' '


class Communaute(models.Model):
    name = models.CharField(max_length=250, blank=False,
                            null=False)
    zone = models.ForeignKey('Zone', db_column='zone_communaute_id', related_name='Zone_communaute',
                             on_delete=models.CASCADE, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name + ' '


class Rapport(models.Model):
    details = models.CharField(max_length=500, blank=False,
                               null=False)
    type = models.CharField(max_length=500, blank=True,
                            null=True)
    incident = models.ForeignKey('Incident', db_column='incident_rapport_id', related_name='incident_rapport',
                                 on_delete=models.CASCADE, null=True)
    zone = models.CharField(max_length=250, blank=False, null=True)
    user_id = models.ForeignKey('User', db_column='user_rapport_id', related_name='user_rapport',
                                on_delete=models.CASCADE, null=True)
    date_livraison = models.CharField(max_length=100, blank=True,
                                      null=True)
    statut = models.CharField(
        max_length=15, choices=ETAT_RAPPORT, blank=False, null=False, default="new")
    incidents = models.ManyToManyField('Incident', blank=True)
    disponible = models.BooleanField(_('active'), default=False)
    file = models.FileField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.details + ' '


class Participate(models.Model):
    evenement_id = models.ForeignKey('Evenement', db_column='event_participate_id', related_name='event_participate',
                                     on_delete=models.CASCADE, null=True)
    user_id = models.ForeignKey('User', db_column='user_participate_id', related_name='user_participate',
                                on_delete=models.CASCADE, null=True)
    created_at = models.DateTimeField(auto_now_add=True)


class Zone(models.Model):
    name = models.CharField(max_length=250, blank=False,
                            null=False, unique=True)
    lattitude = models.CharField(max_length=250, blank=True,
                                 null=True)
    longitude = models.CharField(max_length=250, blank=True,
                                 null=True)
    photo = models.ImageField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name + ' '


class Message(models.Model):
    objet = models.CharField(max_length=250, blank=False,
                             null=False)
    message = models.CharField(max_length=250, blank=False, null=False)

    zone = models.ForeignKey('Zone', db_column='mess_zone_id', related_name='zone_mess', on_delete=models.CASCADE,
                             null=True)
    communaute = models.ForeignKey('Communaute', db_column='mess_communaute_id', related_name='communaute_mess',
                                   on_delete=models.CASCADE, null=True)
    user_id = models.ForeignKey('User', db_column='user_mess_id', related_name='user_mess', on_delete=models.CASCADE,
                                null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.objet + ' '


class ResponseMessage(models.Model):
    response = models.CharField(max_length=250, blank=False, null=False)

    message = models.ForeignKey('Message', db_column='mess_resp_id', related_name='resp_mess', on_delete=models.CASCADE,
                                null=True)
    elu = models.ForeignKey('User', db_column='user_mess_id', related_name='user_resp', on_delete=models.CASCADE,
                            null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.response + ' '


class Category(models.Model):
    name = models.CharField(max_length=250, blank=False,
                            null=False, unique=True)
    photo = models.ImageField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name + ' '


class Indicateur(models.Model):
    name = models.CharField(max_length=250, blank=False,
                            null=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name + ' '


class PasswordReset(models.Model):
    code = models.CharField(max_length=7, blank=False, null=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, blank=False, null=False, on_delete=models.CASCADE)
    date_created = models.DateTimeField(auto_now_add=True)
    used = models.BooleanField(default=False)
    date_used = models.DateTimeField(null=True)


class ImageBackground(models.Model):
    photo = models.ImageField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

# verification code otp
class PhoneOTP(models.Model):
    phone_number = models.CharField(max_length=15)
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

# Collaboration table
class Collaboration(models.Model):
    incident = models.ForeignKey('Incident', blank=False, null=False, on_delete=models.CASCADE)
    user = models.ForeignKey(User, blank=False, null=False, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    end_date = models.DateField(blank=True)

class Prediction(models.Model):
    incident_id = models.CharField(max_length=255, blank=False, null=False)
    incident_type = models.CharField(max_length=255, blank=False, null=False)
    piste_solution = models.TextField(blank=False, null=False)
    impact_potentiel = models.TextField(blank=False, null=False)
    context = models.TextField(blank=False, null=False)


class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)


class ChatHistory(models.Model):
    session_id = models.CharField(max_length=255, db_index=True)
    question = models.TextField(db_index=True)
    answer = models.TextField(db_index=True)
