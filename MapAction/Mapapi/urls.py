from django.urls import path
from .views import *
from django.contrib.auth.views import (
    LoginView, LogoutView,
    PasswordChangeView, PasswordChangeDoneView,
    PasswordResetView,PasswordResetDoneView, PasswordResetConfirmView,PasswordResetCompleteView,
)


urlpatterns = [
    path('login/', login),
    path('register/', UserRegisterView, name='register'),
    path('user/<int:id>/', UserAPIView, name='user'),
    path('user/', UserAPIListView.as_view(), name='user_list'),
    path('user_retrieve/', UserRetrieveView.as_view(), name='user_retrieve'),
    # URL for views incidents
    path('incidentByZone/<int:zone>/', IncidentByZoneAPIView.as_view(), name='incidentZone'),
    path('incident/<int:id>', IncidentAPIView.as_view(), name='incidentZone'),
    path('incident/', IncidentAPIListView.as_view(), name='incidentZone'),
    path('incidentResolved/', IncidentResolvedAPIListView.as_view(), name='incidentResolved'),
    path('incidentNotResolved/', IncidentNotResolvedAPIListView.as_view(), name='incidentNotResolved'),
    path('incidentByMonth/', IncidentByMonthAPIListView.as_view(), name='incidentByMonth'),
    path('incidentByMonth_zone/<zone>', IncidentByMonthByZoneAPIView.as_view(), name='incidentByMonth_zone'),
    path('IncidentOnWeek/', IncidentOnWeekAPIListView.as_view(), name='IncidentOnWeek'),
    path('IncidentOnWeek_zone/<zone>', IncidentByWeekByZoneAPIView.as_view(), name='IncidentOnWeek_zone'),
    # URL for views Events
    path('Event/<int:id>', EvenementAPIView.as_view(), name='event'),
    path('Event/', EvenementAPIListView.as_view(), name='event'),
    # URL for views contact
    path('contact/<int:id>', ContactAPIView.as_view(), name='contact'),
    path('contact/', ContactAPIListView.as_view(), name='contact'),
    # URL for views community
    path('community/<int:id>', CommunauteAPIView.as_view(), name='community'),
    path('community/', CommunauteAPIListView.as_view(), name='community'),
    # URL for views rapport
    path('rapport/<int:id>', RapportAPIView.as_view(), name='rapport'),
    path('rapport/', RapportAPIListView.as_view(), name='rapport_list'),
    path('rapport_user/<int:id>', RapportByUserAPIView.as_view(), name='rapport_user'),
    path('rapport_zone/', RapportOnZoneAPIView.as_view(), name='rapport_zone'),
    # URL for views participate
    path('participate/<int:id>', ParticipateAPIView.as_view(), name='community'),
    path('participate/', ParticipateAPIListView.as_view(), name='community'),
    # URL for views Elu
    path('community/<int:id>', EluAPIListView.as_view(), name='community'),
    path('community/', EluToZoneAPIListView.as_view(), name='community'),
    # URL for views citizen
    path('community/<int:id>', CitizenAPIListView.as_view(), name='community'),
    # URL for views zone
    path('zone/<int:id>', ZoneAPIView.as_view(), name='zone'),
    path('zone/', ZoneAPIListView.as_view(), name='zone_list'),
    # URL for views message
    path('message/<int:id>', MessageAPIView.as_view(), name='message'),
    path('message/', MessageAPIListView.as_view(), name='message_list'),
    path('message/', MessageByComAPIView.as_view(), name='message_com'),
    path('message_user/', MessageByUserAPIView.as_view(), name='message_user'),
    path('message/<zone>', MessageByZoneAPIView.as_view(), name='message_zone'),
    path('response_msg/', ResponseMessageAPIListView.as_view(), name='response_msg'),
    path('response_msg/<int:id>', ResponseMessageAPIView.as_view(), name='response_msg'),
    # URL for views category
    path('category/<int:id>', CategoryAPIView.as_view(), name='category'),
    path('category/', CategoryAPIListView.as_view(), name='message_list'),
    # URL for views indicator
    path('indicator/', IndicateurAPIListView.as_view(), name='indicator'),
    path('indicator/<int:id>', IndicateurAPIView.as_view(), name='indicator'),
    path('indicator_incident/', IndicateurOnIncidentAPIListView.as_view(), name='indicator_incident'),
    path('indicator_incident_zone/<zone>', IndicateurOnIncidentByZoneAPIView.as_view(), name='indicator_incident_zone'),
    path('indicator_incident_elu/<int:id>', IndicateurOnIncidentByEluAPIView.as_view(), name='indicator_incident_elu'),
    # URL for views imageBackground
    path('image/', ImageBackgroundAPIListView.as_view(), name='image'),
    path('image/<int:id>', ImageBackgroundAPIView.as_view(), name='image'),
    # URL for views password
    path('password/', PasswordResetRequestView.as_view(), name='passwordRequest'),
    path('password_reset/', PasswordResetView.as_view(), name='passwordReset'),
    path('change_password/', ChangePasswordView.as_view(), name='change_password'),
    path('updatePoint/', UpdatePointAPIListView.as_view(), name='updatePoint'),
]
