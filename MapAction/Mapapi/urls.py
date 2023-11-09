from django.urls import path
from Mapapi import views

urlpatterns = [
    path('', views.login),

]
