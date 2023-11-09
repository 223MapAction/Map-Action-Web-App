from django.urls import path
from MapApp import views

urlpatterns = [
    path('', views.loginView),

]
