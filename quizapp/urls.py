from django.urls import path, include
from . import views


urlpatterns = [
    path("", views.index),
    
    path("register", views.register_request, name="register"),
    path("login", views.login_request, name="login"),
    path("logout", views.logout_request, name = "logout"),
    path("password_reset", views.password_reset_request, name="password_reset"),
]