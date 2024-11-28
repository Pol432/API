from django.urls import path
from .views import (
    UserRegister,
    UserLogin,
    UserLogout,
    ReportGet
)

urlpatterns = [
    path('register', UserRegister.as_view(), name='register'),
    path('login', UserLogin.as_view(), name='login'),
    path('logout', UserLogout.as_view(), name='logout'),
    path('report/<int:report_id>', ReportGet(), name='report')
]
