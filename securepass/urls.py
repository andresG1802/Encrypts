from django.urls import path
from .views import SecurePassView

urlpatterns = [
    path('securepass/', SecurePassView.as_view(), name='securepass'),
]
