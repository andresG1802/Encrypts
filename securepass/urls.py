from django.urls import path
from .views import SecurePassView ,DecryptView

urlpatterns = [
    path('securepass/', SecurePassView.as_view(), name='securepass'),
    path('decrypt/', DecryptView.as_view(), name='decrypt'),  # Nueva ruta para desencriptar
    
]
