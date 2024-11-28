from django.shortcuts import render

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from securepass.Encrypt import EncryptsMain

class SecurePassView(APIView):

    permission_classes = [HasAPIKey]  # Requiere una API Key válida


    def post(self, request, *args, **kwargs):
        # Verifica que el JSON contiene la clave "password"
        password = request.data.get("password")
        if not password:
            return Response(
                {"error": "The 'password' field is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Procesa el password usando EncryptsMain
        encrypted_password = EncryptsMain(password) # Ajusta según la lógica de tu clase

        # Retorna la respuesta con el password encriptado
        return Response(
            {"message": "Secure access granted!", "encrypted_password": encrypted_password},
            status=status.HTTP_200_OK
        )
