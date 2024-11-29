from django.shortcuts import render

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from securepass.Encrypt import EncryptsMain , Desencryptar

class SecurePassView(APIView):

    # permission_classes = [HasAPIKey]  # Requiere una API Key válida


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
class DecryptView(APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        ciphertext_hex = data.get("ciphertext_hex")
        key_hex = data.get("key_hex")
        iv_hex = data.get("iv_hex")

        if not all([ciphertext_hex, key_hex, iv_hex]):
            return Response({"error": "Missing ciphertext, key, or IV"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Llamada a la función de desencriptado
            decrypted_message = Desencryptar(ciphertext_hex, key_hex, iv_hex)
            if decrypted_message is None:
                return Response({"error": "Decryption failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({"decrypted_message": decrypted_message}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)