import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# 1. Matriz de transformación y su inversa
transformation_matrix = np.array([
    [3, 1, 4],
    [1, 5, 9],
    [2, 6, 5]
])

# Calcular la inversa de la matriz
inverse_transformation_matrix = np.linalg.inv(transformation_matrix)


# 2. Transformación lineal
def linear_transform(data: str) -> np.ndarray:
    """
    Aplica una transformación lineal al texto de entrada, manejando el texto en bloques.
    """
    # Convertir el texto en un vector numérico (ASCII)
    data_vector = np.array([ord(c) for c in data])
    block_size = transformation_matrix.shape[1]  # Tamaño del bloque según las columnas de la matriz

    # Dividir el vector en bloques
    blocks = [
        data_vector[i:i + block_size]
        for i in range(0, len(data_vector), block_size)
    ]

    # Rellenar el último bloque si no es completo
    if len(blocks[-1]) < block_size:
        blocks[-1] = np.pad(blocks[-1],
                            (0, block_size - len(blocks[-1])),
                            mode='constant')

    # Aplicar la transformación lineal a cada bloque
    transformed_blocks = [np.dot(transformation_matrix, block) for block in blocks]

    # Combinar los bloques transformados en un solo vector
    transformed_vector = np.concatenate(transformed_blocks)
    return transformed_vector

# 2. Transformación lineal reversa (Inversa de la matriz)
def reverse_linear_transform(transformed_vector: np.ndarray) -> str:
    """
    Invierte la transformación lineal para recuperar el texto original, manejando bloques.
    """
    block_size = transformation_matrix.shape[1]  # Tamaño del bloque según las columnas de la matriz
    num_blocks = len(transformed_vector) // transformation_matrix.shape[0]  # Cantidad de bloques

    # Dividir el vector transformado en bloques
    blocks = np.split(transformed_vector, num_blocks)

    # Aplicar la matriz inversa a cada bloque
    original_blocks = [
        np.dot(inverse_transformation_matrix, block).round().astype(int)
        for block in blocks
    ]

    # Combinar los bloques originales en un solo vector
    original_vector = np.concatenate(original_blocks)

    # Convertir de nuevo a caracteres
    original_text = ''.join(map(chr, original_vector))
    return original_text

# 3. Encriptación con PyCryptodome
def encrypt_with_aes(data: np.ndarray, key: bytes, iv: bytes) -> bytes:
    """
    Cifra un vector numérico utilizando AES.
    """
    # Convertir el vector en bytes
    data_bytes = data.astype(np.int32).tobytes()  # Convertir a bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data_bytes, AES.block_size))
    return ciphertext

def decrypt_with_aes(ciphertext: bytes, key: bytes, iv: bytes) -> np.ndarray:
    """
    Descifra los datos cifrados con AES y los convierte de vuelta en un vector numérico.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
    # Convertir de bytes a vector numérico
    decrypted_vector = np.frombuffer(decrypted_bytes, dtype=np.int32)
    return decrypted_vector

def EncryptsMain(plaintext):
    

    # Clave y IV para AES
    key = get_random_bytes(16)  # Clave de 128 bits
    iv = get_random_bytes(16)   # Vector de inicialización

    # Transformación lineal
    transformed_vector = linear_transform(plaintext)
    # print("Vector transformado:", transformed_vector)

    # Encriptar con AES
    ciphertext = encrypt_with_aes(transformed_vector, key, iv)
    # print("Texto encriptado (AES):", ciphertext.hex())


    return ciphertext.hex()
    # # Desencriptar con AES
    # decrypted_vector = decrypt_with_aes(ciphertext, key, iv)
    # print("Vector desencriptado:", decrypted_vector)

    # # Revertir la transformación lineal
    # original_text = reverse_linear_transform(decrypted_vector)
    # print("Texto original:", original_text)

