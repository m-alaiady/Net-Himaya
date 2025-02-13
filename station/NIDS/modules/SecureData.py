from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import zlib
import json
import base64

class SecureData:
    def __init__(self, data, key, operation):
        self.data = data
        self.key = key
        self.operation = operation

        if(self.operation == "Encryption"):
            self.result = self.__encrypt_data()
        elif(self.operation == 'Decryption'):
            self.result = self.__decrypt_data()
        else:
            print(f"[!] Unknown operation")

    
    def __encrypt_data(self):
        # Get data
        data_json = json.dumps(self.data).encode('utf-8')
        
        # Generate a random IV
        iv = get_random_bytes(AES.block_size)
        # Get AES object
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        # Encrypt data by using AES encryption
        encrypted_data = cipher.encrypt(pad(data_json, AES.block_size))

        # Perform CRC 
        crc = zlib.crc32(encrypted_data) & 0xFFFFFFFF

        # prepare the payload
        return json.dumps({
            "header": {
                "crc": crc,
                "encryption": "AES",
                "iv": base64.b64encode(iv).decode('utf-8')
            },
            "data": base64.b64encode(encrypted_data).decode('utf-8')
        })

    
    def __decrypt_data(self):
        try:
            # Get data
            encrypted_data = json.loads(self.data)
            # print(f"[!] IV {encrypted_data['header']['iv']}")
            
            # Decrypt the data and decode it
            iv = base64.b64decode(encrypted_data['header']['iv'])
            encrypted_payload = base64.b64decode(encrypted_data['data'])
            
            # Validate CRC value
            calculated_crc = zlib.crc32(encrypted_payload) & 0xFFFFFFFF
            if calculated_crc != encrypted_data['header']['crc']:
                raise ValueError("CRC mismatch: Data may be corrupted or tampered with.")
            
            # Decrypt the data
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_payload), AES.block_size)
            
            # Convert it to JSON
            return json.loads(decrypted_data.decode('utf-8'))
        
        except Exception as e:
            # if decryption process failed raise an error
            raise ValueError(f"Decryption failed: {e}")


