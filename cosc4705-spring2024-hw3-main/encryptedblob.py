import base64
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import imexceptions


class EncryptedBlob:

    # the constructor
    def __init__(self, plaintext=None, confkey=None, authkey=None): 
        self.plaintext = plaintext
        self.ivBase64 = None
        self.ciphertextBase64 = None
        self.macBase64 = None

        if plaintext is not None:
            self.ivBase64, self.ciphertextBase64, self.macBase64 = self.encryptThenMAC(confkey, authkey, plaintext)


    def encryptThenMAC(self,confkey,authkey,plaintext):

        if confkey is None or authkey is None:
            raise ValueError("confkey and authkey cannot be None!")  

        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(confkey, AES.MODE_CBC, iv)

        # I changed this to AESs blcok size to kind of standardize it with the rest of the code and it made
        # more sense to me as I learned more about the AES. It seemed the best way to make sure everything was correct
        # without hardcoding values.
        plaintextPadded = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(plaintextPadded)  

        hmac = HMAC.new(authkey, digestmod=SHA256)
        hmac.update(ciphertext)
        mac = hmac.digest()

        ivBase64 = base64.b64encode(iv).decode("utf-8") 
        ciphertextBase64 = base64.b64encode(ciphertext).decode("utf-8") 
        macBase64 = base64.b64encode(mac).decode("utf-8") 
        
        return ivBase64, ciphertextBase64, macBase64


    def decryptAndVerify(self,confkey,authkey,ivBase64,ciphertextBase64,macBase64):

        if confkey is None or authkey is None:
            raise ValueError("confkey and authkey cannot be None!")        

        iv = base64.b64decode(ivBase64)
        ciphertext = base64.b64decode(ciphertextBase64)
        mac = base64.b64decode(macBase64)


        hmac = HMAC.new(authkey, digestmod=SHA256)
        hmac.update(ciphertext)

        try:
            hmac.verify(mac)
        
        except ValueError:
            raise imexceptions.FailedAuthenticationError("ruh oh! The MAC was not verified!!!")
        
        cipher = AES.new(confkey, AES.MODE_CBC, iv)
        plaintextPadded = cipher.decrypt(ciphertext)

        try:
            plaintext = unpad(plaintextPadded, AES.block_size).decode('utf-8')

        except ValueError:
            raise imexceptions.FailedDecryptionError("ruh oh! This was not decrypted!!!")

        
        self.plaintext = plaintext 
        return self.plaintext
