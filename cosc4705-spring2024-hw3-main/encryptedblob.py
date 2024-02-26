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



    # encrypts the plaintext and adds a SHA256-based HMAC
    # using an encrypt-then-MAC solution
    def encryptThenMAC(self,confkey,authkey,plaintext):
        # TODO: MODIFY THE CODE BELOW TO ACTUALLY ENCRYPT 
        # AND GENERATE A SHA256-BASED HMAC BASED ON THE 
        # confkey AND authkey

        cipher = AES.new(confkey, AES.MODE_CBC, iv)

        # pad the plaintext to make AES happy
        plaintextPadded = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(plaintextPadded)  
        iv = get_random_bytes(AES.block_size)

        hmac = HMAC.new(authkey, digestmod=SHA256)
        hmac.update(ciphertext)
        mac = hmac.digest()


        mac = bytes([0x00, 0x00, 0x00, 0x00]) # and this too!

        # DON'T CHANGE THE BELOW.
        # What we're doing here is converting the iv, ciphertext,
        # and mac (which are all in bytes) to base64 encoding, so that it 
        # can be part of the JSON EncryptedIM object
        ivBase64 = base64.b64encode(iv).decode("utf-8") 
        ciphertextBase64 = base64.b64encode(ciphertext).decode("utf-8") 
        macBase64 = base64.b64encode(mac).decode("utf-8") 
        return ivBase64, ciphertextBase64, macBase64


    def decryptAndVerify(self,confkey,authkey,ivBase64,ciphertextBase64,macBase64):
        iv = base64.b64decode(ivBase64)
        ciphertext = base64.b64decode(ciphertextBase64)
        mac = base64.b64decode(macBase64)
        
        # TODO: MODIFY THE CODE BELOW TO ACTUALLY DECRYPT
        # IF IT DOESN'T DECRYPT, YOU NEED TO RAISE A 
        # FailedDecryptionError EXCEPTION



        # TODO: hint: in encryptThenMAC, I padded the plaintext.  You'll
        # need to unpad it.
        # See https://pycryptodome.readthedocs.io/en/v3.11.0/src/util/util.html#crypto-util-padding-module

        # so, this next line is definitely wrong.  :)
    
        
        # TODO: DON'T FORGET TO VERIFY THE MAC!!!
        # IF IT DOESN'T VERIFY, YOU NEED TO RAISE A
        # FailedAuthenticationError EXCEPTION

        hmac = HMAC.new(authkey, digestmod=SHA256)
        hmac.update(ciphertext)

        try:
            hmac.verify(mac)
        
        except ValueError:
            raise imexceptions.FailedAuthenticationError("ruh oh! The MAC was not verified!!!")
        
        cipher = AES.new(confkey, AES.MODE_CBC, iv)
        

        return self.plaintext
