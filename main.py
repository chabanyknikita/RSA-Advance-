 from Crypto.PublicKey import RSA
 from Crypto.Random import get_random_bytes
 from Crypto.Cipher import AES, PKCS1_OAEP


 def generate_public_and_private_key():
     key = RSA.generate(2048)
     private_key = key.export_key()
     file_out = open("private_key.pem", "wb")
     file_out.write(private_key)
     file_out.close()

     public_key = key.publickey().export_key()
     file_out = open("public_key.pem", "wb")
     file_out.write(public_key)
     file_out.close()


 a = input("Write text, which you want to encrypt: ")

 clear = lambda: print('\n' * 100)
 clear()


 def encrypted_data_rsa():
     data = a.encode("utf-8")
     file_out = open("encrypted_data.bin", "wb")

     recipient_key = RSA.import_key(open("public_key.pem").read())
     session_key = get_random_bytes(16)

     # Encrypt the session key with the public RSA key
     cipher_rsa = PKCS1_OAEP.new(recipient_key)
     enc_session_key = cipher_rsa.encrypt(session_key)

     # Encrypt the data with the AES session key
     cipher_aes = AES.new(session_key, AES.MODE_EAX)
     ciphertext, tag = cipher_aes.encrypt_and_digest(data)
     [file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
     file_out.close()


 def decrypted_data_rsa():
     file_in = open("encrypted_data.bin", "rb")

     private_key = RSA.import_key(open("private_key.pem").read())

     enc_session_key, nonce, tag, ciphertext = \
         [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

     # Decrypt the session key with the private RSA key
     cipher_rsa = PKCS1_OAEP.new(private_key)
     session_key = cipher_rsa.decrypt(enc_session_key)

     # Decrypt the data with the AES session key
     cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
     data = cipher_aes.decrypt_and_verify(ciphertext, tag)
     print(data.decode("utf-8"))


 generate_public_and_private_key()
 encrypted_data_rsa()
 decrypted_data_rsa()
