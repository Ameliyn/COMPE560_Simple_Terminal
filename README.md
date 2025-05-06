# COMPE 560 Secure UDP Chat Service

Prepared by Skye Russ

## Instructions

1. run `python server.py`
2. run `python client.py`
3. Have fun!

## Implementation

The initial RSA keys are generated using Crypto.PublicKey.RSA.generate() with 2048 length. 
The AES keys are 16 random bytes.
The HMAC secret is also 16 random bytes for each client. The selected HMAC hashing algorithm is "SHA256"

On startup, the client pings the server with their RSA public key and the server responds with the 
AES encrypted secret that is encrypted using RSA. It also then uses AES encryption to send along the 
HMAC mutual shared secret. This secret could be passed by file as well, but for ease of use it is passed
in the initialization phase.

Both the client and the server use AES encryption passed with HMAC verification bytes to verify the identity of
the sender.

## Limitations

1. This code was designed and tested in an **ubuntu 22.04 linux docker container** (provided). I can not guarantee it works on other operating systems.
   The provided Dockerfile and `docker_start.bat` provide a simple way to run the code, but it should work on any linux distribution provided the packages
   in `requirements.txt` are installed. (Those requirements are cryptography and PyCryptodome)
2. If a bad actor captured the initialization of nodes, they could potentially break the encryption/verification scheme because the HMAC key is sent over the network.
3. This module uses the JSON package for easy conversion between JSON dictionaries to strings and back for convienence.