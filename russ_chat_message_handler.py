from crypto_utils import ( 
generate_rsa_keypair, decrypt_with_rsa, 
encrypt_with_aes, decrypt_with_aes 
) 
from Crypto.Util.Padding import pad, unpad 
from cryptography.hazmat.primitives import hashes, hmac



class RussChatMessageHandler():
    class Connection():
        '''A storage class that contains keys, secrets, and sequences for a given connection.'''
        def __init__(self, 
                     rsa_key = None, 
                     sequence = 0, 
                     aes_key = None, 
                     hmac_secret = None):
            '''Initialize a connection with passed parameters.
            
            Params:
                rsa_key: RSA Key
                sequence: Initial sequence number
                aes_key: AES key
                hmac_secret: HMAC Secret
            '''
            self._rsa = rsa_key
            self._aes_key = aes_key
            self._hmac_secret = hmac_secret
            self._seq = sequence
        
        @property
        def rsa(self):
            return self._rsa
        
        @rsa.setter
        def rsa(self, val):
            self._rsa = val

        @property
        def aes_key(self):
            return self._aes_key
        
        @aes_key.setter
        def aes_key(self, val):
            self._aes_key = val

        @property
        def hmac_secret(self):
            return self._hmac_secret
        
        @hmac_secret.setter
        def hmac_secret(self, val):
            self._hmac_secret = val

        @property
        def seq(self):
            return self._seq
        
        @seq.setter
        def seq(self, val):
            self._seq = val

    def __init__(self, connections: dict[tuple, Connection] = {}):
        self._connections = connections
        self.rsa_private_key, self.rsa_public_key = generate_rsa_keypair()

    @property
    def connections(self):
        return self._connections
    
    def create_connection(self, 
                          addr: tuple, 
                          sequence = 0, 
                          rsa_key = None, 
                          aes_key = None, 
                          hmac_secret = None):
        '''Create a connection for the given address.
        
        WARNING: If a duplicate address is provided, it will overwrite a previous connection.
        '''
        self.connections[addr] = RussChatMessageHandler.Connection(
            rsa_key=rsa_key, sequence=sequence, 
            aes_key=aes_key, hmac_secret=hmac_secret
        )

    #
    # Message Creation Functions
    #
    def create_con_req_message(self, addr: tuple) -> bytes:
        '''Create a new connection request message 
        
        (This uses the stored private RSA key)
        '''
        return self._create_message(msg_type=0,
                                    seq=self.connections[addr].seq,
                                    flags=1,
                                    payload=self.connections[addr].rsa)

    def create_con_ack_message(self, addr: tuple):
        '''Create a new connection acknowledgemennt message.
        
        (This uses the stored HMAC and AES keys)
        '''
        return self._create_message(msg_type=1,
                                    seq=self.connections[addr].seq,
                                    flags=1,
                                    payload=self.connections[addr].rsa)

    def create_data_message(self, addr, payload: bytes):
        '''Create a standard data message with the given flags (default AES encrypted)

        Params:
            addr: Address for data message
            payload: Bytes of data
        '''
        if self.connections[addr].aes_key is None or self.connections[addr].hmac_secret is None:
            raise RuntimeError('Connection Acknowledgement attempted before AES Key or HMAC Secret set.')
        
        # Generate HMAC Encryption
        hmac_encryption = hmac.HMAC(self.connections[addr].hmac_secret, hashes.SHA256())
        hmac_encryption.update(payload)
        self.connections[addr].seq += len(payload)
        # Return generated message bytes
        return self._create_message(msg_type=2,
                                    seq=self.connections[addr].seq - len(payload),
                                    flags=12,
                                    hmac=hmac_encryption,
                                    payload=encrypt_with_aes(self.connections[addr].aes_key, payload.hex()))
    
    def check_hmac_validation(self, addr: tuple, payload: bytes, received_hmac: bytes) -> bool:
        '''Check if the given hmac bytes are valid for the payload and address.
        
        Params:
            addr: Address of the receiver
            payload: Bytes of the message
            received_hmac: hmac value
        '''
        hmac_encryption = hmac.HMAC(self.connections[addr].hmac_secret, hashes.SHA256())
        hmac_encryption.update(payload)
        return received_hmac == hmac_encryption.finalize()

    def create_ack_message(self, seq: int) -> bytes:
        '''Create an acknowledgement message for the given sequence number.
        
        Params:
            seq: Sequence number to acknowledge
        '''
        # Return generated message bytes
        return self._create_message(3,seq=seq, flags=8)

    def _create_message(self, msg_type: int = 2, seq: int = 0, flags: int = 0, hmac: bytes = None, payload: bytes = None) -> bytes:
        '''Create a bytes message with the given parameters.

        Params:
            msg_type: Message Type (0 - Connection Request, 1 - Connection Acknowledgement, 2 - Data, 3 - Acknowledgement)
            seq: Sequence Number
            flags: Message Flags (Bits Set: 0 - Payload Unencrypted, 1 - Payload RSA encrypted, 2 - Payload AES Encrypted, 3 - HMAC Valid)
            hmac: HMAC Verification Bytes (length == 0 or length == 32)
            payload: Payload in bytes
        '''
        if hmac is None:
            i = 0
            hmac = i.to_bytes(32, 'big')
        if len(hmac) != 32:
            raise RuntimeError(f'HMAC bytes bad length: {len(hmac)} != 32')
        if payload is not None and size != 0 and len(payload) != size:
            raise RuntimeError(f'Size of Payload does not match size parameter: {len(payload)} != {size}')
        
        result = bytearray()
        result.extend(msg_type.to_bytes(1, 'big')) # 1 Byte
        result.extend(seq.to_bytes(2, 'big')) # 2 Bytes
        result.extend(flags.to_bytes(1, 'big')) # 1 Byte
        if payload is None:
            size = 0
        result.extend(size.to_bytes(2, 'big')) # 2 Bytes
        result.extend(hmac) # 32 Bytes
        if size > 0:
            result.extend(payload)
        return result

    def _decode_message(self, addr: tuple, data: bytes) -> dict:
        '''Decode a message and return a dictionary with the components.'''
        # Decode Message Portions
        result = {}
        result['msg_type'] = int.from_bytes(data[0], 'big')
        result['seq'] = int.from_bytes(data[1:2], 'big') # 2 Bytes
        result['flags'] = bin(int.from_bytes(data[3], 'big'))[2:].zfill(8) # 1 Byte
        result['size'] = int.from_bytes(data[4:5], 'big') # 2 Bytes
        if result['flags'][-4] == '1':
            result['hmac'] = data[6:38] # 32 Bytes
        else:
            result['hmac'] = None
        
        if result['flags'][-1] == '1':
            result['payload'] = data[39:39+result['size']]
        elif result['flags'][-2] == '1':
            result['payload'] = decrypt_with_rsa(self.rsa_private_key, data[39:39+result['size']])
        elif result['flags'][-3] == '1':
            if self.connections[addr].aes_key is None:
                raise RuntimeError('Message Encrypted but AES key not present. Message decryption failed.')
            result['payload'] = decrypt_with_aes(self.connections[addr].aes_key, data[39:39+result['size']])
        return result
        