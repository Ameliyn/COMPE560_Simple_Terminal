from crypto_utils import (
generate_rsa_keypair, decrypt_with_rsa,
encrypt_with_rsa, generate_aes_key,
encrypt_bytes_with_aes, decrypt_bytes_with_aes
)
from cryptography.hazmat.primitives import hashes, hmac


class RussChatMessageHandler():
    '''A class that handles the custom protocol information for encrypted packets.'''
    class Connection():
        '''A storage class that contains keys, secrets, and sequences for a given connection.'''
        def __init__(self,
                     rsa_key = None,
                     tx_seq = 0,
                     rx_seq = 0,
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
            self._tx_seq = tx_seq
            self._rx_seq = rx_seq

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
        def tx_seq(self) -> int:
            return self._tx_seq

        @tx_seq.setter
        def tx_seq(self, val: int):
            self._tx_seq = val

        @property
        def rx_seq(self) -> int:
            return self._rx_seq

        @rx_seq.setter
        def rx_seq(self, val: int):
            self._rx_seq = val

    def __init__(self, connections: dict[tuple, Connection] = {}):
        '''Initialize a Chat Message Handler with passed connections.

        Params:
            connections: dictionary of connections to begin with
        '''
        self._connections = connections
        self.rsa_private_key, self.rsa_public_key = generate_rsa_keypair()
        # raise RuntimeError(f'Message Handler Started {self.connections}')

    @property
    def connections(self):
        return self._connections

    def create_connection(self,
                          addr: tuple,
                          rx_seq: int = 0,
                          tx_seq: int = 0,
                          rsa_key: bytes = None,
                          aes_key: bytes = None,
                          hmac_secret: bytes = None):
        '''Create a connection for the given address.

        WARNING: If a duplicate address is provided, it will overwrite a previous connection.

        Params:
            addr: tuple address
            rx_seq: start receive sequence
            tx_seq: start transmit sequence
            rsa_key: RSA key of host
            aes_key: AES key of host
            hmac_secret: HMAC secret of host
        '''
        self.connections[addr] = RussChatMessageHandler.Connection(
            rsa_key=rsa_key, rx_seq=rx_seq, tx_seq=tx_seq,
            aes_key=aes_key, hmac_secret=hmac_secret
        )

    def initialize_client(self, rsa_key: bytes, addr: tuple):
        '''
        Initialize a client.

        Params:
            rsa_key: base64 RSA Public key for a client
            addr: Client address
        '''
        self.create_connection(
            addr=addr,
            rx_seq=0,
            tx_seq=0,
            rsa_key=rsa_key,
            aes_key=generate_aes_key(),
            hmac_secret=generate_aes_key())

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
    #
    # Message Creation Functions
    #
    def create_con_req_message(self, addr: tuple) -> bytes:
        '''Create a new connection request message

        Params:
            addr: tuple address receiver
        '''
        if self.rsa_private_key is None or self.rsa_public_key is None:
            self.rsa_private_key, self.rsa_public_key = generate_rsa_keypair()
        return self._create_message(addr=addr,
                                    msg_type=0,
                                    seq=self.connections[addr].tx_seq,
                                    flags=1,
                                    payload=self.rsa_public_key)

    def create_con_ack_message(self, addr: tuple):
        '''Create a new connection acknowledgemennt message.

        Params:
            addr: tuple address receiver
        '''
        if addr not in self.connections.keys():
            raise RuntimeError(f'{addr} not found in existing Connections.')
        if self.connections[addr].rsa is None:
            raise RuntimeError('Creating CONACK message for connection without RSA key')
        if self.connections[addr].aes_key is None:
            raise RuntimeError('Creating CONACK message for connection without AES key')
        if self.connections[addr].hmac_secret is None:
            raise RuntimeError('Creating CONACK message for connection without HMAC secret')

        result = bytearray()
        result.extend(self.connections[addr].aes_key)
        result.extend(0b00000001.to_bytes(1, 'big'))
        result.extend(self.connections[addr].hmac_secret)
        return self._create_message(addr=addr,
                                    msg_type=1,
                                    seq=self.connections[addr].tx_seq,
                                    flags=1,
                                    payload=bytes(result))

    def handle_con_ack_message(self, message_dict: dict, addr: tuple):
        '''Decode a CONACK message payload and store the data.

        Params:
            message_dict: CONACK payload
            addr: Tuple address
        '''
        if message_dict['msg_type'] != 1:
            raise RuntimeError(f'Message of wrong type: {message_dict["msg_type"]} != 1')
        self.aes_key = message_dict['payload'][0:16]

        encryption = bin(int.from_bytes(message_dict['payload'][16].to_bytes(1, 'big'), 'big'))[2:].zfill(8)

        # Handle Encryption Flags
        if encryption[-1] == '1':
            self.hmac_secret = message_dict['payload'][17:17+(message_dict['size']-16)]
        elif encryption[-2] == '1':
            self.hmac_secret = decrypt_with_rsa(self.rsa_private_key, message_dict['payload'][17:17+(message_dict['size']-16)])
        elif encryption[-3] == '1':
            if self.aes_key is None:
                raise RuntimeError('Message Encrypted but AES key not present. Message decryption failed.')
            self.hmac_secret = decrypt_bytes_with_aes(self.aes_key, message_dict['payload'][17:17+(message_dict['size']-16)])

        self.create_connection(addr=addr,
                               rx_seq=message_dict['seq'],
                               tx_seq=0,
                               aes_key=self.aes_key,
                               hmac_secret=self.hmac_secret)
    
    def create_reset_message(self, addr):
        '''Create a connection reset message for a given address.
        
        Params:
            addr: Target address
        '''
        if addr in self.connections:
            self.connections.pop(addr)
        return self._create_message(addr=addr, msg_type=4)
    
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
        # Return generated message bytes
        self.connections[addr].tx_seq += len(payload)
        return self._create_message(addr=addr,
                                    msg_type=2,
                                    seq=self.connections[addr].tx_seq,
                                    flags=12,
                                    hmac_bytes=hmac_encryption.finalize(),
                                    payload=payload)

    def create_ack_message(self, addr: tuple, payload: bytes) -> bytes:
        '''Create an acknowledgement message for the given address and payload.

        Params:
            addr: tuple address
            payload: bytes payload
        '''
        # Return generated message bytes
        self.connections[addr].rx_seq += len(payload)
        return self._create_message(addr, msg_type=3,seq=self.connections[addr].rx_seq, flags=0)

    def _create_message(self,
                        addr: tuple,
                        msg_type: int = 2,
                        seq: int = 0,
                        flags: int = 0,
                        hmac_bytes: bytes = None,
                        payload: bytes = None) -> bytes:
        '''Create a bytes message with the given parameters.

        Params:
            addr: tuple address the message will be sent to (used for encryption)
            msg_type: Message Type (0 - Connection Request, 1 - Connection Acknowledgement, 2 - Data, 3 - Acknowledgement)
            seq: Sequence Number
            flags: Message Flags (Bits Set: 0 - Payload Unencrypted, 1 - Payload RSA encrypted, 2 - Payload AES Encrypted, 3 - HMAC Valid)
            hmac: HMAC Verification Bytes (length == 0 or length == 32)
            payload: Unencrypted Payload in Bytes
        '''
        if hmac_bytes is None:
            i = 0
            hmac_bytes = i.to_bytes(32, 'big')
        if len(hmac_bytes) != 32:
            raise RuntimeError(f'HMAC bytes bad length: {len(hmac_bytes)} != 32')
        if payload is None:
            size = 0
        else:
            log_flag = bin(int.from_bytes(flags.to_bytes(1, 'big'), 'big'))[2:].zfill(8)
            if log_flag[-1] == '1':
                encrypted_payload = payload
                # result.extend(payload)
            elif log_flag[-2] == '1':
                encrypted_payload = encrypt_with_rsa(self.rsa_public_key, payload)
                # result.extend(encrypt_with_rsa(self.rsa_public_key, payload))
            elif log_flag[-3] == '1':
                encrypted_payload = encrypt_bytes_with_aes(self.connections[addr].aes_key, payload).encode()
            else:
                raise RuntimeError(f'Encryption flags not set properly {log_flag}')
            size = len(encrypted_payload)

        result = bytearray()
        result.extend(msg_type.to_bytes(1, 'big')) # 1 Byte
        result.extend(seq.to_bytes(2, 'big')) # 2 Bytes
        result.extend(flags.to_bytes(1, 'big')) # 1 Byte
        result.extend(size.to_bytes(2, 'big')) # 2 Bytes
        result.extend(hmac_bytes) # 32 Bytes
        if size == 0:
            return bytes(result)
        result.extend(encrypted_payload)

        return bytes(result)

    def _decode_message(self, addr: tuple, data: bytes) -> dict:
        '''Decode a message and return a dictionary with the components.

        Params:
            addr: tuple origin address
            data: bytes message
        '''
        # Decode Message Portions
        result = {}
        result['msg_type'] = int.from_bytes(data[0].to_bytes(1,'big'), 'big')
        result['seq'] = int.from_bytes(data[1:3], 'big') # 2 Bytes
        result['flags'] = bin(int.from_bytes(data[3].to_bytes(1,'big'), 'big'))[2:].zfill(8) # 1 Byte
        result['size'] = int.from_bytes(data[4:6], 'big') # 2 Bytes
        if result['flags'][-4] == '1':
            result['hmac'] = data[6:38] # 32 Bytes
        else:
            result['hmac'] = None
        if result['size'] == 0:
            return result
        if result['flags'][-1] == '1':
            result['payload'] = data[38:38+result['size']]
        elif result['flags'][-2] == '1':
            result['payload'] = decrypt_with_rsa(self.rsa_private_key, data[38:38+result['size']])
        elif result['flags'][-3] == '1':
            if self.connections[addr].aes_key is None:
                raise RuntimeError('Message Encrypted but AES key not present. Message decryption failed.')
            try:
                result['payload'] = decrypt_bytes_with_aes(self.connections[addr].aes_key, bytes(data[38:38+result['size']]))
            except KeyError as k:
                result['payload'] = None
        else:
            raise RuntimeError(f'Encryption flags not set properly. {result["flags"]}')
        return result
