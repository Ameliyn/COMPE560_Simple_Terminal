'''Create a server for encrypted conmmunication.'''
import base64
import json
import socket 
import threading 
import time

from cryptography.hazmat.primitives import hashes, hmac
from curses import wrapper

from crypto_utils import generate_aes_key, encrypt_with_rsa, decrypt_with_aes, encrypt_with_aes
from curses_console_app import CursesConsoleApp
from russ_chat_message_handler import RussChatMessageHandler

#SERVER_IP: ‘0.0.0.0’ means the server listens on all available network interfaces.
#SERVER_PORT: The port number used for communication.
#BUFFER_SIZE: The size of the data chunks received (4 KB).
SERVER_IP = 'localhost'  # Bind to all interfaces
SERVER_PORT = 12347
BUFFER_SIZE = 4096    


class Server(CursesConsoleApp, RussChatMessageHandler):
    def __init__(self, server_addr):
        '''Initialize the Server.
        
        Params: 
            server_addr: tuple Server IP and port to bind to.
        '''
        RussChatMessageHandler.__init__(self)
        CursesConsoleApp.__init__(self, username='Server')
        self.server_addr = server_addr
        self.clients = {}
        self.client_keys = {}
        self.client_hmac_keys = {}
        self.hmac = {}
        self.seq = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
        self.sock.bind(self.server_addr) 
        
        self.write_console(f"Server started on {self.server_addr[0]}:{self.server_addr[1]}")        
        threading.Thread(target=self.handle_messages, daemon=True).start()
        self.run_server()
    
    def handle_messages(self): 
        '''
        Handle receiving messages.
        '''
        while True: 
            data, addr = self.sock.recvfrom(BUFFER_SIZE) 
            if addr in self.clients:
                try:
                    # Convert message to JSON dictionary after decoding
                    msg = json.loads(decrypt_with_aes(self.clients[addr], data))

                    if msg['msg_type'] == 'msg':
                        h = hmac.HMAC(self.client_hmac_keys[addr], hashes.SHA256())
                        h.update(msg['msg'].encode())

                        # Verify message with HMAC
                        if h.finalize() == bytes.fromhex(msg['hmac']):
                            self.write_console(f'[HMAC Verified] [{addr}] {msg["msg"]}')
                        else:
                            self.write_console(f'WARNING: HMAC VERIFICATION FAILED FOR: [{addr}]')
                        
                        # Send Acknowledgement
                        ack = {}
                        ack['msg_type'] = 'ack'
                        ack['seq'] = msg['seq'] + len(msg['msg'])
                        encrypted = encrypt_with_aes(self.clients[addr], json.dumps(ack)).encode()
                        self.sock.sendto(encrypted, addr)

                        # Propagate message to all other clients.
                        self.broadcast_message(msg['msg'], exclude_addr=addr)
                    elif msg['msg_type'] == 'ack':
                        self.seq[addr] = msg['seq']
                except Exception as e:
                    self.write_console(f'Message malformed from {addr}')
            else:
                self.initialize_client(data, addr)
                
    def initialize_client(self, data: bytes, addr: tuple):
        '''
        Initialize a client.

        Params:
            data: base64 RSA Public key for a client
            addr: Client address
        '''
        try:
            rsa_pub_key = base64.b64decode(data) 
            self.clients[addr] = generate_aes_key()
            self.client_keys[addr] = rsa_pub_key 
            self.client_hmac_keys[addr] = generate_aes_key() # Set the HMAC secret to 128 random bytes
            self.seq[addr] = 0
            
            self.sock.sendto(encrypt_with_rsa(rsa_pub_key, self.clients[addr]), addr)
            self.sock.sendto(encrypt_with_aes(self.clients[addr], self.client_hmac_keys[addr].hex()).encode(), addr)
            self.write_console(f"Key exchanged with {addr}")
        except Exception as e:
            self.write_console(f'Initialization failed for {addr}')
            self.write_console(e)

    def broadcast_message(self, msg: str, exclude_addr=None):
        '''
        Broadcast a message to all clients (except the excluded)
        
        Params:
            msg: string message to broadcast
            exclude_addr: client to be excluded
        '''
        for client_addr, aes_key in self.clients.items():
            if client_addr == exclude_addr:
                continue
            h = hmac.HMAC(self.client_hmac_keys[client_addr], hashes.SHA256())
            h.update(msg.encode())
            finalize = h.finalize()
            encrypted = encrypt_with_aes(aes_key, msg).encode()

            deliverable = {}
            deliverable['msg'] = msg
            deliverable['hmac'] = finalize.hex()
            deliverable['seq'] = self.seq[client_addr]
            deliverable['msg_type'] = 'msg'

            encrypted = encrypt_with_aes(aes_key, json.dumps(deliverable)).encode()
            desired_seq = self.seq[client_addr] + len(msg)
            threading.Thread(target=self.send_msg_with_ack, 
                             args=[encrypted, desired_seq, client_addr, 3], 
                             daemon=True).start()
            
    def send_msg_with_ack(self, encrypted_msg: bytes, desired_seq: int, client_addr: tuple, retries=3):
        '''
        Sends a message and waits for acknowledgements

        Params:
            encrypted_msg: bytes to be sent
            desired_seq: desired sequence number of acknowledgement
            client_addr: address to send the message
            retries: Number of retries (default: 3)
        '''
        retries = 0
        while desired_seq != self.seq[client_addr]:
            self.sock.sendto(encrypted_msg, client_addr)
            time.sleep(0.3)
            retries += 1
            if retries >= 3:
                self.write_console(f'NO ACK RECEIVED FROM {client_addr}')
                break

    def run_server(self):
        '''Allow the server to get input from the console and send it to the clients.'''
        while True:
            try:
                message = self.get_input().strip()
                self.write_console(f"[You] Server: {message}")
                # Broadcast the message
                self.broadcast_message(f'{self.username}: {message}')
            except Exception as e:
                self.write_console(f"Error receiving message: {e}")


def main(_):
    s = Server((SERVER_IP,SERVER_PORT))


if __name__ == "__main__":
    try:
        wrapper(main)
    except KeyboardInterrupt as k:
        print('Goodbye!')
    except Exception as e:
        print(e)