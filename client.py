#socket: Provides the low-level networking interface.
#threading: Allows the server and client to handle sending and receiving messages concurrently.
import socket
import threading
import time
import base64 
from cryptography.hazmat.primitives import hashes, hmac
from Crypto.Util.Padding import pad
from crypto_utils import ( 
generate_rsa_keypair, decrypt_with_rsa, 
encrypt_with_aes, decrypt_with_aes 
) 
import json

import curses
from curses import wrapper
from curses.textpad import Textbox, rectangle
from curses_console_app import CursesConsoleApp

#SERVER_IP: ‘0.0.0.0’ means the server listens on all available network interfaces.
#SERVER_PORT: The port number used for communication.
#BUFFER_SIZE: The size of the data chunks received (1 KB).
SERVER_IP = 'localhost'  # Bind to all interfaces
SERVER_PORT = 12347
BUFFER_SIZE = 4096

class Client(CursesConsoleApp):

    def __init__(self, username, server_addr):
        super().__init__(username=username)
        self.username = username
        self.server_addr = server_addr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.aes_key = None
        self.hmac_key = None
        self.cached_msg = None
        self.seq = 0
        
        self.private_key, self.public_key = generate_rsa_keypair() 
        self.initialize()
        threading.Thread(target=self.receive_messages, daemon=True).start()
        self.run_client()
    
    def initialize(self):
        self.write_console('Establishing Secure Server Connection...')
        thread_started = False
        timeout = 0
        while self.aes_key is None or self.hmac_key is None: 
            self.write_console('Waiting for server Connection...')
            self.sock.sendto(base64.b64encode(self.public_key), self.server_addr)
            if not thread_started:
                threading.Thread(target=self.wait_for_initial_response, daemon=True).start()
                thread_started = True
            time.sleep(0.3)
            timeout += 0.3
            if timeout > 10:
                self.write_console('ERROR: Connection could not be established. Quitting in 5 seconds...')
                time.sleep(5)
                raise RuntimeError('Connection Could Not be Established with Server')
            
        self.write_console('Done!')
    
    def wait_for_initial_response(self):
        data, _ = self.sock.recvfrom(4096)
        self.aes_key = decrypt_with_rsa(self.private_key, data)
        self.write_console("Received and decrypted AES key.") 
        data, _ = self.sock.recvfrom(4096)
        self.hmac_key = bytes.fromhex(decrypt_with_aes(self.aes_key, data))
        self.write_console(f'Received HMAC key')          

    # Function to receive messages concurrently
    def receive_messages(self):
        while True: 
            data, _ = self.sock.recvfrom(4096) 
            if self.aes_key is None: 
                encrypted_key = base64.b64decode(data) 
                self.aes_key = decrypt_with_rsa(self.private_key, encrypted_key) 
                self.write_console("Received and decrypted AES key.") 
            elif self.hmac_key is None:
                self.hmac_key = bytes.fromhex(decrypt_with_aes(self.aes_key, data))
                self.write_console(f'Received HMAC key')
            else:
                try:
                    msg = json.loads(decrypt_with_aes(self.aes_key, data))
                    if msg['msg_type'] == 'msg':
                        h = hmac.HMAC(self.hmac_key, hashes.SHA256())
                        h.update(msg['msg'].encode())
                        if h.finalize() == bytes.fromhex(msg['hmac']):
                            self.write_console(f'[HMAC Verified] {msg["msg"]}')
                        
                        # Send ACK
                        ack = {}
                        ack['msg_type'] = 'ack'
                        ack['seq'] = msg['seq'] + len(msg['msg'])
                        encrypted = encrypt_with_aes(self.aes_key, json.dumps(ack)).encode()
                        self.sock.sendto(encrypted, self.server_addr)
                    elif msg['msg_type'] == 'ack':
                        self.seq = msg['seq']
                except Exception as e:
                    self.write_console('Decryption Failed!')
                    self.write_console(e)
    
    # Client chat function
    #Creates a UDP socket for the client to communicate with the server.
    def run_client(self):
        # Start the receiving thread
        # Sending messages from the main thread
        while True:
            try:
                message = self.get_input().strip()
                if self.aes_key:
                    h = hmac.HMAC(self.hmac_key, hashes.SHA256())
                    h.update(f'{self.username}: {message}'.encode())
                    finalize = h.finalize()

                    deliverable = {}
                    deliverable['msg'] = f'{self.username}: {message}'
                    deliverable['hmac'] = finalize.hex()
                    deliverable['seq'] = self.seq
                    deliverable['msg_type'] = 'msg'

                    encrypted = encrypt_with_aes(self.aes_key, json.dumps(deliverable)).encode()
                    desired_seq = self.seq + len(f'{self.username}: {message}')
                    retries = 0
                    while self.seq != desired_seq:
                        self.sock.sendto(encrypted, self.server_addr)
                        time.sleep(0.3)
                        retries += 1
                        if retries >= 3:
                            self.write_console(f'NO ACK RECEIVED FROM {self.server_addr}')
                            break
                    if self.seq == desired_seq:
                        self.write_console(msg=f'[You] {self.username}: {message}')
            except Exception as e:
                self.write_console(f"Error sending message: {e}")


def main(stdscr):
    inp = curses.newwin(8,55, 0,0)
    inp.addstr(1,1, "Please enter your username:")
    sub = inp.subwin(3, 34, 2, 1)
    sub.border()
    sub2 = sub.subwin(1, 32, 3, 2)
    tb = curses.textpad.Textbox(sub2)
    inp.refresh()
    tb.edit()
    # Get resulting contents
    username = tb.gather()
    del inp
    stdscr.touchwin()
    stdscr.refresh()
    c = Client(username.strip().replace('\n',''), (SERVER_IP,SERVER_PORT))


if __name__ == "__main__":
    try:
        wrapper(main)
    except KeyboardInterrupt as k:
        print('Goodbye!')
    except Exception as e:
        print(e)