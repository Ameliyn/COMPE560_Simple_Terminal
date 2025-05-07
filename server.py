'''Create a server for encrypted conmmunication.'''
import socket
import threading
import time

from curses import wrapper

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
            if addr in self.connections.keys():
                try:
                    msg = self._decode_message(addr=addr, data=data)
                    if msg['msg_type'] == 0:
                        # Handle CONREQ Message
                        self.write_console(f'Received CONREQ for existiong client: [{addr}]. Sending CONACK')
                        self.initialize_client(rsa_key=msg['payload'], addr=addr)
                        conack = self.create_con_ack_message(addr=addr)
                        self.sock.sendto(conack,addr)
                    elif msg['msg_type'] == 1:
                        # Handle CONACK Message
                        raise RuntimeError('Server received CONACK message.')
                    elif msg['msg_type'] == 2:
                        # Handle Data Message
                        # Check Validity
                        validity = self.check_hmac_validation(addr=addr, payload=msg['payload'],received_hmac=msg['hmac'])
                        if validity:
                            self.write_console(f'[HMAC Verified] [{addr}] {msg["payload"].decode()}')
                        else:
                            self.write_console(f'[HMAC FAILED] [{addr}] {msg["payload"].decode()}')

                        # Send Acknowledgement
                        ack_msg = self.create_ack_message(addr, msg['payload'])
                        self.sock.sendto(ack_msg, addr)

                        # Broadcast Message
                        self.broadcast_message(msg['payload'].decode(), exclude_addr=addr)
                    elif msg['msg_type'] == 3:
                        # Handle Acknowledgement Message
                        self.connections[addr].rx_seq = msg['seq']
                        self.write_console(f"Ack received {msg['seq']}")
                    else:
                        raise RuntimeError('Server received message for unsopported type.')
                except Exception as e:
                    self.write_console(f'Message malformed from {addr}')
                    self.write_console(f'{e}')
            else:
                msg = self._decode_message(addr=addr, data=data)
                self.write_console(f'Received CONREQ for client: [{addr}].')
                self.initialize_client(addr=addr, rsa_key=msg['payload'])
                conack = self.create_con_ack_message(addr=addr)
                self.write_console(f'Sending CONACK to: [{addr}].')
                self.sock.sendto(conack,addr)

                # self.send_msg_with_ack(msg=conack)
                # self.initialize_client(data, addr)

    def broadcast_message(self, msg: str, exclude_addr=None):
        '''
        Broadcast a message to all clients (except the excluded)

        Params:
            msg: string message to broadcast
            exclude_addr: client to be excluded
        '''
        for client_addr in self.connections.keys():
            if client_addr == exclude_addr:
                continue
            data_msg = self.create_data_message(addr=client_addr, payload=msg.encode())

            desired_seq = self.connections[client_addr].rx_seq + len(msg.encode())
            self.write_console(f'Current Seq: {self.connections[client_addr].rx_seq}')
            self.write_console(f'Desired Seq: {desired_seq}')

            threading.Thread(target=self.send_msg_with_ack,
                             args=[data_msg, desired_seq, client_addr, 3],
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
        retry_count = 0
        while self.connections[client_addr].rx_seq != desired_seq:
            self.sock.sendto(encrypted_msg, client_addr)
            time.sleep(0.3)
            retry_count += 1
            if retry_count >= retries:
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
