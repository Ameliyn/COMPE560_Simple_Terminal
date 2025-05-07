import socket
import threading
import time

import curses
from curses import wrapper
from curses_console_app import CursesConsoleApp
from russ_chat_message_handler import RussChatMessageHandler

#SERVER_IP: ‘0.0.0.0’ means the server listens on all available network interfaces.
#SERVER_PORT: The port number used for communication.
#BUFFER_SIZE: The size of the data chunks received (1 KB).
SERVER_IP = 'localhost'  # Bind to all interfaces
SERVER_PORT = 12347
BUFFER_SIZE = 4096

class Client(CursesConsoleApp, RussChatMessageHandler):

    def __init__(self, username, server_addr):
        RussChatMessageHandler.__init__(self)
        CursesConsoleApp.__init__(self, username=username)
        self.username = username
        self.server_addr = server_addr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.initialize()
        threading.Thread(target=self.receive_messages, daemon=True).start()
        self.run_client()

    def initialize(self):
        '''Initialize Client.'''
        self.write_console('Establishing Secure Server Connection...')
        thread_started = False
        timeout = 0
        self.create_connection(self.server_addr, 0)
        conreq = self.create_con_req_message(self.server_addr)
        self.sock.sendto(conreq, self.server_addr)

        while self.connections[self.server_addr].aes_key is None or self.connections[self.server_addr].hmac_secret is None:
            self.write_console('Waiting for server Connection...')
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
        '''Wait for initial response asynchronously.'''
        while True:
            data, addr = self.sock.recvfrom(4096)
            msg = self._decode_message(data=data, addr=addr)
            if msg['msg_type'] != 1:
                time.sleep(1)
                continue
            else:
                self.handle_con_ack_message(message_dict=msg, addr=addr)
                self.server_addr = addr
                self.write_console("Received and decrypted AES key.")
                self.write_console(f'Received HMAC key')
                break

    # Function to receive messages concurrently
    def receive_messages(self):
        '''Receive and process messages.'''
        while True:
            data, addr = self.sock.recvfrom(4096)
            if addr in self.connections.keys():
                try:
                    msg = self._decode_message(addr=addr, data=data)
                    if msg['msg_type'] == 0:
                        # Handle CONREQ Message
                        self.write_console(f'WARNING Received CONREQ as client: [{addr}]')
                    elif msg['msg_type'] == 1:
                        # Handle CONACK Message
                        self.write_console(f'Received new CONACK message... Reinitializing connection.')
                        self.initialize()
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

                    elif msg['msg_type'] == 3:
                        self.write_console(f'Ack Received for seq: {msg["seq"]}')
                        self.connections[addr].rx_seq = msg['seq']
                        # Handle Acknowledgement Message
                    else:
                        raise RuntimeError('Server received message for unsopported type.')
                except Exception as e:
                    self.write_console('Decryption Failed!')
                    self.write_console(e)
            else:
                self.write_console(f'WARNING: Received message from non-server entity.')

    def run_client(self):
        '''Get input and broadcast messages.'''
        while True:
            try:
                message = self.get_input().strip()
                if self.server_addr in self.connections.keys():
                    data_message = self.create_data_message(addr=self.server_addr, payload=f'{self.username}: {message}'.encode())

                    desired_seq = self.connections[self.server_addr].rx_seq + len(f'{self.username}: {message}'.encode())
                    self.write_console(f'Current Seq: {self.connections[self.server_addr].rx_seq}')
                    self.write_console(f'Desired Seq: {desired_seq}')

                    retries = 3
                    retry_count = 0
                    while self.connections[self.server_addr].rx_seq != desired_seq:
                        self.sock.sendto(data_message, self.server_addr)
                        time.sleep(0.3)
                        retry_count += 1
                        if retry_count >= retries:
                            self.write_console(f'NO ACK RECEIVED FROM {self.server_addr}')
                            break
                    if self.connections[self.server_addr].rx_seq == desired_seq:
                        self.write_console(msg=f'[You] {self.username}: {message}')
            except Exception as e:
                self.write_console(f"Error sending message: {e}")


def main(stdscr):
    # Get username
    inp = curses.newwin(8,55, 0,0)
    inp.addstr(1,1, "Please enter your username:")
    sub = inp.subwin(3, 34, 2, 1)
    sub.border()
    sub2 = sub.subwin(1, 32, 3, 2)
    tb = curses.textpad.Textbox(sub2)
    inp.refresh()
    tb.edit()
    username = tb.gather()

    # Reset Window
    del inp
    stdscr.touchwin()
    stdscr.refresh()

    # Start Client
    c = Client(username.strip().replace('\n',''), (SERVER_IP,SERVER_PORT))


if __name__ == "__main__":
    try:
        wrapper(main)
    except KeyboardInterrupt as k:
        print('Goodbye!')
    except Exception as e:
        print('Fatal Exception')
        print(e)
        # raise e
