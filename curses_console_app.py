'''Use Curses to make the console look pretty'''

import curses
from curses import wrapper
from curses.textpad import Textbox, rectangle
import time
import threading

class CursesConsoleApp():
    def __init__(self, username):
        threading.Thread(target=self.set_up_window, daemon=True).start()
        self.username = username
        self.buffer = []
        
    def set_up_window(self):
        '''Set up the initial window and handle the output section.'''

        self.output_window_size = 15
        self.output_window_length = 64
        self.output_win = curses.newwin(self.output_window_size,self.output_window_length+2, 0,0)
        self.output_win.border()
        self.output_win.noutrefresh()
        self.refresh_buffer = True
        self.output_subwin = self.output_win.subwin(self.output_window_size-2,self.output_window_length, 1, 1)

        self.input_win = curses.newwin(3,self.output_window_length+2, self.output_window_size+1, 0)
        self.input_win.border()
        self.input_subwin = self.input_win.subwin(1, self.output_window_length, self.output_window_size+2, 1)
        self.input_tb = Textbox(self.input_subwin)
        self.input_win.noutrefresh()

        instructions_win_length = 32
        instructions_win = curses.newwin(3,instructions_win_length+2, self.output_window_size+1+3, 0)
        instructions_win.addstr(0,0,'Ctrl-C to quit')
        instructions_win.noutrefresh()
        
        # Handle updating the output buffer
        while True:
            try:
                if self.refresh_buffer:
                    self.output_subwin.erase()
                    for i in range(len(self.buffer)):
                        self.output_subwin.addstr(i,0, self.buffer[i])
                    self.output_subwin.noutrefresh()
                    self.refresh_buffer = False
                curses.doupdate()
                time.sleep(0.2)
            except KeyboardInterrupt as k:
                pass
            except Exception as e:
                pass

    def get_input(self):
        '''Get input from the console'''
        try:
            self.input_subwin.addstr('You: ')
            self.input_tb.edit()
            output = self.input_tb.gather()[5:]
            self.input_subwin.erase()
            self.input_win.noutrefresh()
            return output
        except Exception as e:
            pass

    def write_console(self, msg: str):
        '''Write to the output buffer and flag it as changed.
        
        Params:
            msg: string message to display'''
        try:
            for part in self.textwrap(msg, self.output_window_length):
                self.buffer.append(part)
                if len(self.buffer) >= self.output_window_size-1:
                    self.buffer = self.buffer[1:]
            self.refresh_buffer = True
        except Exception as e:
            pass
        
    def textwrap(self, msg: str, line_limit: int) -> list:
        '''
        Take an input string and turn it into a list of strings that will not overflow.
        This function automatically separates strings by spaces.

        Params:
            msg: input string
            line_limit: integer line limit to wrap at

        Returns:
            List of strings
        '''
        result = []
        portion = ''
        for character in msg.split(' '):
            if len(portion) + len(character) > line_limit - 1:
                result.append(portion)
                portion = ''
            portion = f'{portion} {character}'
        result.append(portion)
        return result