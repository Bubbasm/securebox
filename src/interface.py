import pyfiglet
import curses
from curses.textpad import rectangle, Textbox
from config import APP_NAME, APP_VERSION, AUTHORS
from editor.editor import Editor


class TUI:
    """
    Class representing the TUI interface of the application.
    Handles the graphical part of the application inside the terminal
    using the curses library.
    """

    class TerminalTooSmallError(Exception):
        """Exception raised when the terminal is too small (less than 24x100)"""

    def __init__(self, stdscr: curses.window):
        """
        Constructor of the Interface class

        :param stdscr: curses window object
        """
        self.stdscr = stdscr
        self.MIN_HEIGHT = 24
        self.MIN_WIDTH = 100

    def clear_screen(self):
        """Clear the screen of the terminal"""
        self.stdscr.clear()
        # set window border color to A_DIM
        self.stdscr.attron(curses.A_DIM)
        self.stdscr.box()
        self.stdscr.attroff(curses.A_DIM)

    def check_screen_size(self):
        """
        Check if the terminal is big enough to display the application.

        :raise TerminalTooSmallError: if the terminal is too small
        """
        if curses.LINES < self.MIN_HEIGHT or curses.COLS < self.MIN_WIDTH:
            raise self.TerminalTooSmallError()

    def get_size(self) -> tuple[int, int]:
        """
        Get the size of the terminal

        :return: a dictionary with keys 'y' and 'x' representing the size of the terminal
        """
        return {"y": curses.LINES, "x": curses.COLS}

    def print_centered(
            self,
            text: str,
            x: int = None,
            y: int = None,
            border: bool = False):
        """
        Print some text centered on (x, y)

        :param text: text to print. Can contain multiple lines separated by '\n'
        :param x: x coordinate of the center of the text. If None, the center of the screen is used
        :param y: y coordinate of the center of the text. If None, the center of the screen is used
        """
        text = text.split('\n')
        text_height = len(text)

        if x is None:
            x = int(curses.COLS / 2)
        if y is None:
            y = int(curses.LINES / 2)

        y -= int(text_height / 2)

        if border:
            w = len(max(text, key=len)) + 8
            h = text_height + 4
            win = curses.newwin(h, w, y - 2, x - int(w / 2))
            win.attron(curses.A_BOLD)
            win.box()
            win.attroff(curses.A_BOLD)
            win.refresh()

        for line in text:
            if y >= 0 and y < curses.LINES:
                self.stdscr.addstr(y, x - int(len(line) / 2), line)
            y += 1

    def print_banner(self):
        """
        Print the banner of the application (name, version, authors, etc.)
        centered on the screen.
        """
        banner = pyfiglet.figlet_format(APP_NAME, font="ansi_shadow")
        banner += "By " + AUTHORS + " - " + APP_VERSION

        margin_top = 7
        self.print_centered(banner, y=margin_top)

    def print_list(
            self,
            items: list[tuple[int, str]],
            info: str = None,
            help_text: str = None,
            cursor: int = 0,
            pages: tuple[int, int] = None) -> tuple[int, int]:
        """
        Print a list of items and let the user select one

        :param items: list of tuples (id, name) to display
        :param info: information to display above the list
        :param help_text: optional, help text to display at the bottom of the screen
        :param cursor: optional, position of the cursor in the list
        :param pages: optional, tuple (current_page, total_pages) to display
        :return: (y, x) position of the cursor
        """
        row_height = 2

        self.clear_screen()

        if info:
            self.stdscr.addstr(0, 2, f" {info} ", curses.A_BOLD)

        if help_text:
            x = curses.COLS - len(help_text) - 4
            self.stdscr.addstr(0, x, f" {help_text} ", curses.A_BOLD)

        if pages and len(items) > 0:
            pages_text = f" Page {pages[0] + 1} of {pages[1]} "
            y, x = (curses.LINES - 1, curses.COLS - len(pages_text) - 2)
            self.stdscr.addstr(y, x, pages_text, curses.A_BOLD)

        y, x = row_height, 6

        if len(items) == 0:
            self.stdscr.addstr(
                y, x, "No items to display. Press N to add a new one.")
            return

        self.stdscr.addstr(y, x, "ID")
        self.stdscr.addstr(y, x + 10, "Name")
        y += 1
        separator = "─" * (curses.COLS - 2 * (x - 1))
        self.stdscr.addstr(y, x - 1, separator, curses.A_DIM)
        y += 1

        initial_pos = (y, x)
        # for key, value in items:
        for i, (key, value) in enumerate(items):
            if y >= curses.LINES:
                break
            if i == cursor:
                self.stdscr.addstr(y, x - 3, ">")
            if y >= curses.LINES:
                break
            self.stdscr.addstr(y, x, str(key))
            max_len = curses.COLS - x - 15
            if len(value) >= max_len:
                value = value[:max_len - 3] + "..."
            self.stdscr.addstr(y, x + 10, value)
            y += row_height

        return initial_pos

    def text_field_prompt(
            self,
            title: str = "",
            text: str = "",
            pw_mode: bool = False) -> str:
        """
        Print a small prompt centered on the screen

        :param title: title of the prompt
        :param text: prompt to print
        :param pw_mode: if True, the input is hidden (password mode)
        :return: the input of the user
        """
        h = 3
        w = 60
        y = curses.LINES // 2 - h // 2 + pw_mode * 3
        x = curses.COLS // 2 - w // 2

        editor = Editor(
            self.stdscr,
            inittext=text,
            win_location=(y, x),
            win_size=(h, w),
            max_paragraphs=1,
            pw_mode=pw_mode)

        if title:
            title = f" {title.strip()} "
            self.stdscr.addstr(y, x + 2, title, curses.A_BOLD)

        text = editor()
        curses.curs_set(0)
        return text

    def editor(
            self,
            title: str = "",
            text: str = "",
            edit: bool = True) -> str:
        """
        Open the editor to edit some text

        :param title: title of the editor
        :param text: initial text to display in the editor
        :param edit: if True, the text is editable, otherwise it is read-only
        :return: the edited text
        """
        self.clear_screen()
        editor = Editor(
            self.stdscr,
            inittext=text,
            win_location=(1, 1),
            win_size=(curses.LINES - 2, curses.COLS - 2),
            edit=edit,
            box=False
        )

        if title:
            title = f" {title.strip()} "
            self.stdscr.addstr(0, 2, title, curses.A_BOLD)

        if not edit:
            help_text = "Q/F2/ESC: Go back"
        else:
            help_text = "F2/Ctrl+X: Save, F3/ESC: Cancel"

        x = curses.COLS - len(help_text) - 4
        self.stdscr.addstr(0, x, f" {help_text} ", curses.A_BOLD)

        text = editor()
        curses.curs_set(0)
        return text
