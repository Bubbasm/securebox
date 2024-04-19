"""
File: securebox.py
Author: Bhavuk Sikka and Samuel de Lucas
Date: 21-02-2024

Description: This is an application that allows users to store their
passwords in a secure manner. The application consists of a unique vault,
which is composed of multiple containers, each of which can store multiple
files. Each container is encrypted with different keys, but it is
configurable to allow the user to use the same key for all containers.
The application will also allow users to generate random passwords.
"""

import os
import curses
import signal
import getpass
import functools
import argparse
import tkinter as tk
from tkinter import ttk
from interface import TUI
from models import Vault
from config import AUTO_UPLOAD, CONFIG_PATH, SAVE_PATH, AUTHORS, APP_VERSION
from abc import ABC, abstractmethod
from time import sleep


class Application(ABC):
    """
    Class representing the application.
    Controls the flow of the application and renders the interface
    """

    class MenuOption:
        """Represents the possible actions that can be done"""
        CREATE = "create"
        VIEW = "view"
        EDIT = "edit"
        DELETE = "delete"

    def __init__(self):
        self.vault = None

    @abstractmethod
    def run(self):
        """
        Run the application
        """
        raise NotImplementedError

    @abstractmethod
    def ask_for_master_password(self) -> str:
        """
        Ask the user for the master password

        :return: the master password entered by the user
        """
        raise NotImplementedError

    @abstractmethod
    def show_error(self, message: str):
        """
        Print an error message about the login

        :param message: message to print
        """
        raise NotImplementedError

    def exit(self, error: str = None, upload: bool = True):
        """
        Exit the application

        :param error: optional error message to print before exit
        :param upload: if True, upload the vault to the cloud before exit. Still does not upload if AUTO_UPLOAD is False
        """
        if error:
            self.show_error(error)

        if AUTO_UPLOAD and upload and not error:
            if "show_dialog" in dir(self):
                self.show_dialog(
                    "Uploading Vault",
                    "Uploading vault to the cloud before exit. Please wait...")

            try:
                success = self.vault.upload_backup(SAVE_PATH)
            except Exception as e:
                success = False

            if not success:
                msg = "Could not upload vault to the cloud."
                self.show_error(msg)

            elif "show_dialog" in dir(self):
                self.show_dialog(
                    "Vault Uploaded",
                    "Vault has been uploaded to the cloud successfully.",
                    blocking=True)

        if "post_run" in dir(self):
            self.post_run()

        exit(1 if error else 0)

    def login(
            self,
            dialog_open: callable = None,
            dialog_close: callable = None):
        """
        Open the vault file and load the vault object

        :param dialog_callable: optional callable to show a dialog
        :param post_login: optional callable to execute after login
        """
        while self.vault is None:
            master_password = self.ask_for_master_password()
            if dialog_open:
                ret = dialog_open(
                    "Opening vault...",
                    "Decrypting vault contents. Please wait...")
            try:
                self.vault = Vault(master_password, SAVE_PATH)
            except FileNotFoundError:
                self.vault = Vault(master_password)
                try:
                    self.vault.save_to_file(SAVE_PATH)
                except PermissionError as e:
                    error = "Could not save: permission denied."
                    self.exit(error)
            except PermissionError:
                error = "Could not open save file: permission denied."
                self.exit(error)
            except Vault.LoadVaultError as e:
                self.show_error(str(e))
                self.vault = None
            finally:
                if dialog_close:
                    dialog_close(ret)


class TUIApplication(Application):
    """
    Class representing the application.
    Controls the flow of the application and renders the interface (TUI)
    """

    def __init__(self):
        """
        Constructor of the Application class

        :param stdscr: curses window object
        """
        super().__init__()
        self.stdscr = None
        self.interface = None

    def ask_for_master_password(self) -> str:
        """
        Ask the user for the master password

        :return: the master password entered by the user
        """
        self.interface.clear_screen()
        self.interface.print_banner()
        master_password = self.interface.text_field_prompt(
            title="Master password", pw_mode=True)
        return master_password

    def show_error(self, message: str):
        """
        Print show error message to the user

        :param message: message to print
        """
        self.interface.clear_screen()
        self.show_dialog("Error", message, blocking=True)

    def show_dialog(self, title: str, message: str, blocking: bool = False):
        """
        Show a dialog with a message

        :param message: message to show
        :param blocking: if True, wait for user to press a key
        """
        if blocking:
            message += "\n\nPress any key to continue"

        self.interface.clear_screen()
        self.interface.print_centered(message)

        if blocking:
            try:
                self.stdscr.getkey()
            except curses.error:
                pass  # ignore curses error on ctrl+c

    def show_yes_no_dialog(self, title: str, message: str) -> bool:
        """
        Show a dialog with a message and yes/no options (yes is default)

        :param title: title of the dialog
        :param message: message to show
        :return: True if the user presses "yes", False otherwise
        """
        message += "\n\nYES (y) / no (n)"
        self.interface.clear_screen()
        self.interface.print_centered(message)

        curses.flushinp()  # flush input buffer

        selection = None
        # while the selection is not valid
        while selection not in [ord("y"), ord("Y"), ord("n"), ord("N"), 10]:
            try:
                selection = self.stdscr.getch()
            except curses.error:
                pass  # ignore curses error on ctrl+c

        return selection in [ord("y"), ord("Y"), 10]

    def list_containers(
            self,
            page: int = 0,
            cursor: int = 0) -> tuple[int, "Application.MenuOption"]:
        """
        List the containers in the vault, and an option to create a new one

        :param page: optional, page to show
        :param cursor: optional, initial cursor position
        :return: the id of the selected container, and the action to perform
        """
        row_height = 2
        items_per_page = (self.interface.get_size()["y"]) // row_height - 2

        containers = list(self.vault.get_containers().values())
        containers.sort(key=lambda c: c.get_id())

        paged_containers = {
            i // items_per_page: [
                (c.get_id(), c.get_name())
                for c in containers[i:i + items_per_page]
            ]
            for i in range(0, len(containers), items_per_page)
        } if len(containers) > 0 else {0: {}}

        page = max(0, min(page, len(paged_containers) - 1))
        while True:
            info = "Select a container"
            help_text = (
                "ARROWS: navigate, "
                "E/V/D: edit/view/delete, "
                "N: new container, "
                "Q: quit"
            )
            cursor = max(0, min(cursor, len(paged_containers[page]) - 1))
            pages = (page, len(paged_containers))
            position = self.interface.print_list(
                paged_containers[page], info, help_text, cursor, pages)

            prev_page = page
            while page == prev_page:
                try:
                    curses.flushinp()  # flush input buffer
                    key = self.stdscr.getch()
                except curses.error:
                    pass  # ignore curses error on ctrl+c

                if key == ord('q') or key == ord('Q'):
                    return None, None, None, None
                if key == ord('n') or key == ord('N'):
                    cursor = len(paged_containers[page]) % items_per_page
                    page += cursor == 0
                    return None, Application.MenuOption.CREATE, page, cursor

                if len(paged_containers[page]) > 0:
                    prev_cursor = cursor
                    if key == curses.KEY_DOWN:
                        cursor = (cursor + 1) % len(paged_containers[page])
                    elif key == curses.KEY_UP:
                        cursor = (cursor - 1) % len(paged_containers[page])
                    elif key == ord('e') or key == ord('E'):
                        c_id = paged_containers[page][cursor][0]
                        return c_id, Application.MenuOption.EDIT, page, cursor
                    elif key == ord('v') or key == ord('V'):
                        c_id = paged_containers[page][cursor][0]
                        return c_id, Application.MenuOption.VIEW, page, cursor
                    elif key == ord('d') or key == ord('D'):
                        c_id = paged_containers[page][cursor][0]
                        if len(paged_containers[page]) == 1:
                            page -= 1
                            cursor = items_per_page - 1
                        return c_id, Application.MenuOption.DELETE, page, cursor

                    if cursor != prev_cursor and position:
                        y, x = position
                        self.stdscr.addstr(
                            y + prev_cursor * row_height, x - 3, " ")
                        self.stdscr.addstr(
                            y + cursor * row_height, x - 3, ">")

                if len(paged_containers) > 1:
                    if key == curses.KEY_RIGHT:
                        cursor = 0
                        page = (page + 1) % len(paged_containers)
                    elif key == curses.KEY_LEFT:
                        cursor = 0
                        page = (page - 1) % len(paged_containers)

        return None, None, None, None

    def pre_run(self):
        """
        Method to run before the main loop.
        Initializes the curses interface
        """
        self.stdscr = curses.initscr()
        self.stdscr.immedok(True)
        self.stdscr.keypad(1)
        curses.noecho()
        curses.cbreak()
        curses.curs_set(0)

        self.interface = TUI(self.stdscr)

    def post_run(self):
        """
        Method to run after the main loop.
        Closes the curses interface
        """
        self.stdscr.keypad(0)
        curses.echo()
        curses.nocbreak()
        curses.curs_set(1)
        curses.endwin()

    def run(self):
        """
        Run the application in text mode
        """

        terminal_too_small = error = False
        try:
            self.pre_run()

            self.interface.check_screen_size()

            signal.signal(signal.SIGINT, lambda x, y: self.exit(upload=False))
            self.login(dialog_open=self.show_dialog)
            signal.signal(signal.SIGINT, self.exit)

            # main loop (actions depending on the selected container)
            page, cursor = 0, 0
            while True:
                c_id, action, page, cursor = self.list_containers(page, cursor)
                if not any([c_id, action, page, cursor]):
                    break

                if action == Application.MenuOption.CREATE:
                    data = self.interface.editor(title="New container")

                    if data:
                        name = self.interface.text_field_prompt(
                            title="Container name")
                        self.show_dialog(
                            "Creating Container",
                            f"Creating container. Please wait...")
                        self.vault.add_container(name, data)
                        self.vault.save_to_file(SAVE_PATH)
                        self.show_dialog(
                            "Container Created",
                            f"The container has been created successfully.",
                            blocking=True)

                elif action == Application.MenuOption.DELETE:
                    delete = self.show_yes_no_dialog(
                        "Delete Container",
                        f"Are you sure you want to delete the container with ID {c_id}?\nThis action cannot be undone.")
                    if delete:
                        self.show_dialog(
                            "Deleting Container",
                            f"Deleting container. Please wait...")
                        self.vault.remove_container(c_id)
                        self.vault.save_to_file(SAVE_PATH)
                        self.show_dialog(
                            "Container Deleted",
                            f"Container with ID {c_id} has been deleted.",
                            blocking=True)

                else:  # VIEW or EDIT
                    container = self.vault.get_container(c_id)
                    edit = (action == Application.MenuOption.EDIT)

                    title = "Container: " + container.get_name()
                    initial_data = container.get_data()
                    data = self.interface.editor(
                        title=title, text=initial_data, edit=edit)

                    if edit and data != initial_data:
                        self.show_dialog(
                            "Updating Container",
                            f"Updating container. Please wait...")
                        self.vault.update_container(c_id, data=data)
                        self.vault.save_to_file(SAVE_PATH)
                        self.show_dialog(
                            "Container Updated",
                            f"Container with ID {c_id} has been updated successfully.",
                            blocking=True)

        except TUI.TerminalTooSmallError as e:
            terminal_too_small = True

        except Exception as e:
            self.show_error(str(e))
            error = True

        finally:
            self.post_run()

            if not error and not terminal_too_small:
                self.exit()

            elif terminal_too_small:
                # print error message after closing curses and before exit if
                # the terminal was too small
                min_h = self.interface.MIN_HEIGHT
                min_w = self.interface.MIN_WIDTH
                print(f"Resize your terminal to at least {min_h} x {min_w}")
                print("Current size: ", curses.LINES, "x", curses.COLS)


class GUIApplication(Application):
    """
    Class representing the application.
    Controls the flow of the application and renders the interface (GUI)
    """

    def __init__(self):
        super().__init__()
        self.root = tk.Tk()
        self.root.title("SecureBox")
        self.root.geometry("800x600")
        self.colors = {
            "bg": "#070506",
            "fg": "#fdfdfd",
            "highlightcolor": "#aaaaaa",  # element focused
            "highlightbackground": "#444444",  # element not focused
        }
        self.btn_focus_colors = {
            "highlightcolor": self.colors["highlightcolor"],
            "highlightbackground": "#070506",
        }
        self.entry_colors = self.colors | {
            "insertbackground": self.colors["fg"],
            "disabledforeground": "#777777",
            "disabledbackground": "#0F0F0F",
        }
        self.root.configure(bg=self.colors["bg"])
        self.root.protocol(
            "WM_DELETE_WINDOW",
            lambda: exit(0) if not self.vault else self.exit())
        self.root.update()
        self.root_frame = None

    def ask_for_master_password(
            self,
            message: str = "Enter your master password",
            exit_on_close: bool = True) -> str:
        """
        Ask the user for the master password

        :param message: optional message to print
        :return: the master password entered by the user
        """
        window = tk.Toplevel(self.root, bg=self.colors["bg"])
        window.title("SecureBox: Login")
        window.focus_force()

        frame = tk.Frame(window, bg=self.colors["bg"], pady=30, padx=60)
        frame.pack(expand=True)

        label = tk.Label(
            frame,
            text=message,
            **self.colors)
        label.pack()

        entry = tk.Entry(
            frame,
            show="*",
            **self.entry_colors)
        entry.pack(pady=10)
        entry.focus_set()

        button = tk.Button(
            frame,
            text="Submit",
            command=window.quit,
            **self.btn_focus_colors)
        window.bind("<Return>", lambda e: window.quit())
        button.pack()

        if exit_on_close:
            window.protocol("WM_DELETE_WINDOW", lambda: exit(0))
        window.mainloop()

        master_password = entry.get()
        window.destroy()
        self.root.update()
        return master_password

    def show_error(self, message: str):
        """
        Show error message to the user

        :param message: message to print
        """
        window = self.show_dialog("Error", message, button_text="Close")
        window.wait_window()

    def show_dialog(
            self,
            title: str,
            message: str,
            button_text: str = None,
            blocking: bool = False):
        """
        Show a dialog with a message and a button

        :param title: title of the dialog
        :param message: message to show
        :param button_text: text for the button
        :param blocking: if True, wait for user to press the button
        :return: the window object
        """
        if blocking:
            button_text = button_text or "Close"

        window = tk.Toplevel(self.root, bg=self.colors["bg"])
        window.title(f"SecureBox: {title}")
        window.focus_force()

        frame = tk.Frame(window, bg=self.colors["bg"], pady=30, padx=60)
        frame.pack(expand=True)

        label = tk.Label(
            frame,
            text=message,
            **self.colors)
        label.pack(pady=(0, 10))

        if button_text is not None:
            button = tk.Button(frame, text=button_text, command=window.destroy)
            button.pack()
            window.bind("<Return>", lambda e: window.destroy())

        window.update_idletasks()
        self.root.update()

        return window

    def show_yes_no_dialog(
            self,
            title: str,
            message: str,
            yes_command: callable = None,
            yes_text: str = "Yes",
            no_command: callable = None,
            no_text: str = "No",
            destructive_warning: bool = False):
        """
        Show a dialog with a message and two buttons (yes/no)

        :param title: title of the dialog
        :param message: message to show
        :param yes_command: command to execute when the "yes" button is clicked
        :param yes_text: text for the "yes" button
        :param no_command: command to execute when the "no" button is clicked
        :param no_text: text for the "no" button
        :param destructive_warning: if True, show a warning message in red
        """
        window = tk.Toplevel(self.root, bg=self.colors["bg"])
        window.title(f"SecureBox: {title}")
        window.focus_force()

        frame = tk.Frame(window, bg=self.colors["bg"], pady=30, padx=60)
        frame.pack(expand=True)

        label = tk.Label(
            frame,
            text=message,
            **self.colors)
        label.pack()

        if destructive_warning:
            label = tk.Label(
                frame,
                text="This action cannot be undone.",
                fg="red",
                bg=self.colors["bg"])
            label.pack(pady=(0, 10))

        buttons_frame = tk.Frame(frame, bg=self.colors["bg"])
        buttons_frame.pack(expand=True, fill=tk.BOTH, pady=5)

        def yes_command_wrapper():
            if yes_command:
                yes_command()
            window.destroy()

        def no_command_wrapper():
            if no_command:
                no_command()
            window.destroy()

        button = tk.Button(
            buttons_frame,
            text=yes_text,
            command=yes_command_wrapper,
            **self.btn_focus_colors)
        button.pack(side=tk.RIGHT, padx=5)

        button = tk.Button(
            buttons_frame,
            text=no_text,
            command=no_command_wrapper,
            **self.btn_focus_colors)
        button.pack(side=tk.LEFT, padx=5)

    def container_action(
            self,
            action: "Application.MenuOption",
            c_id: int = None):
        """
        Perform an action on a container

        :param action: action to perform
        :param c_id: container id
        """

        if action == Application.MenuOption.DELETE:
            def delete_container():
                dialog = self.show_dialog(
                    "Deleting Container",
                    f"Deleting container. Please wait...")
                self.vault.remove_container(c_id)
                self.vault.save_to_file(SAVE_PATH)
                dialog.destroy()
                dialog = self.show_dialog(
                    "Container Deleted",
                    f"Container with ID {c_id} has been deleted.",
                    button_text="Close")
                self.fill_frame_with_containers()

            self.show_yes_no_dialog(
                "Delete Container",
                f"Are you sure you want to delete the container with ID {c_id}?",
                yes_command=delete_container,
                yes_text="Yes, delete it",
                no_text="No, go back",
                destructive_warning=True)

        else:
            window = tk.Toplevel(self.root, bg=self.colors["bg"])
            window.title("SecureBox: " + action.capitalize() + " Container")
            window.geometry("600x400")
            window.focus_force()

            frame = tk.Frame(window, bg=self.colors["bg"], pady=30, padx=60)
            frame.pack(expand=True)

            name_frame = tk.LabelFrame(
                frame, text=" Container Name", **self.colors, bd=0)
            name_frame.pack(expand=True, fill=tk.BOTH, pady=5)

            name = tk.Entry(
                name_frame,
                **self.entry_colors)
            name.pack(expand=True, fill=tk.BOTH, pady=5, padx=5)
            if action != Application.MenuOption.VIEW:
                name.focus_set()

            text_frame = tk.LabelFrame(
                frame, text=" Data", **self.colors, bd=0)
            text_frame.pack(expand=True, fill=tk.BOTH, pady=5)

            text = tk.Text(
                text_frame,
                height=10,
                wrap=tk.WORD,
                **self.colors,
                insertbackground=self.entry_colors["insertbackground"])
            text.pack(fill=tk.X, pady=5, padx=5)

            if action == Application.MenuOption.VIEW or\
                    action == Application.MenuOption.EDIT:
                container = self.vault.get_container(c_id)
                name.insert(0, container.get_name())
                text.insert(tk.END, container.get_data())

            if action == Application.MenuOption.VIEW:
                name.config(state=tk.DISABLED)
                name_frame.config(text=" Container Name (read-only)")
                text_frame.config(text=" Data (read-only)")
                text.config(
                    state=tk.DISABLED,
                    bg=self.entry_colors["disabledbackground"],
                    fg=self.entry_colors["disabledforeground"],
                    highlightcolor=self.colors["highlightbackground"],
                )

            buttons_frame = tk.Frame(frame, bg=self.colors["bg"])
            buttons_frame.pack(expand=True, fill=tk.BOTH, pady=5)

            def add_container():
                dialog = self.show_dialog(
                    "Adding Container",
                    f"Creating container. Please wait...")
                c_name = name.get()
                data = text.get("1.0", "end-1c")
                data = data if data else "<empty>"
                window.destroy()
                self.vault.add_container(c_name, data)
                self.vault.save_to_file(SAVE_PATH)
                dialog.destroy()
                dialog = self.show_dialog(
                    "Container Created",
                    f"The container has been created successfully.",
                    button_text="Close")
                self.fill_frame_with_containers()

            def edit_container():
                dialog = self.show_dialog(
                    "Updating Container",
                    f"Updating container. Please wait...")
                c_name = name.get()
                data = text.get("1.0", "end-1c")
                data = data if data else "<empty>"
                window.destroy()
                self.vault.update_container(c_id, name=c_name, data=data)
                self.vault.save_to_file(SAVE_PATH)
                dialog.destroy()
                dialog = self.show_dialog(
                    "Container Updated",
                    f"Container with ID {c_id} has been updated successfully.",
                    button_text="Close")
                self.fill_frame_with_containers()

            command = None
            if action == Application.MenuOption.CREATE:
                command = add_container
            elif action == Application.MenuOption.EDIT:
                command = edit_container

            if command is not None:
                save_button = tk.Button(
                    buttons_frame,
                    text="Save",
                    command=command,
                    **self.btn_focus_colors)
                save_button.pack(side=tk.RIGHT, padx=5)

            cancel_button = tk.Button(
                buttons_frame,
                text="Cancel" if command is not None else "Go Back",
                command=window.destroy,
                **self.btn_focus_colors)
            cancel_button.pack(side=tk.LEFT, padx=5)

            window.mainloop()

    def fill_frame_with_containers(self):
        """
        Auxiliary method to fill the tk frame with the containers
        """
        for widget in self.containers_frame.winfo_children():
            widget.destroy()

        containers = self.vault.get_containers()
        btn_texts = ["View", "Edit", "Delete"]
        for c_id, container in containers.items():
            container_frame = tk.Frame(
                self.containers_frame, bg=self.colors["bg"])
            container_frame.pack(expand=True, fill=tk.X)

            max_len = 60
            c_name = container.get_name()[0:max_len]
            if len(c_name) >= max_len:
                c_name += "..."
            container_label = tk.Label(
                container_frame, text=f"({c_id}) " + c_name, **self.colors)
            container_label.pack(fill=tk.X, side=tk.LEFT, padx=5)

            buttons = tk.Frame(container_frame, bg=self.colors["bg"])
            buttons.pack(side=tk.RIGHT)

            btn_actions = [
                Application.MenuOption.VIEW,
                Application.MenuOption.EDIT,
                Application.MenuOption.DELETE
            ]
            btn_commands = [
                functools.partial(self.container_action, action, c_id)
                for action in btn_actions
            ]

            for i, text in enumerate(btn_texts):
                button = tk.Button(
                    buttons,
                    text=text,
                    command=btn_commands[i],
                    **self.btn_focus_colors)
                button.pack(side=tk.LEFT, padx=5)

            sep = ttk.Separator(self.containers_frame, orient="horizontal")
            sep.pack(fill=tk.X, pady=5)

    def list_containers(self):
        """
        List the containers in the vault, and an option to create a new one
        """
        self.root_frame.destroy()
        self.root_frame = tk.Frame(self.root, bg=self.colors["bg"])
        self.root_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        folder = os.path.dirname(os.path.abspath(__file__))
        logo_file = os.path.join(folder, "imgs/logo_small.png")

        logo_small = tk.PhotoImage(file=logo_file)
        logo = tk.Label(self.root_frame, image=logo_small, borderwidth=0)
        logo.image = logo_small  # keep a reference
        logo.pack()

        # outer frame, labeled as "Your Containers"
        outer_frame = tk.LabelFrame(
            self.root_frame, **self.colors, text=" Your Containers ")
        outer_frame.pack(pady=10, expand=True, fill=tk.BOTH)

        header = tk.Frame(outer_frame, bg=self.colors["bg"])
        header.pack(fill=tk.X)

        label1 = tk.Label(
            header, text="Name", **self.colors)
        label1.pack(side=tk.LEFT, padx=5)

        label2 = tk.Label(
            header, text="Actions", **self.colors)
        label2.pack(side=tk.RIGHT, padx=160)

        s = ttk.Style()
        s.configure("TSeparator", background=self.colors["bg"])
        sep = ttk.Separator(outer_frame, orient="horizontal")
        sep.pack(fill=tk.X, pady=5)

        # inner scrollable frame
        # https://blog.teclado.com/tkinter-scrollable-frames/
        canvas = tk.Canvas(
            outer_frame,
            bg=self.colors["bg"],
            bd=0,
            highlightthickness=0)
        canvas.pack(expand=True, fill=tk.BOTH, side=tk.LEFT)
        canvas.bind_all(  # windows
            "<MouseWheel>",
            lambda e: canvas.yview_scroll(int(-1 * (e.delta // 120)), "units")
        )
        canvas.bind_all(  # linux
            "<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
        canvas.bind_all(  # linux
            "<Button-5>", lambda e: canvas.yview_scroll(1, "units"))

        scrollbar = tk.Scrollbar(
            outer_frame,
            orient=tk.VERTICAL,
            command=canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.containers_frame = tk.Frame(canvas, bg=self.colors["bg"])
        self.containers_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        self.containers_frame.grid(row=0, column=0, sticky="nsew")

        w_id = canvas.create_window(
            (0, 0), window=self.containers_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas_window = canvas.winfo_toplevel()
        canvas_window.bind(
            "<Configure>",
            lambda e: canvas.itemconfig(w_id, width=canvas.winfo_width())
        )

        # self.fill_frame_with_containers(self.containers_frame)
        self.fill_frame_with_containers()

        # add bottom buttons
        buttons_frame = tk.Frame(self.root_frame, bg=self.colors["bg"])
        buttons_frame.pack(side=tk.BOTTOM)

        new_container_button = tk.Button(
            buttons_frame, text="Add Container",
            command=lambda: self.container_action(
                Application.MenuOption.CREATE),
            **self.btn_focus_colors)
        new_container_button.pack(side=tk.RIGHT)

        def change_password():
            new_master_password = self.ask_for_master_password(
                "Enter the new master password for the vault.",
                exit_on_close=False)
            dialog = self.show_dialog(
                "Changing Master Password",
                "Encrypting vault contents with the new master password. Please wait...")
            self.vault.set_master_password(new_master_password)
            self.vault.save_to_file(SAVE_PATH)
            dialog.destroy()

        change_password_button = tk.Button(
            buttons_frame, text="Change master password",
            command=change_password,
            **self.btn_focus_colors)
        change_password_button.pack(side=tk.RIGHT, padx=10)

        outer_frame.focus_set()

    def pre_run(self) -> tk.PhotoImage:
        """
        Method to run before the main loop.
        Shows the logo and version of the application

        :return: the logo (so that it doesn't disappear)
        """
        self.root_frame = tk.Frame(self.root, bg=self.colors["bg"])
        self.root_frame.pack(expand=True)

        folder = os.path.dirname(os.path.abspath(__file__))
        logo_file = os.path.join(folder, "imgs/logo.png")

        # show vertically centered logo w/ version
        logo_big = tk.PhotoImage(file=logo_file)
        logo = tk.Label(self.root_frame, image=logo_big, borderwidth=0)
        logo.image = logo_big  # keep a reference
        logo.pack()

        authors = tk.Label(self.root_frame, text=AUTHORS, **self.colors)
        authors.pack()

        version = tk.Label(self.root_frame, text=APP_VERSION, **self.colors)
        version.pack()

        self.root.update()

        return logo_big  # return the logo so that it doesn't disappear

    def run(self):
        """
        Run the application in graphical mode using Tkinter
        """
        img = self.pre_run()

        sleep(0.2)

        self.login(
            dialog_open=self.show_dialog,
            dialog_close=lambda x: x.destroy())

        self.root_frame.destroy()

        self.list_containers()

        self.root.mainloop()


class CLIApplication(Application):
    """
    Class representing the application.
    Controls the flow of the application and renders the interface (CLI)
    """

    def __init__(self, parser: argparse.ArgumentParser):
        super().__init__()
        self.parser = parser
        self.master_password = None

        cli_options = self.parser.add_argument_group("CLI Options")
        group = cli_options.add_mutually_exclusive_group(required=True)
        group.add_argument(
            "--create",
            help="create new container (see --name/--text options below)",
            action="store_true")
        group.add_argument(
            "--view",
            metavar="CONTAINER_ID",
            help="view container contents (full vault integrity not verified)")
        group.add_argument(
            "--edit",
            metavar="CONTAINER_ID",
            help="edit container (see --name/--text options below)")
        group.add_argument(
            "--delete",
            metavar="CONTAINER_ID",
            help="delete container")
        group.add_argument(
            "--verify-integrity",
            help="verify the integrity of the vault",
            action="store_true")
        group.add_argument(
            "--upload",
            help="upload backup to the cloud (see --set-credentials)",
            action="store_true")
        group.add_argument(
            "--download",
            help="download backup from the cloud (see --set-credentials)",
            action="store_true")
        group.add_argument(
            "--change-password",
            help="change the master password of the vault",
            action="store_true")
        group.add_argument(
            "--regenerate-keys",
            help="regenerate all derived keys",
            action="store_true")
        group.add_argument(
            "--set-credentials",
            metavar="FILE",
            help="set Google Cloud credentials (OAuth 2.0) for backups")
        group.add_argument(
            "--sign-out",
            help="remove the token associated to your personal Google account (not the Google Cloud credentials)",
            action="store_true")
        group.add_argument(
            "--print-paths",
            help="print the paths of the save file and the configuration file",
            action="store_true")
        group.add_argument(
            "-v", "--version",
            help="print version and exit",
            action="version",
            version='%(prog)s ' + APP_VERSION)
        group.add_argument(
            "-h", "--help",
            action="help",
            help="print help message and exit")

        group = self.parser.add_argument_group("Options for --create, --edit")
        group.add_argument(
            "--name",
            help="Name for the container")
        group.add_argument(
            "--text",
            help="Text for the container")

        args, unknown = self.parser.parse_known_args()
        self.args = args

        # name cannot be empty
        if args.create:
            if args.text is None or args.name is None:
                err = "create requires --name and --text arguments"
                self.exit(err)
            if args.name == "":
                err = "name cannot be empty"
                self.exit(err)

        # name cannot be empty
        if args.edit and args.text is None and not args.name:
            err = "edit requires --name or --text argument"
            self.exit(err)

    def ask_for_master_password(self) -> str:
        """
        Ask the user for the master password

        :return: the master password entered by the user
        """
        if self.master_password is not None:
            return self.master_password
        return getpass.getpass("Enter your master password: ")

    def show_error(self, message: str):
        """
        Show error message to the user

        :param message: message to print
        """
        print("Error: ", message)

    def run(self):
        """
        Run the application in text mode
        """
        args = self.args

        if args.print_paths:
            print("Save file: ", SAVE_PATH)
            print("Config file: ", CONFIG_PATH)
            return

        if args.view:
            self.master_password = self.ask_for_master_password()
            try:
                c_info = Vault.fetch_container(
                    args.view, self.master_password,
                    SAVE_PATH).get_container_info()
            except Exception as e:
                self.show_error("Password may be incorrect or the file may have been tampered with.")
                return
            print(str(c_info["id"]) + ". " + c_info["name"])
            print(c_info["data"])
            return

        self.login()
        # Puede darse el caso de querer descargar la backup
        # ya que la integridad no se verifica. En ese caso, se
        # leen las credenciales de la backup y se descarga
        if args.download:
            if self.vault is None:
                self.vault = Vault(master_password)
                cred_container = Vault.fetch_container(
                    "-1", self.master_password, SAVE_PATH)
                token_container = Vault.fetch_container(
                    "-2", self.master_password, SAVE_PATH)
                self.vault.set_cloud_credentials(
                    cred_container.get_container_info()["data"],
                    token_container.get_container_info()["data"])

            # mv savefile to savefile.old
            if os.path.exists(SAVE_PATH):
                os.rename(
                    SAVE_PATH,
                    SAVE_PATH + ".old")
            # download savefile from GDrive
            self.vault.download_backup(SAVE_PATH)
            print("Vault downloaded")
            return

        if args.verify_integrity:
            print("Integrity verified")
            return

        if args.set_credentials:
            credentials = None
            with open(args.set_credentials, "r") as f:
                credentials = f.read()
            self.vault.set_cloud_credentials(credentials, None)
            self.vault.start_cloud()
            self.vault.save_to_file(SAVE_PATH)
            print("Credentials set")

        if args.sign_out:
            self.vault.set_cloud_credentials(None, "")
            self.vault.save_to_file(SAVE_PATH)
            print("Signed out")

        if args.create:
            self.vault.add_container(args.name, args.text)
            self.vault.save_to_file(SAVE_PATH)
            print("Container created")

        if args.edit:
            try:
                id = int(args.edit)
            except ValueError:
                print("error: edit argument must be a number")
                exit(1)
            self.vault.update_container(id, args.name, args.text)
            self.vault.save_to_file(SAVE_PATH)
            print("Container updated")

        if args.delete:
            self.vault.remove_container(int(args.delete))
            self.vault.save_to_file(SAVE_PATH)
            print("Container deleted")

        if args.upload:
            self.vault.upload_backup(SAVE_PATH)
            self.vault.save_to_file(SAVE_PATH)
            print("Vault uploaded")

        if args.change_password:
            self.master_password = None
            self.ask_for_master_password()
            self.vault.set_master_password(self.master_password)
            self.vault.save_to_file(SAVE_PATH)
            print("Master password changed")

        if args.regenerate_keys:
            self.vault.regenerate_keys()
            self.vault.save_to_file(SAVE_PATH)
            print("Keys regenerated")


# entry point
if __name__ == "__main__":
    app = None

    # only parse tui and gui arguments. Ignore any other arguments in that case
    parser = argparse.ArgumentParser(
        description=f"SecureBox {APP_VERSION}: a local password manager written in python.",
        add_help=False)
    mode = parser.add_argument_group(
        "Application mode",
        "Run the TUI/GUI versions instead of the default CLI.\
            If these are provided any other arguments will be ignored.")
    group = mode.add_mutually_exclusive_group()
    group.add_argument(
        "--tui",
        help="run the application in text mode",
        action="store_true")
    group.add_argument(
        "--gui",
        help="run the application in graphical mode",
        action="store_true")
    args, unknown = parser.parse_known_args()

    if args.tui:
        app = TUIApplication()
    elif args.gui:
        app = GUIApplication()
    else:
        app = CLIApplication(parser)

    app.run()
