"""
Midbar Firebase Edition
Distributed under the MIT License
© Copyright Maxim Bortnikov 2024
For more information please visit
https://sourceforge.net/projects/midbar-firebase-edition/
https://github.com/Northstrix/Midbar-Firebase-Edition
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/mobizt/Firebase-ESP32
"""
import tkinter as tk
from tkinter import ttk
import sv_ttk
import hashlib

class PasswordForm(ttk.Frame):
    def __init__(self, parent):
        ttk.Frame.__init__(self, parent)

        # Make the form responsive
        self.grid_rowconfigure(0, weight=1)  # First row
        self.grid_rowconfigure(1, weight=1)  # Second row
        self.grid_rowconfigure(2, weight=1)  # Third row
        self.grid_columnconfigure(0, weight=1)  # Single column

        # Create widgets
        self.setup_widgets()

    def setup_widgets(self):
        # First row: Label for master password
        master_password_label = ttk.Label(self, text="Enter Your Master Password", font=("TkDefaultFont", 12, "bold"))
        master_password_label.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        # Second row: Entry for password input
        self.password_entry = ttk.Entry(self, show="*")  # Show asterisks instead of actual characters
        self.password_entry.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        # Bind the Return key to the hash_password method for the entry widget
        self.password_entry.bind("<Return>", lambda event: self.hash_password())

        # Third row: Container for buttons
        button_container = ttk.Frame(self)
        button_container.grid(row=2, column=0, padx=5, pady=5, sticky="nsew")

        # Continue Button
        continue_button = ttk.Button(button_container, text=" Continue ", command=self.hash_password, style="Accent.TButton")
        continue_button.pack(side="left", padx=5, pady=5)

        # Cancel Button
        cancel_button = ttk.Button(button_container, text="   Cancel   ", command=root.destroy)
        cancel_button.pack(side="left", padx=5, pady=5)

        # Bind the Escape key to the root.destroy method
        self.master.bind("<Escape>", lambda event: root.destroy())

    def hash_password(self):
        password = self.password_entry.get()
        hashed_password = hashlib.sha512(password.encode()).hexdigest()
        print("Hashed Password:", hashed_password)

if __name__ == "__main__":
    root = tk.Tk()
    assert sv_ttk.get_theme(root=root) == ttk.Style(root).theme_use()

    sv_ttk.set_theme("dark", root=root)
    assert sv_ttk.get_theme(root=root) == "dark"

    style = ttk.Style()

    pf = PasswordForm(root)
    pf.grid(row=0, column=0, sticky="nsew")  # Grid the app frame in the main window
    root.grid_rowconfigure(0, weight=1)  # Allow the app frame to resize with the window
    root.grid_columnconfigure(0, weight=1)

    # Set the window size
    root.geometry("280x140")  # Adjusted height for the single row
    root.update()
    root.minsize(root.winfo_width(), root.winfo_height())
    root.mainloop()
