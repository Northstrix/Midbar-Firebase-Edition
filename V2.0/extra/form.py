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
import customtkinter
from PIL import ImageTk, Image

customtkinter.set_appearance_mode("system")  # Modes: system (default), light, dark
customtkinter.set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

MAX_NUM_OF_RECS = 999
pointer = 1

def move_left(event=None):
    global pointer
    global MAX_NUM_OF_RECS
    pointer -= 1
    if pointer < 1:
        pointer = MAX_NUM_OF_RECS
    update_slot_label()

# Function to handle right arrow button press
def move_right(event=None):
    global pointer
    global MAX_NUM_OF_RECS
    pointer += 1
    if pointer > MAX_NUM_OF_RECS:
        pointer = 1
    update_slot_label()

# Function to update the slot label with the current pointer value
def update_slot_label():
    global pointer
    global MAX_NUM_OF_RECS
    slotlbl.configure(text="Slot {}/{}".format(pointer, MAX_NUM_OF_RECS))

def add_record(event=None):
    print("add")
    
def edit_record(event=None):
    print("edit")
    
def delete_record(event=None):
    print("delete")
    
def view_record(event=None):
    print("view")

def unlock_app(entry_text):
    global pointer
    global MAX_NUM_OF_RECS
    app.destroy()  # destroy current window
    vf = customtkinter.CTk()
    vf.geometry("680x220")
    vf.title("Midbar | מדבר")
    img1 = ImageTk.PhotoImage(Image.open("./assets/pattern.jpg"))
    vfl1 = customtkinter.CTkLabel(master=vf, image=img1)
    vfl1.pack()
    vfl1.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
    frame = customtkinter.CTkFrame(master=vfl1, width=540, height=168, corner_radius=15)
    frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
    left_arrow_unicode = "\u2190"
    button1 = customtkinter.CTkButton(master=frame, width=28, text=left_arrow_unicode, command=move_left, corner_radius=6)
    button1.place(x=10, y=10)
    global slotlbl  # Declare slotlbl as global
    slotlbl = customtkinter.CTkLabel(master=frame, text="Slot {}/{}".format(pointer, MAX_NUM_OF_RECS), anchor="center", width=258, font=('Century Gothic', 20))
    slotlbl.place(x=50, y=10)
    right_arrow_unicode = "\u2192"
    button2 = customtkinter.CTkButton(master=frame, width=28, text=right_arrow_unicode, command=move_right, corner_radius=6)
    button2.place(x=320, y=10)
    vf.bind("<Left>", move_left)
    vf.bind("<Right>", move_right)
    add_login = customtkinter.CTkButton(master=frame, width=170, text="Add Login", command=add_record, corner_radius=6)
    add_login.place(x=360, y=10)
    edit_login = customtkinter.CTkButton(master=frame, width=170, text="Edit Login", command=edit_record, corner_radius=6)
    edit_login.place(x=360, y=50)
    delete_login = customtkinter.CTkButton(master=frame, width=170, text="Delete Login", command=delete_record, corner_radius=6)
    delete_login.place(x=360, y=90)
    view_login = customtkinter.CTkButton(master=frame, width=170, text="View Login", command=view_record, corner_radius=6)
    view_login.place(x=360, y=130)
    vf.bind("<a>", add_record)
    vf.bind("<e>", edit_record)
    vf.bind("<d>", delete_record)
    vf.bind("<v>", view_record)
    vf.mainloop()


app = customtkinter.CTk()  # creating custom tkinter window
app.geometry("800x640")
app.title("Midbar | מדבר")

img1 = ImageTk.PhotoImage(Image.open("./assets/pattern.jpg"))
l1 = customtkinter.CTkLabel(master=app, image=img1)
l1.pack()

# creating custom frame
frame = customtkinter.CTkFrame(master=l1, width=300, height=220, corner_radius=15)
frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

l2 = customtkinter.CTkLabel(master=frame, text="Unlock Midbar", font=('Century Gothic', 20))
l2.place(x=50, y=45)

mpentry = customtkinter.CTkEntry(master=frame, width=220, placeholder_text='Enter Your Master Password', show="#")
mpentry.place(x=50, y=95)

# Create custom button
button1 = customtkinter.CTkButton(master=frame, width=220, text="Continue", command=lambda: unlock_app(mpentry.get()), corner_radius=6)
button1.place(x=50, y=145)

mpentry.bind("<Return>", lambda event: unlock_app(mpentry.get()))

app.mainloop()
