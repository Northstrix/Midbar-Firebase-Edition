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

class ViewRecordForm:
    def __init__(self):
        self.view_record_form = None

    def on_ok_pressed(self):
        # Destroy the form when the OK button is pressed
        self.view_record_form.destroy()  

    def update_entry_text(self, text):
        # Update text of all entry widgets
        ttlentry.configure(state='normal')
        loginentry.configure(state='normal')
        passwordentry.configure(state='normal')
        websiteentry.configure(state='normal')
        
        ttlentry.delete(0, 'end')
        loginentry.delete(0, 'end')
        passwordentry.delete(0, 'end')
        websiteentry.delete(0, 'end')
        
        ttlentry.insert(0, text)
        loginentry.insert(0, text)
        passwordentry.insert(0, text)
        websiteentry.insert(0, text)
        
        ttlentry.configure(state='readonly')
        loginentry.configure(state='readonly')
        passwordentry.configure(state='readonly')
        websiteentry.configure(state='readonly')

    def show_form(self):
        self.view_record_form = customtkinter.CTk()
        self.view_record_form.geometry("520x680")
        self.view_record_form.title("Record From Slot N")
        img1 = ImageTk.PhotoImage(Image.open("pattern.jpg"))
        vfl1 = customtkinter.CTkLabel(master=self.view_record_form, image=img1)
        vfl1.pack()
        vfl1.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        frame = customtkinter.CTkFrame(master=vfl1, width=340, height=500, corner_radius=15)
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        hl = customtkinter.CTkLabel(master=frame, text="מדבר", width=320, anchor="center", font=('Arial Bold', 54))
        hl.place(x=10, y=10)
        ttllb = customtkinter.CTkLabel(master=frame, text="Title", width=300, font=('Segoe UI Semibold', 20))
        ttllb.place(x=20, y=100)
        global ttlentry
        ttlentry = customtkinter.CTkEntry(master=frame, width=290, font=('Arial', 16), placeholder_text="", state="readonly")
        ttlentry.place(x=25, y=137)
        global loginentry
        loginlb = customtkinter.CTkLabel(master=frame, text="Login", width=300, font=('Segoe UI Semibold', 20))
        loginlb.place(x=20, y=170)
        loginentry = customtkinter.CTkEntry(master=frame, width=290, font=('Arial', 16), placeholder_text="", state="readonly")
        loginentry.place(x=25, y=207)
        global passwordentry
        passwordlb = customtkinter.CTkLabel(master=frame, text="Password", width=300, font=('Segoe UI Semibold', 20))
        passwordlb.place(x=20, y=250)
        passwordentry = customtkinter.CTkEntry(master=frame, width=290, font=('Arial', 16), placeholder_text="", state="readonly")
        passwordentry.place(x=25, y=287)
        global websiteentry
        websitelb = customtkinter.CTkLabel(master=frame, text="Website", width=300, font=('Segoe UI Semibold', 20))
        websitelb.place(x=20, y=320)
        websiteentry = customtkinter.CTkEntry(master=frame, width=290, font=('Arial', 16), placeholder_text="", state="readonly")
        websiteentry.place(x=25, y=357)
        button1 = customtkinter.CTkButton(master=frame, width=260, text="Ok", font=('Segoe UI Semibold', 20), corner_radius=6)
        button1.place(x=40, y=410)
        intvrlb = customtkinter.CTkLabel(master=frame, text="Integrity Verified Successfully", width=300, font=('Segoe UI Semibold', 16))
        intvrlb.place(x=20, y=460)

        # Bind the button to update the text of all entry widgets
        button1.configure(command=lambda: self.update_entry_text("New Text"))

        self.view_record_form.mainloop()

# Create an instance of ViewRecordForm and display the form
view_record_form_instance = ViewRecordForm()
view_record_form_instance.show_form()
