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
Credit:
https://www.pexels.com/photo/gray-and-black-hive-printed-textile-691710/
https://github.com/nishantprj/custom_tkinter_login
https://codepen.io/argyleink/pen/abXvVME
"""
import tkinter as tk
from tkinter import *
import customtkinter
from PIL import ImageTk, Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import firebase_admin
from firebase_admin import db, credentials, initialize_app, storage
import random
import string
import numpy as np
import os
import time
import hashlib
import secrets
from tkinter import messagebox
import textwrap

customtkinter.set_appearance_mode("dark")  # Modes: system (default), light, dark
customtkinter.set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

MAX_NUM_OF_RECS = 999
pointer = 0

title_preview_text = ""

string_for_data = ""
array_for_CBC_mode = bytearray(16)
back_aes_key = bytearray(32)
decract = 0

aes_key = bytearray([
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
])

def back_aes_k():
    global back_aes_key
    back_aes_key = bytearray(aes_key)

def rest_aes_k():
    global aes_key
    aes_key = bytearray(back_aes_key)

def incr_aes_key():
    global aes_key
    i = 15
    while i >= 0:
        if aes_key[i] == 255:
            aes_key[i] = 0
            i -= 1
        else:
            aes_key[i] += 1
            break

def encrypt_iv_for_aes(iv):
    global array_for_CBC_mode
    array_for_CBC_mode = bytearray(iv)
    encrypt_with_aes(bytearray(iv))

def encrypt_with_aes(to_be_encrypted):
    global string_for_data
    global decract
    to_be_encrypted = bytearray(to_be_encrypted)  # Convert to mutable bytearray
    if decract > 0:
        for i in range(16):
            to_be_encrypted[i] ^= array_for_CBC_mode[i]
            
    cipher = AES.new(aes_key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(pad(to_be_encrypted, AES.block_size))
    incr_aes_key()
    if decract > 0:
        for i in range(16):
            if i < 16:
                array_for_CBC_mode[i] = int(encrypted_data[i])
    
    for i in range(16):
        if encrypted_data[i] < 16:
            string_for_data += "0"
        string_for_data += hex(encrypted_data[i])[2:]
    
    decract += 11
    
def decrypt_string_with_aes_in_cbc(ct):
    global decract
    global array_for_CBC_mode
    global string_for_data
    back_aes_k()
    clear_variables()
    ct_bytes = bytes.fromhex(ct)
    ext = 0
    decract = -1
    while len(ct) > ext:
        split_for_decr(ct_bytes, ext)
        ext += 16
        decract += 10

    rest_aes_k()

def split_for_decr(ct, p):
    global decract
    global array_for_CBC_mode
    global string_for_data

    res = bytearray(16)
    prev_res = bytearray(16)
    br = False

    for i in range(0, 16):
        if i + p > len(ct) - 1:
            br = True
            break
        res[i] = ct[i + p]

    for i in range(0, 16):
        if i + p - 16 > len(ct) - 1:
            break  # Skip if index is out of bounds
        prev_res[i] = ct[i + p - 16]

    if not br:
        if decract > 16:
            array_for_CBC_mode = prev_res[:]

        cipher_text = res
        ret_text = bytearray(16)

        cipher = AES.new(bytes(aes_key), AES.MODE_ECB)
        ret_text = bytearray(cipher.decrypt(bytes(cipher_text)))

        incr_aes_key()

        if decract > 2:
            for i in range(16):
                ret_text[i] ^= array_for_CBC_mode[i]

            for byte in ret_text:
                if byte > 0:
                    string_for_data += chr(byte)
                    

        if decract == -1:
            array_for_CBC_mode = ret_text[:]

        decract += 1

def decrypt_hash_with_aes_in_cbc(ct):
    global decract
    global array_for_CBC_mode
    global string_for_data
    back_aes_k()
    clear_variables()
    ct_bytes = bytes.fromhex(ct)
    ext = 0
    decract = -1
    while len(ct) > ext:
        split_for_decr_hash(ct_bytes, ext)
        ext += 16
        decract += 10

    rest_aes_k()

def split_for_decr_hash(ct, p):
    global decract
    global array_for_CBC_mode
    global string_for_data

    res = bytearray(16)
    prev_res = bytearray(16)
    br = False

    for i in range(0, 16):
        if i + p > len(ct) - 1:
            br = True
            break
        res[i] = ct[i + p]

    for i in range(0, 16):
        if i + p - 16 > len(ct) - 1:
            break  # Skip if index is out of bounds
        prev_res[i] = ct[i + p - 16]

    if not br:
        if decract > 16:
            array_for_CBC_mode = prev_res[:]

        cipher_text = res
        ret_text = bytearray(16)

        cipher = AES.new(bytes(aes_key), AES.MODE_ECB)
        ret_text = bytearray(cipher.decrypt(bytes(cipher_text)))

        incr_aes_key()

        if decract > 2:
            for i in range(16):
                ret_text[i] ^= array_for_CBC_mode[i]

            string_for_data += ''.join(format(byte, '02x') for byte in ret_text)
                    

        if decract == -1:
            array_for_CBC_mode = ret_text[:]

        decract += 1

def clear_variables():
    global string_for_data
    global decract
    string_for_data = ""
    decract = 0

def encr_str_with_aes():
    global string_for_data
    global decract
    back_aes_k()
    string_for_data = ""
    decract = 0
    
    iv = [secrets.randbelow(256) for _ in range(16)]  # Initialization vector
    encrypt_iv_for_aes(iv)

def encrypt_string_with_aes_in_cbc(input_string):
    global string_for_data
    global decract
    back_aes_k()
    string_for_data = ""
    decract = 0
    
    iv = [secrets.randbelow(256) for _ in range(16)]  # Initialization vector
    encrypt_iv_for_aes(iv)
    padded_length = (len(input_string) + 15) // 16 * 16
    padded_string = input_string.ljust(padded_length, '\x00')
    byte_arrays = [bytearray(padded_string[i:i+16], 'utf-8') for i in range(0, len(padded_string), 16)]
    
    for i, byte_array in enumerate(byte_arrays):
        encrypt_with_aes(byte_array)
    
    rest_aes_k()
    
def encrypt_hash_with_aes_in_cbc(input_string):
    global string_for_data
    global decract
    back_aes_k()
    string_for_data = ""
    decract = 0
    
    iv = [secrets.randbelow(256) for _ in range(16)]  # Initialization vector
    encrypt_iv_for_aes(iv)
    
    byte_array = bytearray.fromhex(input_string)
    array1 = byte_array[:16]
    array2 = byte_array[16:32]
    array3 = byte_array[32:48]
    array4 = byte_array[48:]
    encrypt_with_aes(array1)
    encrypt_with_aes(array2)
    encrypt_with_aes(array3)
    encrypt_with_aes(array4)
    
    rest_aes_k()

def move_left(event=None):
    global pointer
    global MAX_NUM_OF_RECS
    pointer -= 1
    if pointer < 1:
        pointer = MAX_NUM_OF_RECS
    update_cred_values()

def move_right(event=None):
    global pointer
    global MAX_NUM_OF_RECS
    pointer += 1
    if pointer > MAX_NUM_OF_RECS:
        pointer = 1
    update_cred_values()

# Function to update the slot label with the current pointer value
def update_cred_values():
    global ttl_lbl
    global viewloginentry
    global viewpasswordentry
    global viewwebsentry
    global integrity_when_viewed_label
    ttl_lbl.configure(text='Loading...')
    viewloginentry.configure(state='normal')
    viewpasswordentry.configure(state='normal')
    viewwebsentry.configure(state='normal')
    viewloginentry.delete(0, 'end')
    viewloginentry.insert(0, "Loading...")
    viewpasswordentry.delete(0, 'end')
    viewpasswordentry.insert(0, "Loading...")
    viewwebsentry.delete(0, 'end')
    viewwebsentry.insert(0, "Loading...")
    ttl_lbl.configure(text='Loading...')
    viewloginentry.configure(state='readonly')
    viewpasswordentry.configure(state='readonly')
    viewwebsentry.configure(state='readonly')
    integrity_when_viewed_label.configure(text='Loading...')
    global pointer
    global MAX_NUM_OF_RECS
    slotlbl.configure(text="Slot {}/{}".format(pointer, MAX_NUM_OF_RECS))
    get_and_decrypt_credential()

def unlock_app(entry_text, extr_encr_hash):
    hashed_password = hashlib.sha512(entry_text.encode()).hexdigest()
    #print("Hashed Password:", hashed_password)    
    # Split the hashed password into two halves
    first_half = hashed_password[:64]
    second_half = hashed_password[64:]
    second_hash = hashlib.sha512(second_half.encode()).hexdigest()
    # Update the aes_key with the first half
    global aes_key
    aes_key = bytearray.fromhex(first_half)
    #print("Second Half of Hashed Password:", second_half)
    app.destroy()
    if extr_encr_hash is None:
        set_password(second_hash)
    else:
        check_password(second_hash, extr_encr_hash)
  
def set_password(second_hash):
    encrypt_hash_with_aes_in_cbc(second_hash)
    db.reference("/").update({"mpass" : string_for_data})
    create_main_window()
    
def check_password(second_hash, extr_encr_hash):
    decrypt_hash_with_aes_in_cbc(extr_encr_hash)
    #print(string_for_data)
    #print(second_hash)
    if string_for_data == second_hash:
        create_main_window()
    else:
        messagebox.showerror("Error", "Wrong password!")

def get_and_decrypt_credential():
    global ttl_lbl
    global viewloginentry
    global viewpasswordentry
    global viewwebsentry
    global integrity_when_viewed_label
    viewloginentry.configure(state='normal')
    viewpasswordentry.configure(state='normal')
    viewwebsentry.configure(state='normal')
    extr_encr_ttl = db.reference("/L{}_ttl".format(pointer)).get()
    global deletelb1
    deletelb1.configure(text="Delete Record From The Slot N{}".format(pointer))
    if extr_encr_ttl is None:
        ttl_lbl.configure(text='Empty')
        viewloginentry.configure(state='normal')
        viewpasswordentry.configure(state='normal')
        viewwebsentry.configure(state='normal')
        viewloginentry.delete(0, 'end')
        viewloginentry.insert(0, "Empty")
        viewpasswordentry.delete(0, 'end')
        viewpasswordentry.insert(0, "Empty")
        viewwebsentry.delete(0, 'end')
        viewwebsentry.insert(0, "Empty")
        edittitleentry.delete(0, 'end')
        edittitleentry.insert(0, "Empty")
        editloginentry.delete(0, 'end')
        editloginentry.insert(0, "Empty")
        editpasswordentry.delete(0, 'end')
        editpasswordentry.insert(0, "Empty")
        editwebsentry.delete(0, 'end')
        editwebsentry.insert(0, "Empty")
        viewloginentry.configure(state='readonly')
        viewpasswordentry.configure(state='readonly')
        viewwebsentry.configure(state='readonly')

        integrity_when_viewed_label.configure(text="The Slot N{} Is Empty".format(pointer))
    else:
        decrypted_usn = None
        decrypted_psw = None
        decrypted_wbs = None
        decrypted_hash = None
        decrypt_string_with_aes_in_cbc(extr_encr_ttl)
        decrypted_ttl = string_for_data
        wrapped_text = textwrap.fill(string_for_data, width=440)
        ttl_lbl.configure(text=wrapped_text)
        edittitleentry.delete(0, 'end')
        edittitleentry.insert(0, decrypted_ttl)
        extr_encr_usn = db.reference("/L{}_usn".format(pointer)).get()
        if extr_encr_usn is None:
            decrypted_usn = "Failed To Retrieve!!!"
        else:
            decrypt_string_with_aes_in_cbc(extr_encr_usn)
            decrypted_usn = string_for_data
        editloginentry.delete(0, 'end')
        editloginentry.insert(0, decrypted_usn)
        viewloginentry.configure(state='normal')
        viewloginentry.delete(0, 'end')
        viewloginentry.insert(0, decrypted_usn)
        viewloginentry.configure(state='readonly')
        extr_encr_psw = db.reference("/L{}_psw".format(pointer)).get()
        if extr_encr_psw is None:
            decrypted_psw = "Failed To Retrieve!!!"
        else:
            decrypt_string_with_aes_in_cbc(extr_encr_psw)
            decrypted_psw = string_for_data
        editpasswordentry.delete(0, 'end')
        editpasswordentry.insert(0, decrypted_psw)
        viewpasswordentry.configure(state='normal')
        viewpasswordentry.delete(0, 'end')
        viewpasswordentry.insert(0, decrypted_psw)
        viewpasswordentry.configure(state='readonly')
        extr_encr_wbs = db.reference("/L{}_wbs".format(pointer)).get()
        if extr_encr_wbs is None:
            decrypted_wbs = "Failed To Retrieve!!!"
        else:
            decrypt_string_with_aes_in_cbc(extr_encr_wbs)
            decrypted_wbs = string_for_data
        editwebsentry.delete(0, 'end')
        editwebsentry.insert(0, decrypted_wbs)
        viewwebsentry.configure(state='normal')
        viewwebsentry.delete(0, 'end')
        viewwebsentry.insert(0, decrypted_wbs)
        viewwebsentry.configure(state='readonly')
        extr_encr_hash = db.reference("/L{}_hash".format(pointer)).get()
        if extr_encr_hash is None:
            decrypted_hash = "-1"
        else:
            decrypt_hash_with_aes_in_cbc(extr_encr_hash)
            decrypted_hash = string_for_data
        #print(decrypted_ttl)
        #print(decrypted_usn)
        #print(decrypted_psw)
        #print(decrypted_wbs)
        #print(decrypted_hash)
        to_be_hashed = decrypted_ttl + decrypted_usn + decrypted_psw + decrypted_wbs
        computed_hash = hashlib.sha512(to_be_hashed.encode()).hexdigest()
        #print(computed_hash)

        if decrypted_hash == computed_hash:
            integrity_when_viewed_label.configure(text="Integrity Verified Successfully")
            #print("Integrity Verified Successfully")
        else:
            integrity_when_viewed_label.configure(text="Integrity Verification Failed")
            #print("Integrity Verification Failed")

def clear_entries(tab_name):
    # Clear entries in the specified tab
    if tab_name == "Add Login":
        addtitleentry.delete(0, tk.END)
        addloginentry.delete(0, tk.END)
        addpasswordentry.delete(0, tk.END)
        addwebsentry.delete(0, tk.END)
    elif tab_name == "Edit Login":
        edittitleentry.delete(0, tk.END)
        editloginentry.delete(0, tk.END)
        editpasswordentry.delete(0, tk.END)
        editwebsentry.delete(0, tk.END)

def generate_password(tab_name):
    characters = string.ascii_letters + string.digits + string.punctuation
    password_length = random.randint(20, 34)
    generated_password = ''.join(secrets.choice(characters) for i in range(password_length))
    if tab_name == "Add Login":
        addpasswordentry.delete(0, tk.END)
        addpasswordentry.insert(0, generated_password)
    elif tab_name == "Edit Login":
        editpasswordentry.delete(0, tk.END)
        editpasswordentry.insert(0, generated_password)

def set_data_to_firebase(tab_name):
    if (pointer == 0):
        messagebox.showwarning("Warning", "Select the slot to continue.")
    else:
        entered_title = ""
        entered_username = ""
        entered_password = ""
        entered_website = ""
        if tab_name == "Add Login":
            #print("Content of entries in Add tab:")
            #print("Title:", addtitleentry.get())
            #print("Username:", addloginentry.get())
            #print("Password:", addpasswordentry.get())
            #print("Website:", addwebsentry.get())
            entered_title = addtitleentry.get()
            entered_username = addloginentry.get()
            entered_password = addpasswordentry.get()
            entered_website = addwebsentry.get()
        elif tab_name == "Edit Login":
            #print("Content of entries in Edit tab:")
            #print("Title:", edittitleentry.get())
            #print("Username:", editloginentry.get())
            #print("Password:", editpasswordentry.get())
            #print("Website:", editwebsentry.get())
            entered_title = edittitleentry.get()
            entered_username = editloginentry.get()
            entered_password = editpasswordentry.get()
            entered_website = editwebsentry.get()
        encrypt_string_with_aes_in_cbc(entered_title)
        db.reference("/").update({"/L{}_ttl".format(pointer) : string_for_data})
        encrypt_string_with_aes_in_cbc(entered_username)
        db.reference("/").update({"/L{}_usn".format(pointer) : string_for_data})
        encrypt_string_with_aes_in_cbc(entered_password)
        db.reference("/").update({"/L{}_psw".format(pointer) : string_for_data})
        encrypt_string_with_aes_in_cbc(entered_website)
        db.reference("/").update({"/L{}_wbs".format(pointer) : string_for_data})
        title_username_password_website = entered_title + entered_username + entered_password + entered_website
        hashed_data = hashlib.sha512(title_username_password_website.encode()).hexdigest()
        encrypt_hash_with_aes_in_cbc(hashed_data)
        db.reference("/").update({"/L{}_hash".format(pointer) : string_for_data})
        update_cred_values()
        messagebox.showinfo("Midbar | מדבר", "Slot content modified successfully!")

def delete_record():
    if (pointer == 0):
        messagebox.showwarning("Warning", "Select the slot to continue.")
    else:
        confirm_delete = messagebox.askyesno("Delete Record From Slot N{}".format(pointer), "Are you sure you want to delete that record?")
        if confirm_delete:
            # Delete the files
            db.reference("/L{}_ttl".format(pointer)).delete()
            db.reference("/L{}_usn".format(pointer)).delete()
            db.reference("/L{}_psw".format(pointer)).delete()
            db.reference("/L{}_wbs".format(pointer)).delete()
            db.reference("/L{}_hash".format(pointer)).delete()
            messagebox.showinfo("Midbar | מדבר", "Record deleted successfully!")
            update_cred_values()
        else:
            messagebox.showinfo("Midbar | מדבר", "Operation has been cancelled by user")

def create_main_window():
    customtkinter.set_appearance_mode("dark")  # Modes: system (default), light, dark
    global pointer
    global MAX_NUM_OF_RECS
    vf = customtkinter.CTk()
    vf.geometry("1024x540")
    vf.title("Midbar | מדבר")
    img1 = ImageTk.PhotoImage(Image.open("./assets/pattern.jpg"))
    vfl1 = customtkinter.CTkLabel(master=vf, image=img1)
    vfl1.pack()
    vfl1.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
    frame = customtkinter.CTkFrame(master=vfl1, width=540, height=390)
    frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
    left_arrow_unicode = "\u2190"
    button1 = customtkinter.CTkButton(master=frame, width=28, text=left_arrow_unicode, command=move_left, corner_radius=6)
    button1.place(x=10, y=10)
    global slotlbl
    slotlbl = customtkinter.CTkLabel(master=frame, text="Press Any Arrow", anchor="center", width=440, font=('Century Gothic', 20))
    slotlbl.place(x=50, y=10)
    global ttl_lbl
    wrapped_text = textwrap.fill(title_preview_text, width=440)  # Adjust the width as needed
    ttl_lbl = customtkinter.CTkLabel(master=frame, text=wrapped_text, anchor="center", font=('Century Gothic', 20), wraplength=440)
    ttl_lbl.place(x=50, y=60)
    right_arrow_unicode = "\u2192"
    button2 = customtkinter.CTkButton(master=frame, width=28, text=right_arrow_unicode, command=move_right, corner_radius=6)
    button2.place(x=502, y=10)
    vf.bind("<Left>", move_left)
    vf.bind("<Right>", move_right)
    op_tabs = customtkinter.CTkTabview(master=frame,
                                   width=520, height=200,
                                   segmented_button_selected_color="#E41E5A",
                                   segmented_button_selected_hover_color="#E41E5A",
                                   segmented_button_unselected_color="#222222",
                                   segmented_button_unselected_hover_color="#222222"
                                   )
    op_tabs.place(x=10, y=180)
    add_tab = op_tabs.add("Add Login")
    addbutton = customtkinter.CTkButton(master=add_tab, width=94, text="Add", corner_radius=6, command=lambda: set_data_to_firebase("Add Login"))
    addbutton.place(x=416, y=45)
    genbutton = customtkinter.CTkButton(master=add_tab, width=94, text="Generate", corner_radius=6, command=lambda: generate_password("Add Login"))
    genbutton.place(x=416, y=80)
    clearbutton = customtkinter.CTkButton(master=add_tab, width=94, text="Clear", corner_radius=6, command=lambda: clear_entries("Add Login"))
    clearbutton.place(x=416, y=115)
    addtitlelb = customtkinter.CTkLabel(master=add_tab, text="Title", width=50, font=('Segoe UI Semibold', 16))
    addtitlelb.place(x=20, y=10)
    global addtitleentry
    addtitleentry = customtkinter.CTkEntry(master=add_tab, width=300, font=('Segoe UI Semibold', 16))
    addtitleentry.place(x=100, y=10)
    addloginlb = customtkinter.CTkLabel(master=add_tab, text="Username", width=50, font=('Segoe UI Semibold', 16))
    addloginlb.place(x=20, y=45)
    global addloginentry
    addloginentry = customtkinter.CTkEntry(master=add_tab, width=300, font=('Segoe UI Semibold', 16))
    addloginentry.place(x=100, y=45)
    addpasswordlb = customtkinter.CTkLabel(master=add_tab, text="Password", width=50, font=('Segoe UI Semibold', 16))
    addpasswordlb.place(x=20, y=80)
    global addpasswordentry
    addpasswordentry = customtkinter.CTkEntry(master=add_tab, width=300, font=('Segoe UI Semibold', 16))
    addpasswordentry.place(x=100, y=80)
    addwebslb = customtkinter.CTkLabel(master=add_tab, text="Website", width=50, font=('Segoe UI Semibold', 16))
    addwebslb.place(x=20, y=115)
    global addwebsentry
    addwebsentry = customtkinter.CTkEntry(master=add_tab, width=300, font=('Segoe UI Semibold', 16))
    addwebsentry.place(x=100, y=115)
    edit_tab = op_tabs.add("Edit Login")
    editbutton = customtkinter.CTkButton(master=edit_tab, width=94, text="Edit", corner_radius=6, command=lambda: set_data_to_firebase("Edit Login"))
    editbutton.place(x=416, y=45)
    genbutton = customtkinter.CTkButton(master=edit_tab, width=94, text="Generate", corner_radius=6, command=lambda: generate_password("Edit Login"))
    genbutton.place(x=416, y=80)
    clearbutton = customtkinter.CTkButton(master=edit_tab, width=94, text="Clear", corner_radius=6, command=lambda: clear_entries("Edit Login"))
    clearbutton.place(x=416, y=115)
    edittitlelb = customtkinter.CTkLabel(master=edit_tab, text="Title", width=50, font=('Segoe UI Semibold', 16))
    edittitlelb.place(x=20, y=10)
    global edittitleentry
    edittitleentry = customtkinter.CTkEntry(master=edit_tab, width=300, font=('Segoe UI Semibold', 16))
    edittitleentry.place(x=100, y=10)
    editloginlb = customtkinter.CTkLabel(master=edit_tab, text="Username", width=50, font=('Segoe UI Semibold', 16))
    editloginlb.place(x=20, y=45)
    global editloginentry
    editloginentry = customtkinter.CTkEntry(master=edit_tab, width=300, font=('Segoe UI Semibold', 16))
    editloginentry.place(x=100, y=45)
    editpasswordlb = customtkinter.CTkLabel(master=edit_tab, text="Password", width=50, font=('Segoe UI Semibold', 16))
    editpasswordlb.place(x=20, y=80)
    global editpasswordentry
    editpasswordentry = customtkinter.CTkEntry(master=edit_tab, width=300, font=('Segoe UI Semibold', 16))
    editpasswordentry.place(x=100, y=80)
    editwebslb = customtkinter.CTkLabel(master=edit_tab, text="Website", width=50, font=('Segoe UI Semibold', 16))
    editwebslb.place(x=20, y=115)
    global editwebsentry
    editwebsentry = customtkinter.CTkEntry(master=edit_tab, width=300, font=('Segoe UI Semibold', 16))
    editwebsentry.place(x=100, y=115)
    delete_tab = op_tabs.add("Delete Login")
    global deletelb1
    deletelb1 = customtkinter.CTkLabel(master=delete_tab, text="Select The Slot To Delete Record From", width=500, font=('Segoe UI Semibold', 16))
    deletelb1.place(x=10, y=10)
    deletelb2 = customtkinter.CTkLabel(master=delete_tab, text="This Can't Be Undone", width=500, font=('Segoe UI Semibold', 16))
    deletelb2.place(x=10, y=45)
    deletelb3 = customtkinter.CTkLabel(master=delete_tab, text="Would You Like To Continue?", width=500, font=('Segoe UI Semibold', 16))
    deletelb3.place(x=10, y=80)
    deletebutton = customtkinter.CTkButton(master=delete_tab, width=220, text="Yes, Delete That Record", corner_radius=6, command=delete_record)
    deletebutton.place(x=150, y=115)
    view_tab = op_tabs.add("View Login")
    viewloginlb = customtkinter.CTkLabel(master=view_tab, text="Username", width=50, font=('Segoe UI Semibold', 16))
    viewloginlb.place(x=20, y=10)
    global viewloginentry
    viewloginentry = customtkinter.CTkEntry(master=view_tab, width=400, font=('Segoe UI Semibold', 16), placeholder_text="Loading...", state="readonly")
    viewloginentry.place(x=100, y=10)
    viewpasswordlb = customtkinter.CTkLabel(master=view_tab, text="Password", width=50, font=('Segoe UI Semibold', 16))
    viewpasswordlb.place(x=20, y=45)
    global viewpasswordentry
    viewpasswordentry = customtkinter.CTkEntry(master=view_tab, width=400, font=('Segoe UI Semibold', 16), placeholder_text="Loading...", state="readonly")
    viewpasswordentry.place(x=100, y=45)
    viewwebslb = customtkinter.CTkLabel(master=view_tab, text="Website", width=50, font=('Segoe UI Semibold', 16))
    viewwebslb.place(x=20, y=80)
    global viewwebsentry
    viewwebsentry = customtkinter.CTkEntry(master=view_tab, width=400, font=('Segoe UI Semibold', 16), placeholder_text="Loading...", state="readonly")
    viewwebsentry.place(x=100, y=80)
    global integrity_when_viewed_label
    integrity_when_viewed_label = customtkinter.CTkLabel(master=view_tab, text="", width=480, font=('Segoe UI Semibold', 16))
    integrity_when_viewed_label.place(x=20, y=120)
    about_tab = op_tabs.add("About")
    al = customtkinter.CTkLabel(master=about_tab, text="Midbar Firebase Edition V2.0", width=500, font=('Segoe UI Semibold', 16))
    al.place(x=10, y=10)
    al1 = customtkinter.CTkLabel(master=about_tab, text="Developed by Maxim Bortnikov", width=500, font=('Segoe UI Semibold', 16))
    al1.place(x=10, y=45)
    aboutlb = customtkinter.CTkLabel(master=about_tab, text="SourceForge", width=50, font=('Segoe UI Semibold', 16))
    aboutlb.place(x=10, y=80)
    aboutentry = customtkinter.CTkEntry(master=about_tab, width=390, font=('Segoe UI Semibold', 16), placeholder_text="sourceforge.net/projects/midbar-firebase-edition/")
    aboutentry.place(x=110, y=80)
    about1lb = customtkinter.CTkLabel(master=about_tab, text="Github", width=50, font=('Segoe UI Semibold', 16))
    about1lb.place(x=10, y=115)
    about1entry = customtkinter.CTkEntry(master=about_tab, width=390, font=('Segoe UI Semibold', 16), placeholder_text="github.com/Northstrix/Midbar-Firebase-Edition")
    about1entry.place(x=110, y=115)
    aboutentry.configure(state='readonly')
    about1entry.configure(state='readonly')
    vf.mainloop()

#create_main_window()
customtkinter.set_appearance_mode("light")  # Modes: system (default), light, dark
db_url_file_name = open("db_url.txt", "r")
db_url = db_url_file_name.read()
db_url_file_name.close()
cred = credentials.Certificate("firebase key.json")
firebase_admin.initialize_app(cred, {"databaseURL": db_url})
#db.reference("/").update({"Test File" : "Content"})
extr_encr_hash = db.reference("/mpass").get()
if extr_encr_hash is None:
    entry_hint = 'Set Your Master Password'
else:
    entry_hint = 'Enter Your Master Password'
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
l2.place(x=40, y=45)

mpentry = customtkinter.CTkEntry(master=frame, width=220, placeholder_text=entry_hint, show="#")
mpentry.place(x=40, y=95)

# Create custom button
button1 = customtkinter.CTkButton(master=frame, width=220, text="Continue", command=lambda: unlock_app(mpentry.get(), extr_encr_hash), corner_radius=6)
button1.place(x=40, y=145)

mpentry.bind("<Return>", lambda event: unlock_app(mpentry.get(), extr_encr_hash))

app.mainloop()