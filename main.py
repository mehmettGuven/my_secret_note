from tkinter import *
from tkinter import messagebox
import base64


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key,enc):
    dec=[]
    enc= base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return ''.join(dec)

def save_and_encrypt_notes():
    title=title_entry.get()
    message= secret_text_area.get(1.0,END)
    master_key= master_key_entry.get()

    if len(title) == 0 or len(message) == 0 or len(master_key) == 0 :
        messagebox.showinfo(title="Error!",message="Please enter all information.")
    else:
        message_encrypted = encode(master_key,message)
        try:
            with open("my_secret.txt", "a") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        except FileNotFoundError:
            with open("my_secret.txt", "w") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        finally:
            title_entry.delete(0,END)
            secret_text_area.delete("1.0",END)
            master_key_entry.delete(0,END)

def decrypt_notes():
    message_encrypted=secret_text_area.get("1.0", END)
    master_key = master_key_entry.get()

    if len(message_encrypted)==0 or len(master_key)==0:
        messagebox.showinfo(title="Error!", message="Please enter all information!" )
    else:
        try:
            decrypted_message = decode(master_key,message_encrypted)
            secret_text_area.delete("1.0",END)
            secret_text_area.insert("1.0",decrypted_message)
        except:
            messagebox.showinfo(title="Error!",message="Please make sureof encrypted info.")



#ui
screen=Tk()
screen.title('Secret Notes')
screen.config(pady=30,padx=30)

title_label = Label(text="Enter your title",font=("Arial",9,"bold"))
title_label.pack()
title_label.config(padx=10,pady=10)
title_entry = Entry(width=32)
title_entry.pack()
secret_text_label = Label(text="Enter your secret",font=("Arial",9,"bold"))
secret_text_label.pack()
secret_text_label.config(padx=10,pady=10)
secret_text_area = Text(width=24,height=5)
secret_text_area.pack()
master_key_label = Label(text="Enter master key",font=("Arial",9,"bold"))
master_key_label.pack()
master_key_label.config(padx=10,pady=10)
master_key_entry = Entry(width=32)
master_key_entry.pack()
save_button = Button(text="Save & Encrypt",command=save_and_encrypt_notes)
save_button.pack()
decrypt_button = Button(text="Decrypt", command=decrypt_notes)
decrypt_button.pack()



screen.mainloop()