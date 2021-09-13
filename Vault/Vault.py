try:
    import tkinter as tk
    from tkinter import *
    from tkinter.ttk import *
    import sqlite3
    from tkinter import messagebox
    from datetime import datetime
    import getpass
    import csv
    import os
    from cryptography.fernet import Fernet
    import ctypes
    import base64
    import webbrowser
    import hashlib
    import cv2
    import time
    import random
    import re
    import shutil
    import time
    import onetimepad
    from Cryptodome.Cipher import AES as domeAES
    from Cryptodome.Random import get_random_bytes
    from Crypto import Random
    from Crypto.Cipher import AES as cryptoAES
    import pyAesCrypt
    import pyperclip
    import sys
    from elevate import elevate
    from zipfile import ZipFile
    from tld import get_fld
    from PIL import Image, ImageDraw, ImageFont, ImageGrab, ImageTk

    class CreateToolTip(object):
        def __init__(self, widget, width, height, text='widget info'):
            self.waittime = 500
            self.wraplength = 180 
            self.widget = widget
            self.text = text
            self.width = width
            self.height = height
            self.widget.bind("<Enter>", self.enter)
            self.widget.bind("<Leave>", self.leave)
            self.widget.bind("<ButtonPress>", self.leave)
            self.id = None
            self.tw = None

        def enter(self, event=None):
            self.widget.configure(background="gray85")
            self.schedule()

        def leave(self, event=None):
            self.widget.configure(background="SystemButtonFace")
            self.unschedule()
            self.hidetip()

        def schedule(self):
            self.unschedule()
            self.id = self.widget.after(self.waittime, self.showtip)

        def unschedule(self):
            id = self.id
            self.id = None
            if id:
                self.widget.after_cancel(id)

        def showtip(self, event=None):
            x = y = 0
            x, y, cx, cy = self.widget.bbox("insert")
            x += self.widget.winfo_rootx() + self.width
            y += self.widget.winfo_rooty() + self.height
            self.tw = Toplevel(self.widget)
            self.tw.wm_overrideredirect(True)
            self.tw.wm_geometry("+%d+%d" % (x, y))
            label = Label(self.tw, text=self.text, justify='left',
                           background="#ffffff", relief='solid', borderwidth=1,
                           wraplength = self.wraplength)
            label.pack(ipadx=1)

        def hidetip(self):
            tw = self.tw
            self.tw= None
            if tw:
                tw.destroy()

    def encryptFile():
        user = getpass.getuser()
        file = r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key'
        if os.path.exists(file):
            with open(file, 'rb') as f:
                    file_data = f.read()
            password = decryptMessage(file_data.decode())
        else:
            decryptFile()
            with open(file, 'rb') as f:
                    file_data = f.read()
            password = decryptMessage(file_data.decode())
        if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db'):
            buffersize = 64*1024
            pyAesCrypt.encryptFile(r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db', r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db.aes', password, buffersize)
            os.remove(r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db')
        if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key'):
            buffersize = 64*1024
            password = encryptMessage("b2844889272487db8f0bbf287729534aa0d6186339e3cdb26663c51540e99505ef2ef03b2f58bf05c4a4c060fd5f160370ac1a4e16535d7bfb32162f797329fb")
            pyAesCrypt.encryptFile(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key', r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key.aes', password, buffersize)
            os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key')

    def decryptFile():
        user = getpass.getuser()
        if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key.aes'):
            buffersize = 64*1024
            password = encryptMessage("b2844889272487db8f0bbf287729534aa0d6186339e3cdb26663c51540e99505ef2ef03b2f58bf05c4a4c060fd5f160370ac1a4e16535d7bfb32162f797329fb")
            pyAesCrypt.decryptFile(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key.aes', r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key', password, buffersize)
            os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key.aes')
        file = r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key'
        if os.path.exists(file):
            with open(file, 'rb') as f:
                    file_data = f.read()
            password = decryptMessage(file_data.decode())
        if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db.aes'):
            buffersize = 64*1024
            pyAesCrypt.decryptFile(r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db.aes', r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db', password, buffersize)
            os.remove(r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db.aes')

    def encrypt_str(raw, password):
        BLOCK_SIZE = cryptoAES.block_size
        key = password.encode()
        __key__ = hashlib.sha256(key).digest()
        BS = cryptoAES.block_size
        pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
        raw = base64.b64encode(pad(raw).encode('utf8'))
        iv = get_random_bytes(cryptoAES.block_size)
        cipher = cryptoAES.new(key= __key__, mode= cryptoAES.MODE_CFB,iv= iv)
        a= base64.b64encode(iv + cipher.encrypt(raw))
        IV = Random.new().read(BLOCK_SIZE)
        aes = domeAES.new(__key__, domeAES.MODE_CFB, IV)
        b = base64.b64encode(IV + aes.encrypt(a))
        return b.decode()

    def decrypt_str(enc, password):
        BLOCK_SIZE = cryptoAES.block_size
        key = password.encode()
        __key__ = hashlib.sha256(key).digest()
        passphrase = __key__
        enc = enc.encode()
        encrypted = base64.b64decode(enc)
        IV = encrypted[:BLOCK_SIZE]
        aes = domeAES.new(passphrase, domeAES.MODE_CFB, IV)
        enc = aes.decrypt(encrypted[BLOCK_SIZE:])
        unpad = lambda s: s[:-ord(s[-1:])]
        enc = base64.b64decode(enc)
        iv = enc[:cryptoAES.block_size]
        cipher = cryptoAES.new(__key__, cryptoAES.MODE_CFB, iv)
        b=  unpad(base64.b64decode(cipher.decrypt(enc[cryptoAES.block_size:])).decode('utf8'))
        return b

    def checkenc(string):
        try:
            decryptMessage(string)
        except:
            return False
        else:
            return True

    def encryptKey():
        user = getpass.getuser()
        if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key'):
            file = r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key'
            with open(file, 'rb') as f:
                file_data = f.read()
            with open(file, 'wb') as f:
                f.write(encryptMessage(file_data.decode()).encode('utf-8'))
    def decryptKey():
        user = getpass.getuser()
        if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key'):
            file = r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key'
            with open(file, 'rb') as f:
                file_data = f.read()
            if checkenc(file_data.decode()):
                with open(file, 'wb') as f:
                    f.write(decryptMessage(file_data.decode()).encode('utf-8'))
            else:
                pass

    def safeKey():
        user = getpass.getuser()
        if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key'):
            buffersize = 64*1024
            password = encryptMessage("b2844889272487db8f0bbf287729534aa0d6186339e3cdb26663c51540e99505ef2ef03b2f58bf05c4a4c060fd5f160370ac1a4e16535d7bfb32162f797329fb")
            pyAesCrypt.encryptFile(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key', r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key.aes', password, buffersize)
            os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key')

    def unsafeKey():
        if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key.aes'):
            buffersize = 64*1024
            password = encryptMessage("b2844889272487db8f0bbf287729534aa0d6186339e3cdb26663c51540e99505ef2ef03b2f58bf05c4a4c060fd5f160370ac1a4e16535d7bfb32162f797329fb")
            pyAesCrypt.decryptFile(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key.aes', r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key', password, buffersize)
            os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key.aes')
            
    def increment(s):
        s =  s[::-1]
        cip = ""
        cip2 = ""
        for i in range(len(s)):
            cip += (chr(ord(s[i])+7))
        for i in range(len(cip)):
            cip2 += (chr(ord(cip[i])+13))
        return cip2

    def decrement(x):
        x =  x[::-1]
        deci = ""
        deci2 = ""
        for i in range(len(x)):
            deci += (chr(ord(x[i])-7))
        for i in range(len(deci)):
            deci2 += (chr(ord(deci[i])-13))
        return deci2
    
    def encryptMessage(enc):
        return onetimepad.encrypt(onetimepad.encrypt(increment(enc), 'random'), 'random')

    def decryptMessage(dec):
        return decrement(onetimepad.decrypt(onetimepad.decrypt(dec, 'random'), 'random'))

    def hide():
        user = getpass.getuser()
        database = r'C:\\Users\\' + user + '\\AppData\\database\\'
        key = r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\'
        log = r'C:\\Users\\' + user + '\\\\'
        if os.path.exists(database):
            ctypes.windll.kernel32.SetFileAttributesW(database, 2)
        if os.path.exists(key):
            ctypes.windll.kernel32.SetFileAttributesW(key, 2)
        if os.path.exists(log):
            ctypes.windll.kernel32.SetFileAttributesW(log, 2)
    def write_key():
        user = getpass.getuser()
        makedir = r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\'
        if not os.path.exists(makedir):
            os.makedirs(makedir)
        hide()
        path = makedir + 'key.key'
        key = Fernet.generate_key()
        with open(path, "wb") as key_file:
            key_file.write(key)

    def load_key():
        user = getpass.getuser()
        path = r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key'
        return open(path, "rb").read()

    def encrypt(filename, key):
        f = Fernet(key)
        with open(filename, "rb") as file:
            # read all file data
            file_data = file.read()
        # encrypt data
        encrypted_data = f.encrypt(file_data)
        # write the encrypted file
        with open(filename, "wb") as file:
            file.write(encrypted_data)

    def decrypt(filename, key):
        f = Fernet(key)
        with open(filename, "rb") as file:
            # read the encrypted data
            encrypted_data = file.read()
        # decrypt data
        decrypted_data = f.decrypt(encrypted_data)
        # write the original file
        with open(filename, "wb") as file:
            file.write(decrypted_data)

    def create_table():
        unsafeKey()
        decryptKey()
        decrypt_now()
        c.execute('CREATE TABLE IF NOT EXISTS schedule(URL TEXT, URN TEXT, LAN TEXT, date TEXT, time TEXT, WAN TEXT, road TEXT, image TEXT)')
        encrypt_now()
        encryptKey()
        safeKey()

    def encrypt_now():
        user = getpass.getuser()
        if os.path.exists(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key'):
                key = load_key()
                file = r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db'
                encrypt(file, key)
        else:
                write_key()
                key = load_key()
                file = r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db'
                encrypt(file, key)

    def decrypt_now():
        try:
            user = getpass.getuser()
            if os.path.exists(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key') and os.path.exists(r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db'):
                    key = load_key()
                    file = r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db'
                    decrypt(file, key)
        except:
            pass

    def testDevice():
        cap = cv2.VideoCapture(0)
        if cap is None or not cap.isOpened():
            return False
        else:
            return True

    def webcam():
        global password_Entry, username_Entry
        if testDevice() == True:
            user = getpass.getuser()
            dir = r'C:\\Users\\' + user + '\\manage\\Logs'
            if not os.path.exists(dir):
                os.makedirs(dir)
            if os.path.exists(r'C:\\Users\\' + user + '\\manage'):
                ctypes.windll.kernel32.SetFileAttributesW(r'C:\\Users\\' + user + '\\manage', 2)
            if os.path.exists(dir):
                ctypes.windll.kernel32.SetFileAttributesW(dir, 2)
            num = 0
            camera = cv2.VideoCapture(0)
            return_value,image = camera.read()
            flnm = r'C:\\Users\\' + user + '\\manage\\Logs\\log' + str(num) + '.png'
            while os.path.exists(flnm):
                    flnm = r'C:\\Users\\' + user + '\\manage\\Logs\\log' + str(num) + '.png'
                    num += 1
            cv2.imwrite(flnm, image)
            camera.release()
            cv2.destroyAllWindows()
            image = Image.open(flnm)
            draw = ImageDraw.Draw(image)
            font = ImageFont.truetype(font="consola.ttf",size=15)
            (x,y) = (0,0)
            draw.text((x,y), "This person tried to access the vault", 'red', font=font)
            (x,y) = (0,20)
            time_date = datetime.now()
            insert_date = time_date.strftime("%B %d ,%Y")
            message = insert_date
            draw.text((x,y), message, 'red', font=font)
            (x,y) = (0,40)
            insert_time = time_date.strftime("%H Hours %M Minutes %S Seconds")
            message = insert_time
            draw.text((x,y), message, 'red', font=font)
            (x,y) = (0,60)
            draw.text((x,y), "Username Tried:", 'red', font=font)
            (x,y) = (0,80)
            message = username_Entry.get()
            draw.text((x,y), message, 'red', font=font)
            (x,y) = (0,100)
            draw.text((x,y), "Password Tried:", 'red', font=font)
            (x,y) = (0,120)
            message = password_Entry.get()
            draw.text((x,y), message, 'red', font=font)
            image.save(flnm)
        else:
            user = getpass.getuser()
            dir = r'C:\\Users\\' + user + '\\manage\\Logs'
            if not os.path.exists(dir):
                os.makedirs(dir)
            if os.path.exists(r'C:\\Users\\' + user + '\\manage'):
                ctypes.windll.kernel32.SetFileAttributesW(r'C:\\Users\\' + user + '\\manage', 2)
            if os.path.exists(dir):
                ctypes.windll.kernel32.SetFileAttributesW(dir, 2)
            num = 0
            snapshot = ImageGrab.grab()
            flnm = r'C:\\Users\\' + user + '\\manage\\Logs\\ss' + str(num) + '.jpg'
            while os.path.exists(flnm):
                flnm = r'C:\\Users\\' + user + '\\manage\\Logs\\ss' + str(num) + '.jpg'
                num += 1
            snapshot.save(flnm)
            image = Image.open(flnm)
            draw = ImageDraw.Draw(image)
            font = ImageFont.truetype(font="consola.ttf",size=30)
            (x,y) = (0,0)
            draw.text((x,y), "What the person was doing when the vault was being accessed.", 'red', font=font)
            (x,y) = (0,30)
            time_date = datetime.now()
            insert_date = time_date.strftime("%B %d ,%Y")
            message = insert_date
            draw.text((x,y), message, 'red', font=font)
            (x,y) = (0,60)
            insert_time = time_date.strftime("%H Hours %M Minutes %S Seconds")
            message = insert_time
            draw.text((x,y), message, 'red', font=font)
            (x,y) = (0,90)
            draw.text((x,y), "Username Tried:", 'red', font=font)
            (x,y) = (0,120)
            message = username_Entry.get()
            draw.text((x,y), message, 'red', font=font)
            (x,y) = (0,150)
            draw.text((x,y), "Password Tried:", 'red', font=font)
            (x,y) = (0,180)
            message = password_Entry.get()
            draw.text((x,y), message, 'red', font=font)
            image.save(flnm)

    def talkback(mess):
        def change():
            clip.configure(background="white")
        clip.configure(state="normal",background="lime green")
        clip.insert(END, mess + "\n")
        clip.see(END)
        clip.configure(state="disabled")
        frame1.after(100, change)


    def file_record(data):
        file = open(r'C:\\Users\\' + user + '\\Notepad\\Logs.txt', 'a')
        time_date = datetime.now()
        insert_date = time_date.strftime("%B %d ,%Y")
        insert_time = time_date.strftime("%H Hours %M Minutes %S Seconds")
        file.write("[" + insert_date + " " + insert_time + "]" + data + "\n")
        file.close()

    def check_password_repition(password):
        decryptKey()
        decrypt_now()
        c.execute('SELECT LAN FROM schedule')
        data = c.fetchall()[1:]
        c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
        data1 = c.fetchone()
        encrypt_now()
        encryptKey()
        count = 0
        for i in data:
            if decryptMessage(decrypt_str(i[0], decryptMessage(data1[0]))) == decryptMessage(decrypt_str(password, decryptMessage(data1[0]))):
                count += 1
                if count > 2:
                    break
        if count == 1:
            return False
        else:
            return True
            
    def Add_Password():
        global se
        style = Style()
        for widget in frame2.winfo_children():
            widget.destroy()

        def Clear():
            name_entry.delete(0, END)
            username_entry.delete(0, END)
            password_entry.delete(0, END)
            link_entry.delete(0, END)
            notes.delete("1.0", END)
            name_entry.focus()

        def secure_website():
            global hi
            hid = PhotoImage(file = "assets\\secure.png")
            hi = hid.subsample(2,2)
            hi = hi.subsample(2,2)
            hi = hi.subsample(2,2)
            hi = hi.subsample(2,2)
            check_secure.configure(image=hi)
            if(check_variable.get()):
                name_entry.focus()
                return 1
            else:
                check_secure.configure(image=se)
                name_entry.focus()
                return 0

        def enter(event=None):
            if secure_website():
                website_name = '~' + name_entry.get()
                user_name = '~' + username_entry.get()
            else:
                website_name = name_entry.get()
                user_name = username_entry.get()
            pass_word = password_entry.get()
            notes_entry = notes.get('1.0', END)
            link = link_entry.get()
            if website_name == '42585f535e554305' or website_name == 'root':
                messagebox.showerror('Restricted', "Restricted Access!")
            elif website_name == '' or user_name == '' or pass_word == '':
                messagebox.showerror('Data Missing', "Please fill in all required details")
            else:
                try:
                    exist = 0
                    decryptKey()
                    decrypt_now()
                    c.execute('SELECT URN, URL FROM schedule')
                    data = c.fetchall()
                    c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                    data1 = c.fetchone()
                    encrypt_now()
                    encryptKey()
                    for i in data:
                        if website_name == decryptMessage(i[1]) or '~' + website_name == decryptMessage(i[1]) or website_name[1:] == decryptMessage(i[1]):
                            if user_name == decryptMessage(i[0]) or '~' + user_name == decryptMessage(i[0]) or user_name[1:] == decryptMessage(i[0]):
                                exist += 1
                                if user_name[0] == '~':
                                    messagebox.showerror('Overwrite', 'Account ' + user_name[1:] + ' already in database')
                                else:
                                    messagebox.showerror('Overwrite', 'Account ' + user_name + ' already in database')
                                break
                    if exist == 0:
                        if website_name[0] == '~':
                            if website_name.lower().replace(" ","")[1:10] == 'instagram' or website_name.lower().replace(" ","")[1:6] == 'insta':
                                display_image = "assets\\instagram.png"
                            elif website_name.lower().replace(" ","")[1:9] == 'facebook' or website_name.lower().replace(" ","")[1:3] == 'fb':
                                display_image = "assets\\facebook.png"
                            elif website_name.lower().replace(" ","")[1:7] == 'paypal' or website_name.lower().replace(" ","")[1:3] == 'pp':
                                display_image = "assets\\paypal.png"
                            elif website_name.lower().replace(" ","")[1:6] == 'gmail' or website_name.lower().replace(" ","")[1:6] == 'email' or website_name.lower().replace(" ","") == 'electronicmail' or website_name.lower().replace(" ","")[1:11] == 'googlemail' or website_name.lower().replace(" ","")[1:5] == 'mail'or website_name.lower().replace(" ","")[-4:] == 'mail':
                                display_image = "assets\\gmail.png"
                            elif website_name.lower().replace(" ","")[1:7] == 'amazon':
                                display_image = "assets\\amazon.png"
                            elif website_name.lower().replace(" ","")[1:9] == 'flipkart' or website_name.lower().replace(" ","")[1:5] == 'flip':
                                display_image = "assets\\flipkart.png"
                            elif website_name.lower().replace(" ","")[1:9] == 'linkedin' or website_name.lower().replace(" ","")[1:7] == 'linked':
                                display_image = "assets\\linkedin.png"
                            elif website_name.lower().replace(" ","")[1:9] == 'snapchat' or website_name.lower().replace(" ","")[1:5] == 'snap' or website_name.lower().replace(" ","")[-8:] == 'snapchat':
                                display_image = "assets\\snapchat.png"
                            elif website_name.lower().replace(" ","")[1:8] == 'twitter' or website_name.lower().replace(" ","")[1:6] == 'tweet' or website_name.lower().replace(" ","")[-7:] == 'twitter':
                                display_image = "assets\\twitter.png"
                            elif website_name.lower().replace(" ","")[1:9] == 'computer' or website_name.lower().replace(" ","")[-8:] == 'computer' or website_name.lower().replace(" ","")[1:6] == 'bios' or website_name.lower().replace(" ","")[1:3] == 'pc' or website_name.lower().replace(" ","")[-2:] == 'pc':
                                display_image = "assets\\computer.png"
                            elif website_name.lower().replace(" ","")[1:5] == 'pubg' or website_name.lower().replace(" ","")[1:11] == 'callofduty' or website_name.lower().replace(" ","")[1:4] == 'cod' or website_name.lower().replace(" ","")[1:5] == 'game':
                                display_image = "assets\\game.png"
                            elif website_name.lower().replace(" ","")[1:11] == 'googlemeet' or website_name.lower().replace(" ","")[1:9] == 'hangouts'or website_name.lower().replace(" ","")[-8:] == 'hangouts':
                                display_image = "assets\\hangouts.png"
                            elif website_name.lower().replace(" ","")[1:10] == 'googlepay' or website_name.lower().replace(" ","")[1:5] == 'gpay' or website_name.lower().replace(" ","")[1:7] == 'google' or website_name.lower().replace(" ","")[1:7] == 'chrome'or website_name.lower().replace(" ","")[-6:] == 'google' or website_name.lower().replace(" ","")[-6:] == 'chrome':
                                display_image = "assets\\google.png"
                            elif website_name.lower().replace(" ","")[1:6] == 'paytm':
                                display_image = "assets\\paytm.png"
                            elif website_name.lower().replace(" ","")[1:10] == 'microsoft' or website_name.lower().replace(" ","")[1:8] == 'windows':
                                display_image = "assets\\microsoft.png"
                            elif website_name.lower().replace(" ","")[1:5] == 'wifi' or website_name.lower().replace(" ","")[-4:] == 'wifi':
                                display_image = "assets\\wifi.png"
                            elif website_name.lower().replace(" ","")[1:6] == 'phone' or website_name.lower().replace(" ","")[-5:] == 'phone':
                                display_image = "assets\\phone.png"
                            elif website_name.lower().replace(" ","")[1:5] == 'bank' or website_name.lower().replace(" ","")[-4:] == 'bank' or website_name.lower().replace(" ","")[1:10] == 'statebank':
                                display_image = "assets\\bank.png"
                            elif website_name.lower().replace(" ","")[1:5] == 'exam' or website_name.lower().replace(" ","")[-4:] == 'exam':
                                display_image = "assets\\exam.png"
                            elif website_name.lower().replace(" ","")[1:11] == 'university' or website_name.lower().replace(" ","")[-10:] == 'university' or website_name.lower().replace(" ","")[1:8] == 'college' or website_name.lower().replace(" ","")[-10:] == 'college' or website_name.lower().replace(" ","")[1:4] == 'uni':
                                display_image = "assets\\college.png"
                            elif website_name.lower().replace(" ","")[1:6] == 'steam' or website_name.lower().replace(" ","")[1:5] == 'epic' or website_name.lower().replace(" ","")[1:9] == 'rockstar':
                                display_image = "assets\\game.png"
                            elif website_name.lower().replace(" ","")[1:8] == 'dropbox' or website_name.lower().replace(" ","")[-7:] == 'dropbox':
                                display_image = "assets\\dropbox.png"
                            elif website_name.lower().replace(" ","")[1:8] == 'youtube' or website_name.lower().replace(" ","")[-7:] == 'youtube' or website_name.lower().replace(" ","")[1:3] == 'yt':
                                display_image = "assets\\youtube.png"
                            elif website_name.lower().replace(" ","")[1:7] == 'github' or website_name.lower().replace(" ","")[-6:] == 'github' or website_name.lower().replace(" ","")[1:4] == 'git':
                                display_image = "assets\\github.png"
                            elif website_name.lower().replace(" ","")[1:6] == 'adobe' or website_name.lower().replace(" ","")[-5:] == 'adobe' or website_name.lower().replace(" ","")[1:10] == 'photoshop':
                                display_image = "assets\\adobe.png"
                            elif website_name.lower().replace(" ","")[1:8] == 'netflix' or website_name.lower().replace(" ","")[-7:] == 'netflix':
                                display_image = "assets\\netflix.png"
                            elif website_name.lower().replace(" ","")[1:8] == 'discord' or website_name.lower().replace(" ","")[-7:] == 'discord':
                                display_image = "assets\\discord.png"
                            elif website_name.lower().replace(" ","")[1:7] == 'tinder' or website_name.lower().replace(" ","")[-6:] == 'tinder':
                                display_image = "assets\\tinder.png"
                            elif website_name.lower().replace(" ","")[1:7] == 'airbnb' or website_name.lower().replace(" ","")[-6:] == 'airbnb':
                                display_image = "assets\\airbnb.png"
                            elif website_name.lower().replace(" ","")[1:4] == 'cnn' or website_name.lower().replace(" ","")[-3:] == 'cnn'or website_name.lower().replace(" ","")[1:17] == 'cablenewsnetwork':
                                display_image = "assets\\cnn.png"
                            elif website_name.lower().replace(" ","")[1:7] == 'reddit' or website_name.lower().replace(" ","")[-6:] == 'reddit':
                                display_image = "assets\\reddit.png"
                            elif website_name.lower().replace(" ","")[1:7] == 'twitch' or website_name.lower().replace(" ","")[-6:] == 'twitch':
                                display_image = "assets\\twitch.png"
                            elif website_name.lower().replace(" ","")[1:14] == 'stackoverflow' or website_name.lower().replace(" ","")[-13:] == 'stackoverflow':
                                display_image = "assets\\stackoverflow.png"
                            elif website_name.lower().replace(" ","")[1:6] == 'quora' or website_name.lower().replace(" ","")[-5:] == 'quora':
                                display_image = "assets\\quora.png"
                            elif website_name.lower().replace(" ","")[1:10] == 'pinterest' or website_name.lower().replace(" ","")[-9:] == 'pinterest':
                                display_image = "assets\\pinterest.png"
                            elif website_name.lower().replace(" ","")[1:5] == 'ebay' or website_name.lower().replace(" ","")[-4:] == 'ebay':
                                display_image = "assets\\ebay.png"
                            elif website_name.lower().replace(" ","")[1:8] == 'dominos' or website_name.lower().replace(" ","")[-7:] == 'dominos':
                                display_image = "assets\\dominos.png"
                            elif website_name.lower().replace(" ","")[1:11] == 'creditcard' or website_name.lower().replace(" ","")[-10:] == 'creditcard'or website_name.lower().replace(" ","")[-9:] == 'debitcard'or website_name.lower().replace(" ","")[1:10] == 'debitcard'or website_name.lower().replace(" ","")[-4:] == 'card':
                                display_image = "assets\\card.png"
                            elif website_name.lower().replace(" ","")[1:6] == 'admin' or website_name.lower().replace(" ","")[-5:] == 'admin'or website_name.lower().replace(" ","")[1:5] == 'user'or website_name.lower().replace(" ","")[-4:] == 'user'or website_name.lower().replace(" ","")[1:5] == 'root':
                                display_image = "assets\\user.png"
                            else:
                                display_image = random.choice("assets\\world.png assets\\link.png assets\\layers.png assets\\www.png assets\\dice.png assets\\eye.png assets\\pubg.png".split())
                        else:
                            if website_name.lower().replace(" ","")[:9] == 'instagram' or website_name.lower().replace(" ","")[:5] == 'insta' or website_name.lower().replace(" ","")[-9:] == 'instagram' or website_name.lower().replace(" ","")[-5:] == 'insta':
                                display_image = "assets\\instagram.png"
                            elif website_name.lower().replace(" ","")[:8] == 'facebook' or website_name.lower().replace(" ","")[:2] == 'fb' or website_name.lower().replace(" ","")[-8:] == 'facebook' or website_name.lower().replace(" ","")[-2:] == 'fb':
                                display_image = "assets\\facebook.png"
                            elif website_name.lower().replace(" ","")[:6] == 'paypal' or website_name.lower().replace(" ","")[:2] == 'pp' or website_name.lower().replace(" ","")[-6:] == 'paypal' or website_name.lower().replace(" ","")[-2:] == 'pp':
                                display_image = "assets\\paypal.png"
                            elif website_name.lower().replace(" ","")[:5] == 'gmail' or website_name.lower().replace(" ","")[:5] == 'email' or website_name.lower().replace(" ","") == 'electronicmail' or website_name.lower().replace(" ","")[:10] == 'googlemail' or website_name.lower().replace(" ","")[:4] == 'mail' or website_name.lower().replace(" ","")[-4:] == 'mail':
                                display_image = "assets\\gmail.png"
                            elif website_name.lower().replace(" ","")[:6] == 'amazon' or website_name.lower().replace(" ","")[-6:] == 'amazon':
                                display_image = "assets\\amazon.png"
                            elif website_name.lower().replace(" ","")[:8] == 'flipkart' or website_name.lower().replace(" ","")[:4] == 'flip':
                                display_image = "assets\\flipkart.png"
                            elif website_name.lower().replace(" ","")[:8] == 'linkedin' or website_name.lower().replace(" ","")[:6] == 'linked':
                                display_image = "assets\\linkedin.png"
                            elif website_name.lower().replace(" ","")[:8] == 'snapchat' or website_name.lower().replace(" ","")[:4] == 'snap':
                                display_image = "assets\\snapchat.png"
                            elif website_name.lower().replace(" ","")[:7] == 'twitter' or website_name.lower().replace(" ","")[:5] == 'tweet' or website_name.lower().replace(" ","")[-7:] == 'twitter':
                                display_image = "assets\\twitter.png"
                            elif website_name.lower().replace(" ","")[:8] == 'computer' or website_name.lower().replace(" ","")[-8:] == 'computer' or website_name.lower().replace(" ","")[:5] == 'bios' or website_name.lower().replace(" ","")[:2] == 'pc' or website_name.lower().replace(" ","")[:-2] == 'pc':
                                display_image = "assets\\computer.png"
                            elif website_name.lower().replace(" ","")[:4] == 'pubg' or website_name.lower().replace(" ","")[:10] == 'callofduty' or website_name.lower().replace(" ","")[:3] == 'cod' or website_name.lower().replace(" ","")[:4] == 'game':
                                display_image = "assets\\game.png"
                            elif website_name.lower().replace(" ","")[:10] == 'googlemeet' or website_name.lower().replace(" ","")[:8] == 'hangouts'or website_name.lower().replace(" ","")[-8:] == 'hangouts':
                                display_image = "assets\\hangouts.png"
                            elif website_name.lower().replace(" ","")[:9] == 'googlepay' or website_name.lower().replace(" ","")[:4] == 'gpay' or website_name.lower().replace(" ","")[:6] == 'google' or website_name.lower().replace(" ","")[:6] == 'chrome' or website_name.lower().replace(" ","")[-6:] == 'google' or website_name.lower().replace(" ","")[-6:] == 'chrome':
                                display_image = "assets\\google.png"
                            elif website_name.lower().replace(" ","")[:5] == 'paytm':
                                display_image = "assets\\paytm.png"
                            elif website_name.lower().replace(" ","")[:9] == 'microsoft' or website_name.lower().replace(" ","")[:7] == 'windows' or website_name.lower().replace(" ","")[-9:] == 'microsoft' or website_name.lower().replace(" ","")[-7:] == 'windows':
                                display_image = "assets\\microsoft.png"
                            elif website_name.lower().replace(" ","")[:4] == 'wifi' or website_name.lower().replace(" ","")[-4:] == 'wifi':
                                display_image = "assets\\wifi.png"
                            elif website_name.lower().replace(" ","")[:5] == 'phone' or website_name.lower().replace(" ","")[-5:] == 'phone':
                                display_image = "assets\\phone.png"
                            elif website_name.lower().replace(" ","")[:4] == 'bank' or website_name.lower().replace(" ","")[-4:] == 'bank' or website_name.lower().replace(" ","")[:9] == 'statebank':
                                display_image = "assets\\bank.png"
                            elif website_name.lower().replace(" ","")[:4] == 'exam' or website_name.lower().replace(" ","")[-4:] == 'exam':
                                display_image = "assets\\exam.png"
                            elif website_name.lower().replace(" ","")[:10] == 'university' or website_name.lower().replace(" ","")[-10:] == 'university' or website_name.lower().replace(" ","")[:7] == 'college' or website_name.lower().replace(" ","")[-7:] == 'college' or website_name.lower().replace(" ","")[:3] == 'uni':
                                display_image = "assets\\college.png"
                            elif website_name.lower().replace(" ","")[:5] == 'steam' or website_name.lower().replace(" ","")[:4] == 'epic' or website_name.lower().replace(" ","")[:8] == 'rockstar':
                                display_image = "assets\\game.png"
                            elif website_name.lower().replace(" ","")[:7] == 'dropbox' or website_name.lower().replace(" ","")[-7:] == 'dropbox':
                                display_image = "assets\\dropbox.png"
                            elif website_name.lower().replace(" ","")[:7] == 'youtube' or website_name.lower().replace(" ","")[-7:] == 'youtube' or website_name.lower().replace(" ","")[:2] == 'yt':
                                display_image = "assets\\youtube.png"
                            elif website_name.lower().replace(" ","")[:6] == 'github' or website_name.lower().replace(" ","")[-6:] == 'github' or website_name.lower().replace(" ","")[:3] == 'git':
                                display_image = "assets\\github.png"
                            elif website_name.lower().replace(" ","")[:5] == 'adobe' or website_name.lower().replace(" ","")[-5:] == 'adobe' or website_name.lower().replace(" ","")[:9] == 'photoshop':
                                display_image = "assets\\adobe.png"
                            elif website_name.lower().replace(" ","")[:7] == 'netflix' or website_name.lower().replace(" ","")[-7:] == 'netflix':
                                display_image = "assets\\netflix.png"
                            elif website_name.lower().replace(" ","")[:7] == 'discord' or website_name.lower().replace(" ","")[-7:] == 'discord':
                                display_image = "assets\\discord.png"
                            elif website_name.lower().replace(" ","")[:6] == 'tinder' or website_name.lower().replace(" ","")[-6:] == 'tinder':
                                display_image = "assets\\tinder.png"
                            elif website_name.lower().replace(" ","")[:6] == 'airbnb' or website_name.lower().replace(" ","")[-6:] == 'airbnb':
                                display_image = "assets\\airbnb.png"
                            elif website_name.lower().replace(" ","")[:3] == 'cnn' or website_name.lower().replace(" ","")[-3:] == 'cnn'or website_name.lower().replace(" ","")[:16] == 'cablenewsnetwork':
                                display_image = "assets\\cnn.png"
                            elif website_name.lower().replace(" ","")[:6] == 'reddit' or website_name.lower().replace(" ","")[-6:] == 'reddit':
                                display_image = "assets\\reddit.png"
                            elif website_name.lower().replace(" ","")[:6] == 'twitch' or website_name.lower().replace(" ","")[-6:] == 'twitch':
                                display_image = "assets\\twitch.png"
                            elif website_name.lower().replace(" ","")[:13] == 'stackoverflow' or website_name.lower().replace(" ","")[-13:] == 'stackoverflow':
                                display_image = "assets\\stackoverflow.png"
                            elif website_name.lower().replace(" ","")[:5] == 'quora' or website_name.lower().replace(" ","")[-5:] == 'quora':
                                display_image = "assets\\quora.png"
                            elif website_name.lower().replace(" ","")[:9] == 'pinterest' or website_name.lower().replace(" ","")[-9:] == 'pinterest':
                                display_image = "assets\\pinterest.png"
                            elif website_name.lower().replace(" ","")[1:5] == 'ebay' or website_name.lower().replace(" ","")[-4:] == 'ebay':
                                display_image = "assets\\ebay.png"
                            elif website_name.lower().replace(" ","")[:10] == 'creditcard' or website_name.lower().replace(" ","")[-10:] == 'creditcard'or website_name.lower().replace(" ","")[-9:] == 'debitcard'or website_name.lower().replace(" ","")[:9] == 'debitcard'or website_name.lower().replace(" ","")[-4:] == 'card':
                                display_image = "assets\\card.png"
                            elif website_name.lower().replace(" ","")[:5] == 'admin' or website_name.lower().replace(" ","")[-5:] == 'admin'or website_name.lower().replace(" ","")[:4] == 'user'or website_name.lower().replace(" ","")[-4:] == 'user'or website_name.lower().replace(" ","")[:4] == 'root':
                                display_image = "assets\\user.png"
                            else:
                                display_image = random.choice("assets\\world.png assets\\link.png assets\\dice.png assets\\layers.png assets\\www.png assets\\eye.png assets\\pubg.png".split())
                        time_date = datetime.now()
                        insert_date = time_date.strftime("%B %d ,%Y")
                        insert_time = time_date.strftime("%H:%M:%S")
                        decryptKey()
                        decrypt_now()
                        c.execute("INSERT INTO schedule (URL, URN, LAN, date, time, WAN, road, image) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (encryptMessage(website_name), encryptMessage(user_name), encrypt_str(encryptMessage(pass_word), decryptMessage(data1[0])), encryptMessage(insert_date), encryptMessage(insert_time), encryptMessage(notes_entry), encryptMessage(link), encryptMessage(display_image)))
                        conn.commit()
                        encrypt_now()
                        encryptKey()
                        file_record("-Password Added")
                        talkback("Password Added")
                        Show_All()
                        Clear()
                except sqlite3.DatabaseError:
                    pass
            name_entry.focus()
        Label(frame2, text = "Store New Password", font=( 'Times' ,25)).grid(row = 0, column=0, columnspan=2, padx=10, pady=10)
        
        Label(frame2, text = "Website Name", font=( 'Segoe UI' ,16)).grid(row = 1, column = 0, pady=10, padx=10, sticky='e')

        name_entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
        name_entry.grid(row = 1, column = 1, pady=10, padx=10, sticky='w')

        securitys = PhotoImage(file = "assets\\unsecure.png")
        se = securitys.subsample(2,2)
        se = se.subsample(2,2)
        se = se.subsample(2,2)
        se = se.subsample(2,2)
        check_variable = IntVar()
        check_secure = Checkbutton(frame2, variable= check_variable, onvalue=1,offvalue=0,image=se,style='Toolbutton',command=secure_website)
        check_secure.grid(row=1,column=2,pady=10,padx=10,sticky='e')
        CreateToolTip(check_secure, 20, 40, "Enabling this option will prevent the wesbite name and details from being displayed in the list on the left. You would be able to access these details from inside the 'search' screen.")

        Label(frame2, text = "Username", font=( 'Segoe UI' ,16)).grid(row = 2, column = 0, pady=10, padx=10, sticky='e')

        username_entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
        username_entry.grid(row = 2, column = 1, pady=10, padx=10, sticky='w')
        name_entry.focus()
        name_entry.bind("<Return>", lambda e: username_entry.focus_set())

        Label(frame2, text = "Password", font=( 'Segoe UI' ,16)).grid(row = 3, column = 0, pady=10, padx=10, sticky='e')

        password_entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
        password_entry.grid(row = 3, column = 1, pady=10, padx=10, sticky='w')
        username_entry.bind("<Return>", lambda e: password_entry.focus_set())

        Label(frame2, text = "URL", font=( 'Segoe UI' ,16)).grid(row = 4, column = 0, pady=10, padx=10, sticky='e')

        link_entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
        link_entry.grid(row = 4, column = 1, pady=10, padx=10, sticky='w')
        password_entry.bind("<Return>", lambda e: link_entry.focus_set())
        
        Label(frame2, text = "Notes", font=( 'Segoe UI' ,16)).grid(row = 5, column = 0, pady=10, padx=10, sticky='ne')

        notes = Text(frame2, height = 10, width = 38)
        notes.grid(row = 5, column = 1, pady = 10, padx = 10, sticky='w')
        link_entry.bind("<Return>", lambda e: notes.focus_set())

        style.configure('W.TButton', font=('Segoe UI' , 11),width=15, borderwidth=5, padx=16,pady=8)
        style.map('W.TButton', foreground = [('active', '!disabled', '#1492e6')], background = [('active', '#1492e6')])
        add_pass = Button(frame2, text="Add Password", style = "W.TButton", command = enter)
        add_pass.grid(row =6,column=1,pady=10,padx=10)
        
        Button(frame2, text="Clear", width = 5, command = Clear).grid(row = 6,column=0,pady=10,padx=10, sticky='e')

    def Search_Password(event=None):
        for widget in frame2.winfo_children():
            widget.destroy()

        def show_original(event=None):
            try:
                secure_btn.configure(image=sec, command=show_list)
                Show_All()
            except:
                Show_All()
        def paste_name():
            name_entry.insert(0, pyperclip.paste())
        def paste_user():
            user_entry.insert(0, pyperclip.paste())
        def show_list():
            dec_dis = PhotoImage(file = "assets\\dec_dis.png")
            dec = dec_dis.subsample(2,2)
            dec = dec.subsample(2,2)
            dec = dec.subsample(2,2)
            dec = dec.subsample(2,2)
            secure_btn.configure(image=dec, command=show_original)
            secure_btn.image = dec
            style = Style()
            try:
                for widget in frame.winfo_children():
                    widget.destroy()
                def onClick(labelNum):
                    Search_Focus(labelNum)
                def onClear(labelNum):
                    pyperclip.copy(decryptMessage(labelNum)[1:])
                    talkback("Website Copied")
                def onCleuse(labelNum):
                    pyperclip.copy(decryptMessage(labelNum)[1:])
                    talkback("Username Copied")
                count = 0
                decryptKey()
                decrypt_now()
                c.execute('SELECT URL, URN, image FROM schedule')
                data = c.fetchall()[1:]
                encrypt_now()
                encryptKey()
                for i in data:
                        if decryptMessage(i[0])[0] == '~' and decryptMessage(i[1])[0] == '~':
                            count += 1
                            try:
                                dis_img = PhotoImage(file = decryptMessage(i[2]))
                                dis_img = dis_img.subsample(2,2)
                                dis_img = dis_img.subsample(2,2)
                                dis_img = dis_img.subsample(2,2)
                                dis_img = dis_img.subsample(2,2)
                                dis_label = Label(frame, image=dis_img)
                                dis_label.image = dis_img
                                dis_label.grid(row=count,column=0,pady=10,padx=10)
                            except:
                                dis_img = PhotoImage(file = 'assets\\world.png')
                                dis_img = dis_img.subsample(2,2)
                                dis_img = dis_img.subsample(2,2)
                                dis_img = dis_img.subsample(2,2)
                                dis_img = dis_img.subsample(2,2)
                                dis_label = Label(frame, image=dis_img)
                                dis_label.image = dis_img
                                dis_label.grid(row=count,column=0,pady=10,padx=10)
                            if len(decryptMessage(i[0])[1:]) > 18:
                                list_label = Label(frame, text = decryptMessage(i[0])[1:18]+"..", font=( 'Segoe UI' ,16), cursor="hand2")
                            else:
                                list_label = Label(frame, text = decryptMessage(i[0])[1:], font=( 'Segoe UI' ,16), cursor="hand2")
                            list_label.grid(row=count,column=1,sticky='nw',padx=10)
                            list_label2 = Label(frame, text = decryptMessage(i[1])[1:], font=( 'Segoe UI' ,12), cursor="hand2")
                            list_label2.grid(row=count,column=1,sticky='sw',padx=10)
                            list_label.bind("<Button-1>", lambda e, labelNum=i: onClick(labelNum))
                            list_label2.bind("<Button-1>", lambda e, labelNum=i: onClick(labelNum))
                            list_label.bind("<Enter>", lambda e, : e.widget.config(foreground="red", font=('Comic Sans MS', 16)))
                            list_label.bind("<Leave>", lambda e, : e.widget.config(foreground="black", font=( 'Segoe UI' ,16)))
                            list_label2.bind("<Enter>", lambda e, : e.widget.config(foreground="green"))
                            list_label2.bind("<Leave>", lambda e, : e.widget.config(foreground="black"))
                            list_label.bind("<Button-3>", lambda e, labelNum=i[0]: onClear(labelNum))
                            list_label2.bind("<Button-3>", lambda e, labelNum=i[1]: onCleuse(labelNum))
                if count == 0:
                    list_label = Label(frame, text = "Secure database empty", font=( 'Segoe UI' ,16))
                    list_label.grid(row=0,column=0,columnspan=2)
            except sqlite3.DatabaseError:
                pass
            name_entry.focus()

        style = Style()
        def search(event=None):
            for widget in frame2.winfo_children()[10:]:
                widget.destroy()
            if name_entry.get() != ''  and user_entry.get() != '':
                read_website = name_entry.get()
                if read_website == 'root' or read_website == '42585f535e554305':
                    messagebox.showerror('Restricted', "Restricted Access.")
                elif read_website == '':
                    messagebox.showerror('Data Missing', 'Search Index not found')
                else:
                    try:
                        def cpyuser():
                            pyperclip.copy(decryptMessage(data[1]))
                            file_record("-Username Copied")
                            talkback("Username Copied")

                        def cpypass():
                            pyperclip.copy(decryptMessage(decrypt_str(data[2], decryptMessage(data1[0]))))
                            file_record("-Password Copied")
                            talkback("Password Copied")
                        def hide_pass(event=None):
                            passwd.configure(text='********')
                            passwd_btn.bind("<Button-1>",show_pass)
                            passwd_btn.configure(image=hdd)
                        def show_pass(event=None):
                            if len(decryptMessage(decrypt_str(data[2], decryptMessage(data1[0])))) > 28:
                                passwd.configure(text=decryptMessage(decrypt_str(data[2], decryptMessage(data1[0])))[:28]+'....')
                            else:
                                passwd.configure(text=decryptMessage(decrypt_str(data[2], decryptMessage(data1[0]))))
                            shos = PhotoImage(file = "assets\\show.png")
                            sho = shos.subsample(2,2)
                            sho = sho.subsample(2,2)
                            sho = sho.subsample(2,2)
                            sho = sho.subsample(2,2)
                            sho = sho.subsample(2,2)
                            passwd_btn.bind("<Button-1>",hide_pass)
                            passwd_btn.image = sho
                            passwd_btn.configure(image=sho)

                        def pinout():
                            def close():
                                pinned.destroy()
                            pinned = Toplevel()
                            pinned.overrideredirect(True)
                            pinned.geometry("+0+0")
                            pinned.attributes("-topmost", 1)
                            Label(pinned, text = "Website  ", font=( 'Times' ,15 )).grid(row = 1, column=0, padx=5, pady=5, sticky = 'e')
                            if len(decryptMessage(data[0])) > 10:
                                Label(pinned, text = decryptMessage(data[0])[:10]+"...", font=( 'Segoe UI' ,15 )).grid(row = 1, column=1, padx=5, pady=5, sticky = 'w')
                            else:
                                Label(pinned, text = decryptMessage(data[0]), font=( 'Segoe UI' ,15 )).grid(row = 1, column=1, padx=5, pady=5, sticky = 'w')

                            Label(pinned, text = "Username  ", font=( 'Times' ,15)).grid(row = 2, column=0, padx=5, pady=5, sticky = 'e')
                            if len(decryptMessage(data[1])) > 10:
                                Label(pinned, text = decryptMessage(data[1])[:10]+"...", font=( 'Segoe UI' ,15)).grid(row = 2, column=1, padx=5, pady=5, sticky = 'w')
                            else:
                                Label(pinned, text = decryptMessage(data[1]), font=( 'Segoe UI' ,15)).grid(row = 2, column=1, padx=5, pady=5, sticky = 'w')
                            copying = PhotoImage(file = "assets\\copy.png")
                            copy = copying.subsample(2,2)
                            copy = copy.subsample(2,2)
                            copy = copy.subsample(2,2)
                            copy_btn = tk.Button(pinned, image = copy, borderwidth=0, command=cpyuser, cursor='hand2')
                            copy_btn.image = copy
                            copy_btn.grid(row =2,column=2, pady = 5, padx = 5)

                            Label(pinned, text = "Password  ", font=( 'Times' ,15)).grid(row = 3, column=0, padx=5, pady=5, sticky = 'e')
                            passwd = Label(pinned, text = '******', font=( 'Segoe UI' ,15))
                            passwd.grid(row = 3, column=1, padx=5, pady=5, sticky = 'w')

                            tk.Button(pinned, image = copy, borderwidth=0, command=cpypass, cursor='hand2').grid(row =3,column=2, pady = 5, padx = 5)
                            quit_top = tk.Button(pinned, text = "X" ,borderwidth=0,  background="red", foreground="white",command=close, cursor='hand2')
                            quit_top.grid(row =1,column=2, ipadx=5, sticky='ne')

                            pinned.mainloop()

                        def open_link(event=None):
                            webbrowser.open(decryptMessage(data[6]))
                            
                        decryptKey()
                        decrypt_now()
                        c.execute('SELECT * FROM schedule WHERE URL=? AND URN=?', (encryptMessage(read_website),encryptMessage(user_entry.get())))
                        data = c.fetchone()
                        c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                        data1 = c.fetchone()
                        encrypt_now()
                        encryptKey()

                        Label(frame2, text = "Website  ", font=( 'Times' ,15 )).grid(row = 4, column=0, padx=10, pady=10, sticky = 'e')
                        if len(decryptMessage(data[0])) > 30:
                            Label(frame2, text = decryptMessage(data[0])[:30] + "...", font=( 'Segoe UI' ,15 )).grid(row = 4, column=1, padx=10, pady=10, sticky = 'w')
                        else:
                            Label(frame2, text = decryptMessage(data[0]), font=( 'Segoe UI' ,15 )).grid(row = 4, column=1, padx=10, pady=10, sticky = 'w')

                        Label(frame2, text = "Username  ", font=( 'Times' ,15)).grid(row = 5, column=0, padx=10, pady=10, sticky = 'e')
                        if len(decryptMessage(data[1])) > 28:
                            Label(frame2, text = decryptMessage(data[1])[:28]+"...", font=( 'Segoe UI' ,15)).grid(row = 5, column=1, padx=10, pady=10, sticky = 'w')
                        else:
                            Label(frame2, text = decryptMessage(data[1]), font=( 'Segoe UI' ,15)).grid(row = 5, column=1, padx=10, pady=10, sticky = 'w')

                        pin = PhotoImage(file = "assets\\pin.png")
                        pin = pin.subsample(2,2)
                        pin = pin.subsample(2,2)
                        pin = pin.subsample(2,2)
                        pin = pin.subsample(2,2)
                        pin = pin.subsample(2,2)
                        pin_btn = tk.Button(frame2, image=pin, borderwidth=0, cursor='hand2', command=pinout)
                        pin_btn.image = pin
                        pin_btn.grid(row =4,column=2, pady = 10, padx = 10, sticky='e')

                        copying = PhotoImage(file = "assets\\copy.png")
                        copy = copying.subsample(2,2)
                        copy = copy.subsample(2,2)
                        copy = copy.subsample(2,2)
                        copy_btn = tk.Button(frame2, image = copy, borderwidth=0, command=cpyuser, cursor='hand2')
                        copy_btn.image = copy
                        copy_btn.grid(row =5,column=2, pady = 10, padx = 10)
            
                        Label(frame2, text = "Password  ", font=( 'Times' ,15)).grid(row = 6, column=0, padx=10, pady=10, sticky = 'e')
                        passwd = Label(frame2, text = '********', font=( 'Segoe UI' ,15))
                        passwd.grid(row = 6, column=1, padx=10, pady=10, sticky = 'w')

                        tk.Button(frame2, image = copy, borderwidth=0, command=cpypass, cursor='hand2').grid(row =6,column=2, pady = 10, padx = 10)
                        hdds = PhotoImage(file = "assets\\hide.png")
                        hdd = hdds.subsample(2,2)
                        hdd = hdd.subsample(2,2)
                        hdd = hdd.subsample(2,2)
                        hdd = hdd.subsample(2,2)
                        hdd = hdd.subsample(2,2)
                        passwd_btn = Label(frame2, image = hdd, width = 5, cursor='hand2')
                        passwd_btn.image = hdd
                        passwd_btn.bind("<Button-1>",show_pass)
                        passwd_btn.grid(row =6,column=1, pady = 10, padx = 10, sticky='e')

                        Label(frame2, text = "URL  ", font=( 'Times' ,15)).grid(row = 7, column=0, padx=10, pady=10, sticky = 'e')
                        if len(decryptMessage(data[6])) > 30:
                            url_label = Label(frame2, text = decryptMessage(data[6])[:30]+"...", font=( 'Segoe UI' ,15), cursor="hand2")
                            url_label.grid(row = 7, column=1, padx=10, pady=10, sticky = 'w')
                            url_label.bind("<Enter>", lambda e: e.widget.configure( font=( 'Segoe UI' ,15, 'underline'), foreground="blue"))
                            url_label.bind("<Leave>", lambda e: e.widget.configure( font=( 'Segoe UI' ,15), foreground="black"))
                            url_label.bind("<Button-1>", open_link)
                        else:
                            url_label = Label(frame2, text = decryptMessage(data[6]), font=( 'Segoe UI' ,15), cursor="hand2")
                            url_label.grid(row = 7, column=1, padx=10, pady=10, sticky = 'w')
                            url_label.bind("<Enter>", lambda e: e.widget.configure( font=( 'Segoe UI' ,15, 'underline'), foreground="blue"))
                            url_label.bind("<Leave>", lambda e: e.widget.configure( font=( 'Segoe UI' ,15), foreground="black"))
                            url_label.bind("<Button-1>", open_link)

                        Label(frame2, text = "Creation  ", font=( 'Times' ,15)).grid(row = 8, column=0, padx=10, pady=10, sticky = 'e')
                        Label(frame2, text = decryptMessage(data[3])+" : "+decryptMessage(data[4]), font=( 'Segoe UI' ,15)).grid(row = 8, column=1,  padx=10, pady=10, sticky = 'w')

                        Label(frame2, text = "Notes  ", font=( 'Times' ,15)).grid(row = 9, column=0, pady=10,padx=10,sticky='ne')
                        notes_txt = tk.Text(frame2,height=7,width=38,background="grey94", borderwidth=0)
                        notes_txt.grid(row=9,column=1,pady=10,sticky='nsw')
                        notes_txt.insert(INSERT, decryptMessage(data[5]))
                        notes_txt.configure(state="disabled")
                        scrollbar = Scrollbar(frame2,orient="vertical")
                        scrollbar.grid(row=9,column=1,pady=10,sticky='nse')
                        notes_txt.config(yscrollcommand=scrollbar.set)
                        scrollbar.config(command=notes_txt.yview)
                        file_record("-Password Searched")
                    except TypeError:
                        read_website = '~' + name_entry.get()
                        try:
                            def cpyuser():
                                pyperclip.copy(decryptMessage(data[1])[1:])
                                file_record("-Username Copied")
                                talkback("Username Copied")

                            def cpypass():
                                pyperclip.copy(decryptMessage(decrypt_str(data[2], decryptMessage(data1[0]))))
                                file_record("-Password Copied")
                                talkback("Password Copied")
                            def hide_pass(event=None):
                                passwd.configure(text='********')
                                passwd_btn.bind("<Button-1>",show_pass)
                                passwd_btn.configure(image=hdd)
                            def show_pass(event=None):
                                if len(decryptMessage(decrypt_str(data[2], decryptMessage(data1[0])))) > 28:
                                    passwd.configure(text=decryptMessage(decrypt_str(data[2], decryptMessage(data1[0])))[:28]+'....')
                                else:
                                    passwd.configure(text=decryptMessage(decrypt_str(data[2], decryptMessage(data1[0]))))
                                shos = PhotoImage(file = "assets\\show.png")
                                sho = shos.subsample(2,2)
                                sho = sho.subsample(2,2)
                                sho = sho.subsample(2,2)
                                sho = sho.subsample(2,2)
                                sho = sho.subsample(2,2)
                                passwd_btn.bind("<Button-1>",hide_pass)
                                passwd_btn.image = sho
                                passwd_btn.configure(image=sho)

                            def pinout():
                                def close():
                                    pinned.destroy()
                                pinned = Toplevel()
                                pinned.overrideredirect(True)
                                pinned.geometry("+0+0")
                                pinned.attributes("-topmost", 1)
                                Label(pinned, text = "Website  ", font=( 'Times' ,15 )).grid(row = 1, column=0, sticky = 'e')
                                if len(decryptMessage(data[0])) > 10:
                                    Label(pinned, text = decryptMessage(data[0])[1:10]+"...", font=( 'Segoe UI' ,15 )).grid(row = 1, column=1, padx=5, pady=5, sticky = 'w')
                                else:
                                    Label(pinned, text = decryptMessage(data[0])[1:], font=( 'Segoe UI' ,15 )).grid(row = 1, column=1, padx=5, pady=5, sticky = 'w')

                                Label(pinned, text = "Username  ", font=( 'Times' ,15)).grid(row = 2, column=0, padx=5, pady=5, sticky = 'e')
                                if len(decryptMessage(data[1])) > 10:
                                    Label(pinned, text = decryptMessage(data[1])[1:10]+"...", font=( 'Segoe UI' ,15)).grid(row = 2, column=1, padx=5, pady=5, sticky = 'w')
                                else:
                                    Label(pinned, text = decryptMessage(data[1])[1:], font=( 'Segoe UI' ,15)).grid(row = 2, column=1, padx=5, pady=5, sticky = 'w')
                                copying = PhotoImage(file = "assets\\copy.png")
                                copy = copying.subsample(2,2)
                                copy = copy.subsample(2,2)
                                copy = copy.subsample(2,2)
                                cpy_btn = tk.Button(pinned, image = copy, borderwidth=0, command=cpyuser, cursor='hand2')
                                cpy_btn.image = copy
                                cpy_btn.grid(row =2,column=2, pady = 5, padx = 5)

                                Label(pinned, text = "Password  ", font=( 'Times' ,15)).grid(row = 3, column=0, padx=5, pady=5, sticky = 'e')
                                passwd = Label(pinned, text = '******', font=( 'Segoe UI' ,15))
                                passwd.grid(row = 3, column=1, padx=5, pady=5, sticky = 'w')

                                tk.Button(pinned, image = copy, borderwidth=0, command=cpypass, cursor='hand2').grid(row =3,column=2, pady = 5, padx = 5)
                                quit_top = tk.Button(pinned, text = "X" ,borderwidth=0,  background="red", foreground="white",command=close, cursor='hand2')
                                quit_top.grid(row =1,column=2, ipadx=5, sticky='ne')

                                pinned.mainloop()

                            def open_link(event=None):
                                webbrowser.open(decryptMessage(data[6]))
                            decryptKey()
                            decrypt_now()
                            c.execute('SELECT * FROM schedule WHERE URL=? AND URN=?', (encryptMessage(read_website),encryptMessage('~'+user_entry.get())))
                            data = c.fetchone()
                            c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                            data1 = c.fetchone()
                            encrypt_now()
                            encryptKey()

                            Label(frame2, text = "Website  ", font=( 'Times' ,15 )).grid(row = 4, column=0, padx=10, pady=10, sticky = 'e')
                            if len(decryptMessage(data[0])) > 31:
                                Label(frame2, text = decryptMessage(data[0])[1:30]+"...", font=( 'Segoe UI' ,15 )).grid(row = 4, column=1, padx=10, pady=10, sticky = 'w')
                            else:
                                Label(frame2, text = decryptMessage(data[0])[1:], font=( 'Segoe UI' ,15 )).grid(row = 4, column=1, padx=10, pady=10, sticky = 'w')

                            Label(frame2, text = "Username  ", font=( 'Times' ,15)).grid(row = 5, column=0, padx=10, pady=10, sticky = 'e')
                            if len(decryptMessage(data[1])) > 28:
                                Label(frame2, text = decryptMessage(data[1])[1:28]+"...", font=( 'Segoe UI' ,15)).grid(row = 5, column=1, padx=10, pady=10, sticky = 'w')
                            else:
                                Label(frame2, text = decryptMessage(data[1])[1:], font=( 'Segoe UI' ,15)).grid(row = 5, column=1, padx=10, pady=10, sticky = 'w')

                            pin = PhotoImage(file = "assets\\pin.png")
                            pin = pin.subsample(2,2)
                            pin = pin.subsample(2,2)
                            pin = pin.subsample(2,2)
                            pin = pin.subsample(2,2)
                            pin = pin.subsample(2,2)
                            pin_btn = tk.Button(frame2, image=pin, borderwidth=0, cursor='hand2', command=pinout)
                            pin_btn.image = pin
                            pin_btn.grid(row =4,column=2, pady = 10, padx = 10, sticky='e')

                            copying = PhotoImage(file = "assets\\copy.png")
                            copy = copying.subsample(2,2)
                            copy = copy.subsample(2,2)
                            copy = copy.subsample(2,2)
                            cpy_btn = tk.Button(frame2, image = copy, borderwidth=0, command=cpyuser, cursor='hand2')
                            cpy_btn.image = copy
                            cpy_btn.grid(row =5,column=2, pady = 10, padx = 10, sticky='e')
                
                            Label(frame2, text = "Password  ", font=( 'Times' ,15)).grid(row = 6, column=0, padx=10, pady=10)

                            passwd = Label(frame2, text = '********', font=( 'Segoe UI' ,15))
                            passwd.grid(row = 6, column=1, padx=10, pady=10, sticky = 'w')

                            tk.Button(frame2, image = copy, borderwidth = 0, command=cpypass, cursor='hand2').grid(row =6,column=2, pady = 10, padx = 10)
                            hdds = PhotoImage(file = "assets\\hide.png")
                            hdd = hdds.subsample(2,2)
                            hdd = hdd.subsample(2,2)
                            hdd = hdd.subsample(2,2)
                            hdd = hdd.subsample(2,2)
                            hdd = hdd.subsample(2,2)
                            passwd_btn = Label(frame2, image = hdd, width = 5, cursor='hand2')
                            passwd_btn.image = hdd
                            passwd_btn.bind("<Button-1>",show_pass)
                            passwd_btn.grid(row =6,column=1, pady = 10, padx = 10, sticky='e')

                            Label(frame2, text = "URL  ", font=( 'Times' ,15)).grid(row = 7, column=0, padx=10, pady=10, sticky = 'e')
                            if len(decryptMessage(data[6])) > 30:
                                url_label = Label(frame2, text = decryptMessage(data[6])[:30]+"...", font=( 'Segoe UI' ,15), cursor="hand2")
                                url_label.grid(row = 7, column=1, padx=10, pady=10, sticky = 'w')
                                url_label.bind("<Enter>", lambda e: e.widget.configure( font=( 'Segoe UI' ,15, 'underline'), foreground="blue"))
                                url_label.bind("<Leave>", lambda e: e.widget.configure( font=( 'Segoe UI' ,15), foreground="black"))
                                url_label.bind("<Button-1>", open_link)
                            else:
                                url_label = Label(frame2, text = decryptMessage(data[6]), font=( 'Segoe UI' ,15), cursor="hand2")
                                url_label.grid(row = 7, column=1, padx=10, pady=10, sticky = 'w')
                                url_label.bind("<Enter>", lambda e: e.widget.configure( font=( 'Segoe UI' ,15, 'underline'), foreground="blue"))
                                url_label.bind("<Leave>", lambda e: e.widget.configure( font=( 'Segoe UI' ,15), foreground="black"))
                                url_label.bind("<Button-1>", open_link)

                            Label(frame2, text = "Creation  ", font=( 'Times' ,15)).grid(row = 8, column=0, padx=10, pady=10, sticky = 'e')
                            Label(frame2, text = decryptMessage(data[3])+" : "+decryptMessage(data[4]), font=( 'Segoe UI' ,15)).grid(row = 8, column=1, padx=10, pady=10, sticky = 'w')

                            Label(frame2, text = "Notes  ", font=( 'Times' ,15)).grid(row = 9, column=0, padx=10, pady=10, sticky = 'ne')
                            notes_txt = Text(frame2,height=7,width=38,background="grey94")
                            notes_txt.grid(row=9,column=1,pady=10,sticky='nsw')
                            notes_txt.insert(INSERT, decryptMessage(data[5]))
                            notes_txt.configure(state="disabled")
                            scrollbar = Scrollbar(frame2,orient="vertical")
                            scrollbar.grid(row=9,column=1,pady=10,sticky='nse')
                            notes_txt.config(yscrollcommand=scrollbar.set)
                            scrollbar.config(command=notes_txt.yview)
                            
                            file_record("-Secure Password Searched")
                        except TypeError:
                            for widget in frame2.winfo_children()[10:]:
                                widget.destroy()
                            messagebox.showwarning('Unavailable', 'No Records found.')
            else:
                messagebox.showerror('Missing', 'Please enter the both username and website name.')
            name_entry.focus()

        Label(frame2, text = "Search for Password", font=( 'Times' ,25)).grid(row = 0, column=0, columnspan=2, padx=10, pady=10)
        
        Label(frame2, text = "Enter Website Name", font=( 'Segoe UI' ,16)).grid(row = 1, column = 0, pady=10, padx=10, sticky='e')

        name_entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
        name_entry.grid(row = 1, column = 1, pady=10, padx=10, sticky='w')
        name_entry.focus()

        paste = PhotoImage(file = "assets\\paste.png")
        paste = paste.subsample(2,2)
        paste = paste.subsample(2,2)
        paste = paste.subsample(2,2)
        paste = paste.subsample(2,2)
        paste = paste.subsample(2,2)
        paste_btn = tk.Button(frame2, image=paste, borderwidth=0, cursor="hand2", command=paste_name)
        paste_btn.image = paste
        paste_btn.grid(row=1,column=2, pady=10)

        Label(frame2, text = "Enter Username", font=( 'Segoe UI' ,16)).grid(row = 2, column = 0, pady=10, padx=10, sticky='e')

        user_entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
        user_entry.grid(row = 2, column = 1, pady=10, padx=10, sticky='w')
        name_entry.bind("<Return>", lambda e: user_entry.focus_set())

        tk.Button(frame2, image=paste, borderwidth=0, cursor="hand2", command=paste_user).grid(row=2,column=2, pady=10)

        style.configure('W.TButton', font=('Segoe UI' , 11),width=15, borderwidth=5, padx=16,pady=8)
        style.map('W.TButton', foreground = [('active', '!disabled', '#1492e6')], background = [('active', '#1492e6')])
        button_add = Button(frame2, text="Search Password", style = "W.TButton", command = search)
        button_add.grid(row =3,column=1, pady = 10, padx = 10, sticky='e')
        user_entry.bind("<Return>",search)

        Button(frame2, text="Clear", width = 5, command = Search_Password).grid(row =3,column=0, pady = 10, padx = 10)
        name_entry.bind("<Delete>", Search_Password)
        user_entry.bind("<Delete>", Search_Password)

        sec_dis = PhotoImage(file = "assets\\sec_disp.png")
        sec = sec_dis.subsample(2,2)
        sec = sec.subsample(2,2)
        sec = sec.subsample(2,2)
        sec = sec.subsample(2,2)
        secure_btn = tk.Button(frame2, image=sec, borderwidth=0, cursor="hand2", command = show_list)
        secure_btn.image = sec
        secure_btn.grid(row =0,column=1, pady = 10, padx = 10,sticky='e')
        CreateToolTip(secure_btn, 20, 25, "Display Secure Records.\n->Press once to display secure records list.\n->Press again to hide.")

    def Delete_Password():
        for widget in frame2.winfo_children():
            widget.destroy()
        style = Style()

        def Clear(event=True):
            name_entry.delete(0, END)
            user_entry.delete(0, END)
            name_entry.focus()
            
        def paste_name():
            name_entry.insert(0, pyperclip.paste())
        def paste_user():
            user_entry.insert(0, pyperclip.paste())

        def delete(event=None):
            track_delete = 0
            if name_entry.get() != ''  and user_entry.get() != '':
                delete_username = name_entry.get()
                if delete_username == 'root' or delete_username == '42585f535e554305':
                    messagebox.showerror('Restricted', "Restricted Access")
                elif delete_username == '':
                    messagebox.showerror('Data Missing', 'Please enter the search index')
                else:
                    try:
                        decryptKey()
                        decrypt_now()
                        c.execute('SELECT URL, URN FROM schedule')
                        data = c.fetchall()
                        encrypt_now()
                        encryptKey()
                        for i in data:
                                if encryptMessage(delete_username) == i[0] and encryptMessage(user_entry.get()) == i[1]:
                                        file_record("-Password Deleted")
                                        decryptKey()
                                        decrypt_now()
                                        c.execute('DELETE FROM schedule WHERE URL=? AND URN=?', (encryptMessage(delete_username),encryptMessage(user_entry.get())))
                                        conn.commit()
                                        encrypt_now()
                                        encryptKey()
                                        talkback("Password Deleted")
                                        Show_All()
                                        track_delete += 1
                                        Clear()
                                        break
                                if encryptMessage('~' + delete_username) == i[0] and encryptMessage('~' + user_entry.get()) == i[1]:
                                    res = messagebox.askquestion('Delete Password', 'This will permanently delete a secure record.Continue?')
                                    if res == 'yes':
                                        file_record("-Secure Password Deleted")
                                        decryptKey()
                                        decrypt_now()
                                        c.execute('DELETE FROM schedule WHERE URL=? AND URN=?', (encryptMessage('~' + delete_username),encryptMessage('~' + user_entry.get())))
                                        conn.commit()
                                        encrypt_now()
                                        encryptKey()
                                        talkback("Password Deleted")
                                        Show_All()
                                        track_delete += 1
                                        Clear()
                                        break
                                    else:
                                        track_delete += 1
                                        break
                        if track_delete == 0:
                            messagebox.showerror('Missing', 'No Records Found to be deleted.')
                    except sqlite3.DatabaseError:
                        pass
            else:
                messagebox.showerror('Error!!', 'Enter a website name and corresponding username.')
            name_entry.focus()
        intro = Label(frame2, text = "Delete Your Password", font=( 'Times' ,25))
        intro.grid(row = 0, column=0, columnspan=2, padx=10, pady=10)
        
        Label(frame2, text = "Enter Website Name", font=( 'Segoe UI' ,16)).grid(row = 1, column = 0, pady=10, padx=10, sticky='e')

        name_entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
        name_entry.grid(row = 1, column = 1, pady=10, padx=10, sticky='w')
        name_entry.focus()

        paste = PhotoImage(file = "assets\\paste.png")
        paste = paste.subsample(2,2)
        paste = paste.subsample(2,2)
        paste = paste.subsample(2,2)
        paste = paste.subsample(2,2)
        paste = paste.subsample(2,2)
        paste_btn = tk.Button(frame2, image=paste, borderwidth=0, cursor="hand2", command=paste_name)
        paste_btn.image = paste
        paste_btn.grid(row=1,column=2, pady=10)

        Label(frame2, text = "Enter Username", font=( 'Segoe UI' ,16)).grid(row = 2, column = 0, pady=10, padx=10, sticky='e')

        user_entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
        user_entry.grid(row = 2, column = 1, pady=10, padx=10, sticky='w')
        name_entry.bind("<Return>", lambda e: user_entry.focus_set())

        tk.Button(frame2, image=paste, borderwidth=0, cursor="hand2", command=paste_user).grid(row=2,column=2, pady=10)

        style.configure('W.TButton', font=('Segoe UI' , 11),width=15, borderwidth=5, padx=16,pady=8)
        style.map('W.TButton', foreground = [('active', '!disabled', '#1492e6')], background = [('active', '#1492e6')])
        button_delete = Button(frame2, text="Delete Password", style = "W.TButton", command = delete)
        button_delete.grid(row = 3,column=1, padx=10, sticky='e')

        clear = Button(frame2, text="Clear", width = 5, command = Clear)
        clear.grid(row = 3,column=0)
        name_entry.bind("<Delete>", Clear)
        user_entry.bind("<Delete>", Clear)

    def Update_Password(event=None):
        for widget in frame2.winfo_children():
            widget.destroy()
        style = Style()

        def paste_name():
            name_entry.insert(0, pyperclip.paste())
        def paste_user():
            user_entry.insert(0, pyperclip.paste())

        backend = PhotoImage(file = "assets\\back.png")
        bak = backend.subsample(2,2)
        bak = bak.subsample(2,2)
        bak = bak.subsample(2,2)
        bak = bak.subsample(2,2)
        bak = bak.subsample(2,2)
        Label(frame2, text = "Update Details", font=( 'Times' ,25)).grid(row = 0, column=0, columnspan=2, padx=10, pady=10)
        
        Label(frame2, text = "Enter Website Name", font=( 'Segoe UI' ,16)).grid(row = 1, column = 0, pady=10, padx=10, sticky='e')

        name_entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
        name_entry.grid(row = 1, column = 1, pady=10, padx=10, sticky='w')
        name_entry.focus()

        paste = PhotoImage(file = "assets\\paste.png")
        paste = paste.subsample(2,2)
        paste = paste.subsample(2,2)
        paste = paste.subsample(2,2)
        paste = paste.subsample(2,2)
        paste = paste.subsample(2,2)
        paste_btn = tk.Button(frame2, image=paste, borderwidth=0, cursor="hand2", command=paste_name)
        paste_btn.image = paste
        paste_btn.grid(row=1,column=2, pady=10)

        Label(frame2, text = "Enter Username", font=( 'Segoe UI' ,16)).grid(row = 2, column = 0, pady=10, padx=10, sticky='e')

        user_entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
        user_entry.grid(row = 2, column = 1, pady=10, padx=10, sticky='w')
        name_entry.bind("<Return>", lambda e: user_entry.focus_set())

        tk.Button(frame2, image=paste, borderwidth=0, cursor="hand2", command=paste_user).grid(row=2,column=2, pady=10)

        Label(frame2, text = "Choose what you want to update", font=( 'Segoe UI' ,16)).grid(row = 3, column = 0, columnspan = 3, pady=10, padx=10)
        
        def update_username():
            if name_entry.get() != '' and user_entry.get() != '':
                new_website = name_entry.get()
                username = user_entry.get()
                
                for widget in frame2.winfo_children():
                    widget.destroy()
                def Clear(event=None):
                    new_username_entry.delete(0, END)
                    new_username_entry.focus()

                def update(event=None):
                    track = 0
                    new_username = new_username_entry.get()
                    if new_website == 'root' or new_website == '42585f535e554305':
                        messagebox.showerror('Restricted', "You do not have permission to update root details from here.")
                    elif new_website == '' or new_username == '':
                        messagebox.showerror('Missing', 'Required Data Not Found')
                    else:
                        try:
                            decryptKey()
                            decrypt_now()
                            c.execute('SELECT URL, URN FROM schedule')
                            data = c.fetchall()
                            encrypt_now()
                            encryptKey()
                            for i in data:
                                    if (encryptMessage(new_website) == i[0]) and (encryptMessage(username) == i[1]):
                                        decryptKey()
                                        decrypt_now()
                                        c.execute('UPDATE schedule SET URN=? WHERE URL=? AND URN=?', (encryptMessage(new_username), encryptMessage(new_website),encryptMessage(username)))
                                        conn.commit()
                                        encrypt_now()
                                        encryptKey()
                                        track += 1
                                        file_record("-Username Updated")
                                        talkback("Username Updated")
                                        Clear()
                                        break
                                    if encryptMessage('~' + new_website) == i[0] and encryptMessage('~'+username) == i[1]:
                                        decryptKey()
                                        decrypt_now()
                                        c.execute('UPDATE schedule SET URN=? WHERE URL=? AND URN=?', (encryptMessage(new_username), encryptMessage('~' + new_website),encryptMessage('~'+username)))
                                        conn.commit()
                                        encrypt_now()
                                        encryptKey()
                                        track += 1
                                        file_record("-Secure Record Username Updated")
                                        talkback("Username Updated")
                                        Clear()
                                        break
                            if track == 0:
                                messagebox.showerror('Missing', 'Website entered Not Found')
                            Show_All()
                            
                        except sqlite3.DatabaseError:
                            pass
                    new_username_entry.focus()
                    
                bak_btn = tk.Button(frame2, image = bak, width = 10, command = Update_Password, borderwidth=0, cursor="hand2")
                bak_btn.image = bak
                bak_btn.grid(row =0,column=0,padx=10,sticky='w')
                
                Label(frame2, text = "Update Your Username", font=( 'Times' ,25)).grid(row = 1, column=0, padx=10, pady=10, sticky='w')
                
                Label(frame2, text = "Enter New Username", font=( 'Segoe UI' ,16)).grid(row = 2, column = 0, pady=(10,0), padx=10, sticky='w')

                new_username_entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
                new_username_entry.grid(row = 3, column = 0, pady=(0,10), padx=10, sticky='w')
                new_username_entry.focus()

                style.configure('W.TButton', font=('Segoe UI' , 11),width=15, borderwidth=5, padx=16,pady=8)
                style.map('W.TButton', foreground = [('active', '!disabled', '#1492e6')], background = [('active', '#1492e6')])
                change_username = Button(frame2, text="Update Username", style = "W.TButton", command = update)
                change_username.grid(row =4,column=0, padx=10, sticky='e')
                new_username_entry.bind("<Return>",update)
                new_username_entry.bind("<Escape>",Update_Password)

                Button(frame2, width=5, text="Clear", command = Clear).grid(row =4,column=0,padx=10,sticky='w')
                new_username_entry.bind("<Delete>", Clear)
            else:
                messagebox.showerror("Missing", "Please enter a search index")


        def update_password():
            if name_entry.get() != '' and user_entry.get() != '':
                new_website = name_entry.get()
                username = user_entry.get()
                
                for widget in frame2.winfo_children():
                    widget.destroy()

                def Clear(event=None):
                    new_password_entry.delete(0, END)
                    new_password_entry.focus()

                def uppass(event=None):
                    track = 0
                    new_password = new_password_entry.get()
                    if new_website == 'root' or new_website == '42585f535e554305':
                        messagebox.showerror('Restricted', "You do not have permission to update root details from here.")
                    elif new_password == '' or new_website == '':
                        messagebox.showerror('Missing', 'Required Data Not Found')
                    else:
                        try:
                            decryptKey()
                            decrypt_now()
                            c.execute('SELECT URL, URN FROM schedule')
                            data = c.fetchall()
                            c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                            data1 = c.fetchone()
                            encrypt_now()
                            encryptKey()
                            for i in data:
                                    if encryptMessage(new_website) == i[0] and encryptMessage(username) == i[1]:
                                        decryptKey()
                                        decrypt_now()
                                        c.execute('UPDATE schedule SET LAN=? WHERE URL=? AND URN=?', (encrypt_str(encryptMessage(new_password), decryptMessage(data1[0])), encryptMessage(new_website),encryptMessage(username)))
                                        conn.commit()
                                        encrypt_now()
                                        encryptKey()
                                        track += 1
                                        file_record("-Password Updated")
                                        talkback("Password Updated")
                                        Clear()
                                        break
                                    if encryptMessage('~' + new_website) == i[0] and encryptMessage('~'+username) == i[1]:
                                        decryptKey()
                                        decrypt_now()
                                        c.execute('UPDATE schedule SET LAN=? WHERE URL=? AND URN=?', (encrypt_str(encryptMessage(new_password), decryptMessage(data1[0])), encryptMessage('~' + new_website),encryptMessage(username)))
                                        conn.commit()
                                        encrypt_now()
                                        encryptKey()
                                        track += 1
                                        file_record("-Secure Record Password Updated")
                                        talkback("Password Updated")
                                        Clear()
                                        break
                            if track == 0:
                                messagebox.showerror('Missing', 'Website entered Not Found')
                        except sqlite3.DatabaseError:
                            pass

                    new_password_entry.focus()
                    
                bak_btn = tk.Button(frame2, image = bak, width = 10, command = Update_Password, borderwidth=0,cursor="hand2")
                bak_btn.image = bak
                bak_btn.grid(row =0,column=0,padx=10,sticky='w')
                
                Label(frame2, text = "Update Your Password", font=( 'Times' ,25)).grid(row = 1, column=0, padx=10, pady=10, sticky='w')
                
                Label(frame2, text = "Enter New Password", font=( 'Segoe UI' ,16)).grid(row = 2, column = 0, pady=(10,0), padx=10, sticky='w')

                new_password_entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
                new_password_entry.grid(row = 3, column = 0, pady=(0,10), padx=10, sticky='w')
                new_password_entry.focus()

                style.configure('W.TButton', font=('Segoe UI' , 11),width=15, borderwidth=5, padx=16,pady=8)
                style.map('W.TButton', foreground = [('active', '!disabled', '#1492e6')], background = [('active', '#1492e6')])
                change_password = Button(frame2, text="Update Password", style = "W.TButton", command  = uppass)
                change_password.grid(row =4,column=0, padx=10, sticky='e')
                new_password_entry.bind("<Return>",uppass)
                new_password_entry.bind("<Escape>",Update_Password)

                Button(frame2, text="Clear", width = 5, command = Clear).grid(row =4,column=0, padx=10, sticky='w')
                new_password_entry.bind("<Delete>", Clear)
            else:
                messagebox.showerror("Missing", "Please enter a search index")

        def edit_notes():
            if name_entry.get() != '' and user_entry.get() != '':
                new_website = name_entry.get()
                username = user_entry.get()
                for widget in frame2.winfo_children():
                    widget.destroy()

                def Clear(event=None):
                    new_note_text.delete("1.0", END)
                    new_note_text.focus()

                def uppass(event=None):
                    track = 0
                    new_note = new_note_text.get("1.0", END)
                    if new_website == 'root' or new_website == '42585f535e554305':
                        messagebox.showerror('Restricted', "You do not have permission to update root details from here.")
                    elif new_note == '' or new_website == '':
                        messagebox.showerror('Missing', 'Required Data Not Found')
                    else:
                        try:
                            decryptKey()
                            decrypt_now()
                            c.execute('SELECT URL, URN FROM schedule')
                            data = c.fetchall()
                            encrypt_now()
                            encryptKey()
                            for i in data:
                                    if encryptMessage(new_website) == i[0] and encryptMessage(username) == i[1]:
                                        decryptKey()
                                        decrypt_now()
                                        c.execute('UPDATE schedule SET WAN=? WHERE URL=? AND URN=?', (encryptMessage(new_note), encryptMessage(new_website),encryptMessage(username)))
                                        conn.commit()
                                        encrypt_now()
                                        encryptKey()
                                        track += 1
                                        file_record("-Notes Updated")
                                        talkback("Notes Updated")
                                        Clear()
                                        break
                                    if encryptMessage('~' + new_website) == i[0] and encryptMessage('~'+username) == i[1]:
                                        decryptKey()
                                        decrypt_now()
                                        c.execute('UPDATE schedule SET WAN=? WHERE URL=? AND URN=?', (encryptMessage(new_note), encryptMessage('~' + new_website),encryptMessage('~'+username)))
                                        conn.commit()
                                        encrypt_now()
                                        encryptKey()
                                        track += 1
                                        file_record("-Secure Record Notes Updated")
                                        talkback("Notes Updated")
                                        Clear()
                                        break
                            if track == 0:
                                messagebox.showerror('Missing', 'Website entered Not Found')
                        except sqlite3.DatabaseError:
                            pass
                    new_note_text.focus()
                    
                bak_btn = tk.Button(frame2, image = bak, width = 10, command = Update_Password, borderwidth=0,cursor="hand2")
                bak_btn.image = bak
                bak_btn.grid(row =0,column=0,sticky='w')
                
                Label(frame2, text = "Edit Notes", font=( 'Times' ,25)).grid(row = 1, column=0, columnspan=2, padx=10, pady=10)
                
                Label(frame2, text = "Enter Note", font=( 'Segoe UI' ,16)).grid(row = 2, column = 0, pady=10, padx=10, sticky='n')

                new_note_text = Text(frame2, height = 10, width = 30, font=("Segoe UI", 14))
                new_note_text.grid(row = 2, column = 1, pady=10, padx=10)
                if new_website == '' or new_website == 'root':
                    pass
                else:
                    try:
                        decryptKey()
                        decrypt_now()
                        c.execute('SELECT WAN FROM schedule WHERE URL=? AND URN=?', (encryptMessage(new_website),encryptMessage(username)))
                        data2 = c.fetchone()
                        encrypt_now()
                        encryptKey()
                        new_note_text.insert(INSERT, decryptMessage(data2[0]))
                    except TypeError:
                        try:
                            decryptKey()
                            decrypt_now()
                            c.execute('SELECT WAN FROM schedule WHERE URL=? AND URN=?', (encryptMessage('~' + new_website),encryptMessage('~'+username)))
                            data2 = c.fetchone()
                            encrypt_now()
                            encryptKey()
                            new_note_text.insert(INSERT, decryptMessage(data2[0]))
                        except TypeError:
                            messagebox.showerror('Missing', 'Website entered Not Found')
                    except sqlite3.DatabaseError:
                        pass
                new_note_text.focus()

                style.configure('W.TButton', font=('Segoe UI' , 11),width=14, borderwidth=5, padx=16,pady=8)
                style.map('W.TButton', foreground = [('active', '!disabled', '#1492e6')], background = [('active', '#1492e6')])
                change_password = Button(frame2, text="Update Notes", style = "W.TButton", command  = uppass)
                change_password.grid(row =3,column=1,pady=10,padx=10,sticky='e')
                new_note_text.bind("<Escape>",Update_Password)

                Button(frame2, text="Clear", width = 5, command = Clear).grid(row =3,column=0,pady=10,padx=10,sticky='e')
                new_note_text.bind("<Delete>", Clear)
            else:
                messagebox.showerror("Missing", "Please enter a search index")

        def update_link():
            if name_entry.get() != '' and user_entry.get() != '':
                new_website = name_entry.get()
                username = user_entry.get()
                
                for widget in frame2.winfo_children():
                    widget.destroy()

                def Clear(event=None):
                    new_url_entry.delete(0, END)
                    new_url_entry.focus()

                def uppass(event=None):
                    track = 0
                    new_url = new_url_entry.get()
                    if new_website == 'root' or new_website == '42585f535e554305':
                        messagebox.showerror('Restricted', "You do not have permission to update root details from here.")
                    elif new_url == '' or new_website == '':
                        messagebox.showerror('Missing', 'Required Data Not Found')
                    else:
                        try:
                            decryptKey()
                            decrypt_now()
                            c.execute('SELECT URL, URN FROM schedule')
                            data = c.fetchall()
                            encrypt_now()
                            encryptKey()
                            for (i,j) in zip(data,data1):
                                    if encryptMessage(new_website) == i[0] and encryptMessage(username) == i[1]:
                                        decryptKey()
                                        decrypt_now()
                                        c.execute('UPDATE schedule SET road=? WHERE URL=? AND URN=?', (encryptMessage(new_url), encryptMessage(new_website),encryptMessage(username)))
                                        conn.commit()
                                        encrypt_now()
                                        encryptKey()
                                        track += 1
                                        file_record("-URL Updated")
                                        talkback("Link Updated")
                                        Clear()
                                        break
                                    if encryptMessage('~' + new_website) == i[0] and encryptMessage('~'+username) == i[1]:
                                        decryptKey()
                                        decrypt_now()
                                        c.execute('UPDATE schedule SET road=? WHERE URL=? AND URN=?', (encryptMessage(new_url), encryptMessage('~' + new_website),encryptMessage('~'+username)))
                                        conn.commit()
                                        encrypt_now()
                                        encryptKey()
                                        track += 1
                                        file_record("-Secure Record URL Updated")
                                        talkback("Link Updated")
                                        Clear()
                                        break
                            if track == 0:
                                messagebox.showerror('Missing', 'Website entered Not Found')
                        except sqlite3.DatabaseError:
                            pass
                    new_url_entry.focus()
                    
                bak_btn = tk.Button(frame2, image = bak, width = 10, command = Update_Password, borderwidth=0,cursor="hand2")
                bak_btn.image = bak
                bak_btn.grid(row =0,column=0,padx=10,sticky='w')
                
                Label(frame2, text = "Update URL", font=( 'Times' ,25)).grid(row = 1, column=0, padx=10, pady=10, sticky='w')
                
                Label(frame2, text = "Enter New Link", font=( 'Segoe UI' ,16)).grid(row = 2, column = 0, pady=10, padx=10, sticky='w')

                new_url_entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
                new_url_entry.grid(row = 3, column = 0, pady=10, padx=10, sticky='w')
                new_url_entry.focus()

                style.configure('W.TButton', font=('Segoe UI' , 11),width=15, borderwidth=5, padx=16,pady=8)
                style.map('W.TButton', foreground = [('active', '!disabled', '#1492e6')], background = [('active', '#1492e6')])
                change_password = Button(frame2, text="Update", style = "W.TButton", command  = uppass)
                change_password.grid(row =4,column=0, padx=10, sticky='e')
                new_url_entry.bind("<Return>",uppass)
                new_url_entry.bind("<Escape>",Update_Password)

                Button(frame2, text="Clear", width = 5, command = Clear).grid(row =4,column=0, padx=10, sticky='w')
                new_url_entry.bind("<Delete>", Clear)
            else:
                messagebox.showerror("Missing", "Please enter a search index")
        
        style.configure('W.TButton', font=('Segoe UI' , 14),width=15, borderwidth=5, padx=16,pady=8)
        style.map('W.TButton', foreground = [('active', '!disabled', '#1492e6')], background = [('active', '#1492e6')])
        Button(frame2, text="Update Username", style = "W.TButton", command = update_username).grid(row=4,column=0, pady=10, padx=10, sticky='e')
        
        Button(frame2, text="Update Password", style = "W.TButton", command = update_password).grid(row=4,column=1, pady=10,padx=10, sticky='e')

        Button(frame2, text="Edit Notes", style = "W.TButton", command = edit_notes).grid(row=5,column=0, pady=10,padx=10, sticky='e')

        Button(frame2, text="Update Link", style = "W.TButton", command=update_link).grid(row=5,column=1, pady=10,padx=10, sticky='e')

    def Search_Focus(info):
        for widget in frame2.winfo_children():
            widget.destroy()
        try:
            def Clear(event=None):
                for widget in frame2.winfo_children():
                        widget.destroy()
                Label(frame2, text="Vault", font=("Times",200,"bold"), foreground="deep sky blue").grid(row=0,column=0)
            def cpyuser():
                if decryptMessage(info[0][0])[0] == '~':
                    pyperclip.copy(decryptMessage(data[1])[1:])
                else:
                    pyperclip.copy(decryptMessage(data[1]))
                file_record("-Username Copied")
                talkback("Username Copied")

            def printStrongNess(input_string):
                p = input_string
                x = True
                vul = ''
                t = 2
                while x:
                    if(len(p)<6):
                        t -= 1
                        break
                    elif not re.search("[a-z]",p):
                        t -= 1
                        break
                    elif not re.search("[A-Z]",p):
                        t -= 1
                        break
                    elif not re.search("[0-9]",p):
                        t -= 1
                        break
                    elif not re.search("[!@#$%^&*:~`+-.?=<>;|/()]",p):
                        t -= 1
                        break
                    else:
                        t += 1
                        return True
                        x=False
                        break
                if x:
                    return False

            def cpypass():
                pyperclip.copy(decryptMessage(decrypt_str(data[2], decryptMessage(data1[0]))))
                file_record("-Password Copied")
                talkback("Password Copied")
            def hide_pass(event=None):
                passwd.configure(text='********')
                passwd_btn.bind("<Button-1>",show_pass)
                passwd_btn.configure(image=hdd)
            def show_pass(event=None):
                if len(decryptMessage(decrypt_str(data[2], decryptMessage(data1[0])))) > 28:
                    passwd.configure(text=decryptMessage(decrypt_str(data[2], decryptMessage(data1[0])))[:27]+'...')
                else:
                    passwd.configure(text=decryptMessage(decrypt_str(data[2], decryptMessage(data1[0]))))
                shos = PhotoImage(file = "assets\\show.png")
                sho = shos.subsample(2,2)
                sho = sho.subsample(2,2)
                sho = sho.subsample(2,2)
                sho = sho.subsample(2,2)
                sho = sho.subsample(2,2)
                passwd_btn.bind("<Button-1>",hide_pass)
                passwd_btn.configure(image=sho)
                passwd_btn.image = sho
            def pinout():
                def close():
                    pinned.destroy()
                pinned = Toplevel()
                pinned.overrideredirect(True)
                pinned.geometry("+0+0")
                pinned.attributes("-topmost", 1)
                if decryptMessage(info[0])[0] == '~':
                    Label(pinned, text = "Website  ", font=( 'Times' ,15 )).grid(row = 1, column=0, sticky = 'e')
                    if len(decryptMessage(data[0])) > 10:
                        Label(pinned, text = decryptMessage(data[0])[1:10]+"...", font=( 'Segoe UI' ,15 )).grid(row = 1, column=1, padx=5, pady=5, sticky = 'w')
                    else:
                        Label(pinned, text = decryptMessage(data[0])[1:], font=( 'Segoe UI' ,15 )).grid(row = 1, column=1, padx=5, pady=5, sticky = 'w')

                    Label(pinned, text = "Username  ", font=( 'Times' ,15)).grid(row = 2, column=0, padx=5, pady=5, sticky = 'e')
                    if len(decryptMessage(data[1])) > 10:
                        Label(pinned, text = decryptMessage(data[1])[1:10]+"...", font=( 'Segoe UI' ,15)).grid(row = 2, column=1, padx=5, pady=5, sticky = 'w')
                    else:
                        Label(pinned, text = decryptMessage(data[1])[1:], font=( 'Segoe UI' ,15)).grid(row = 2, column=1, padx=5, pady=5, sticky = 'w')
                    
                else:
                    Label(pinned, text = "Website  ", font=( 'Times' ,15 )).grid(row = 1, column=0, padx=5, pady=5, sticky = 'e')
                    if len(decryptMessage(data[0])) > 10:
                        Label(pinned, text = decryptMessage(data[0])[:10]+"...", font=( 'Segoe UI' ,15 )).grid(row = 1, column=1, padx=5, pady=5, sticky = 'w')
                    else:
                        Label(pinned, text = decryptMessage(data[0]), font=( 'Segoe UI' ,15 )).grid(row = 1, column=1, padx=5, pady=5, sticky = 'w')

                    Label(pinned, text = "Username  ", font=( 'Times' ,15)).grid(row = 2, column=0, padx=5, pady=5, sticky = 'e')
                    if len(decryptMessage(data[1])) > 10:
                        Label(pinned, text = decryptMessage(data[1])[:10]+"...", font=( 'Segoe UI' ,15)).grid(row = 2, column=1, padx=5, pady=5, sticky = 'w')
                    else:
                        Label(pinned, text = decryptMessage(data[1]), font=( 'Segoe UI' ,15)).grid(row = 2, column=1, padx=5, pady=5, sticky = 'w')
                copying = PhotoImage(file = "assets\\copy.png")
                copy = copying.subsample(2,2)
                copy = copy.subsample(2,2)
                copy = copy.subsample(2,2)
                cpy_btn = tk.Button(pinned, image = copy, borderwidth=0, command=cpyuser, cursor='hand2')
                cpy_btn.image = copy
                cpy_btn.grid(row =2,column=2, pady = 5, padx = 5)

                Label(pinned, text = "Password  ", font=( 'Times' ,15)).grid(row = 3, column=0, padx=5, pady=5, sticky = 'e')
                passwd = Label(pinned, text = '******', font=( 'Segoe UI' ,15))
                passwd.grid(row = 3, column=1, padx=5, pady=5, sticky = 'w')

                tk.Button(pinned, image = copy, borderwidth=0, command=cpypass, cursor='hand2').grid(row =3,column=2, pady = 5, padx = 5)
                quit_top = tk.Button(pinned, text = "X" ,borderwidth=0,  background="red", foreground="white",command=close, cursor='hand2')
                quit_top.grid(row =1,column=2, ipadx=5, sticky='ne')

                pinned.mainloop()

            def open_link(event=None):
                webbrowser.open(decryptMessage(data[6]))
            decryptKey()
            decrypt_now()
            c.execute('SELECT * FROM schedule WHERE URL=? AND URN=?', (info[0],info[1]))
            data = c.fetchone()
            c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
            data1 = c.fetchone()
            encrypt_now()
            encryptKey()
            dis_img = PhotoImage(file = decryptMessage(data[7]))
            dis_img = dis_img.subsample(2,2)
            dis_img = dis_img.subsample(2,2)
            dis_img = dis_img.subsample(2,2)
            dis_label = Label(frame2, image=dis_img)
            dis_label.image = dis_img
            dis_label.grid(row=0,column=0,padx=10,sticky='se')
            if decryptMessage(info[0])[0] == '~':
                if len(decryptMessage(info[0])) > 10:
                    detail = Label(frame2, text = decryptMessage(info[0]).upper()[1:10]+"...", font=( 'System' ,18 ,'bold'))
                else:
                    detail = Label(frame2, text = decryptMessage(info[0]).upper()[1:], font=( 'System' ,18, 'bold'))
                detail.grid(row = 0, column=1 ,padx=10, sticky='nw')
                detail.focus()
                detail.bind("<Escape>",Clear)
                detail.bind("<Button-1>",Clear)
                CreateToolTip(detail, 50, 35,"Clear Screen")

                Label(frame2, text = "Website  ", font=( 'Times' ,15 )).grid(row = 1, column=0, padx=10, pady=10, sticky = 'e')
                if len(decryptMessage(data[0])) > 28:
                    Label(frame2, text = decryptMessage(data[0])[1:28]+"...", font=( 'Segoe UI' ,15 )).grid(row = 1, column=1, padx=10, pady=10, sticky = 'w')
                else:
                    Label(frame2, text = decryptMessage(data[0])[1:], font=( 'Segoe UI' ,15 )).grid(row = 1, column=1, padx=10, pady=10, sticky = 'w')

                Label(frame2, text = "Username  ", font=( 'Times' ,15)).grid(row = 2, column=0, padx=10, pady=10, sticky = 'e')
                if len(decryptMessage(data[1])) > 26:
                    Label(frame2, text = decryptMessage(data[1])[1:26]+"...", font=( 'Segoe UI' ,15)).grid(row = 2, column=1, padx=10, pady=10, sticky = 'w')
                else:
                    Label(frame2, text = decryptMessage(data[1])[1:], font=( 'Segoe UI' ,15)).grid(row = 2, column=1, padx=10, pady=10, sticky = 'w')
                
            else:
                if len(decryptMessage(info[0])) > 10:
                    detail = Label(frame2, text = decryptMessage(info[0]).upper()[:10]+"...", font=( 'Candara' ,18, 'bold'))
                else:
                    detail = Label(frame2, text = decryptMessage(info[0]).upper(), font=( 'Candara' ,18, 'bold'))
                detail.grid(row = 0, column=1, padx=10, pady=10, sticky='w')
                detail.focus()
                detail.bind("<Escape>",Clear)
                detail.bind("<Button-1>",Clear)
                CreateToolTip(detail, 50, 35,"Clear Screen")

                Label(frame2, text = "Website  ", font=( 'Times' ,15 )).grid(row = 1, column=0, padx=10, pady=10, sticky = 'e')
                if len(decryptMessage(data[0])) > 28:
                    Label(frame2, text = decryptMessage(data[0])[:28]+"...", font=( 'Segoe UI' ,15 )).grid(row = 1, column=1, padx=10, pady=10, sticky = 'w')
                else:
                    Label(frame2, text = decryptMessage(data[0]), font=( 'Segoe UI' ,15 )).grid(row = 1, column=1, padx=10, pady=10, sticky = 'w')

                Label(frame2, text = "Username  ", font=( 'Times' ,15)).grid(row = 2, column=0, padx=10, pady=10, sticky = 'e')
                if len(decryptMessage(data[1])) > 26:
                    Label(frame2, text = decryptMessage(data[1])[:26]+"...", font=( 'Segoe UI' ,15)).grid(row = 2, column=1, padx=10, pady=10, sticky = 'w')
                else:
                    Label(frame2, text = decryptMessage(data[1]), font=( 'Segoe UI' ,15)).grid(row = 2, column=1, padx=10, pady=10, sticky = 'w')

            if printStrongNess(decryptMessage(decrypt_str(data[2], decryptMessage(data1[0])))):
                Label(frame2, text="Strong Password", font=( 'arial' ,10), foreground="green").grid(row=0,column=1,padx=10,pady=(5,0),sticky='sw')
            else:
                Label(frame2, text="Weak Password", font=( 'arial' ,10), foreground="red").grid(row=0,column=1,padx=10,pady=(5,0),sticky='sw')

            if check_password_repition(data[2]) == False:
                correct = PhotoImage(file = "assets\\correct.png")
                correct = correct.subsample(2,2)
                correct = correct.subsample(2,2)
                correct = correct.subsample(2,2)
                correct = correct.subsample(2,2)
                correct = correct.subsample(2,2)
                correct_lbl = Label(frame2, image=correct)
                correct_lbl.image = correct
                correct_lbl.grid(row=0,column=1,padx=10, sticky='e')

            pin = PhotoImage(file = "assets\\pin.png")
            pin = pin.subsample(2,2)
            pin = pin.subsample(2,2)
            pin = pin.subsample(2,2)
            pin = pin.subsample(2,2)
            pin = pin.subsample(2,2)
            pin_btn = tk.Button(frame2, image=pin, borderwidth=0, cursor='hand2', command=pinout)
            pin_btn.image = pin
            pin_btn.grid(row =0,column=2, pady = 10, padx = 10, sticky='e')
            
            copying = PhotoImage(file = "assets\\copy.png")
            copy = copying.subsample(2,2)
            copy = copy.subsample(2,2)
            copy = copy.subsample(2,2)
            cpy_btn = tk.Button(frame2, image = copy, borderwidth=0, command=cpyuser, cursor='hand2')
            cpy_btn.image = copy
            cpy_btn.grid(row =2,column=2, pady = 10, padx = 10)

            Label(frame2, text = "Password  ", font=( 'Times' ,15)).grid(row = 3, column=0, padx=10, pady=10, sticky = 'e')
            passwd = Label(frame2, text = '******', font=( 'Segoe UI' ,15))
            passwd.grid(row = 3, column=1, padx=10, pady=10, sticky = 'w')

            tk.Button(frame2, image = copy, borderwidth=0, command=cpypass, cursor='hand2').grid(row =3,column=2, pady = 10, padx = 10)
            hdds = PhotoImage(file = "assets\\hide.png")
            hdd = hdds.subsample(2,2)
            hdd = hdd.subsample(2,2)
            hdd = hdd.subsample(2,2)
            hdd = hdd.subsample(2,2)
            hdd = hdd.subsample(2,2)
            passwd_btn = Label(frame2, image = hdd, width = 5, cursor='hand2')
            passwd_btn.bind("<Button-1>",show_pass)
            passwd_btn.image = hdd
            passwd_btn.grid(row =3,column=1, pady = 10, padx = 10, sticky='e')

            Label(frame2, text = "URL  ", font=( 'Times' ,15)).grid(row = 4, column=0, padx=10, pady=10, sticky = 'e')
            if len(decryptMessage(data[6])) > 30:
                url_label = Label(frame2, text = decryptMessage(data[6])[:30]+"...", font=( 'Segoe UI' ,15), cursor="hand2")
                url_label.grid(row = 4, column=1, padx=10, pady=10, sticky = 'w')
                url_label.bind("<Enter>", lambda e: e.widget.configure( font=( 'Segoe UI' ,15, 'underline'), foreground="blue"))
                url_label.bind("<Leave>", lambda e: e.widget.configure( font=( 'Segoe UI' ,15), foreground="black"))
                url_label.bind("<Button-1>", open_link)
            else:
                url_label = Label(frame2, text = decryptMessage(data[6]), font=( 'Segoe UI' ,15), cursor="hand2")
                url_label.grid(row = 4, column=1, padx=10, pady=10, sticky = 'w')
                url_label.bind("<Enter>", lambda e: e.widget.configure( font=( 'Segoe UI' ,15, 'underline'), foreground="blue"))
                url_label.bind("<Leave>", lambda e: e.widget.configure( font=( 'Segoe UI' ,15), foreground="black"))
                url_label.bind("<Button-1>", open_link)

            Label(frame2, text = "Creation  ", font=( 'Times' ,15)).grid(row = 5, column=0, padx=10, pady=10, sticky = 'e')
            Label(frame2, text = decryptMessage(data[3])+" : "+decryptMessage(data[4]), font=( 'Segoe UI' ,15)).grid(row = 5, column=1, padx=10, pady=10, sticky = 'w')

            Label(frame2, text = "Notes  ", font=( 'Times' ,15)).grid(row = 6, column=0,padx=10, pady=10, sticky = 'ne')
            notes_txt = tk.Text(frame2,height=7,width=37,background="grey94", borderwidth=0)
            notes_txt.grid(row=6,column=1,pady=10,padx=(10,0),sticky='nsw')
            notes_txt.insert(INSERT, decryptMessage(data[5]))
            notes_txt.configure(state="disabled")
            scrollbar = Scrollbar(frame2,orient="vertical")
            scrollbar.grid(row=6,column=1,pady=10,sticky='nse')
            notes_txt.config(yscrollcommand=scrollbar.set)
            scrollbar.config(command=notes_txt.yview)
            file_record("-Password Searched")
        except TypeError:
            for widget in frame2.winfo_children():
                widget.destroy()
            Label(frame2, text="Vault", font=("Times",200,"bold"), foreground="deep sky blue").grid(row=0,column=0)
            messagebox.showwarning('No Information', 'Information related to not found')

    def Show_All(event=None):
        try:
            def onClick(labelNum):
                Search_Focus(labelNum)
            def onClear(labelNum):
                pyperclip.copy(decryptMessage(labelNum))
                talkback("Website Copied")
            def onCleuse(labelNum):
                pyperclip.copy(decryptMessage(labelNum))
                talkback("Username Copied")
            for widget in frame.winfo_children():
                widget.destroy()
            row = 0
            column=0
            decryptKey()
            decrypt_now()
            c.execute('SELECT URL, URN, image FROM schedule')
            data = c.fetchall()[1:]
            encrypt_now()
            encryptKey()
            for i in data:
                if decryptMessage(i[0])[0] == '~' or decryptMessage(i[1])[0] == '~':
                    continue
                row += 1
                try:
                    dis_img = PhotoImage(file = decryptMessage(i[2]))
                    dis_img = dis_img.subsample(2,2)
                    dis_img = dis_img.subsample(2,2)
                    dis_img = dis_img.subsample(2,2)
                    dis_img = dis_img.subsample(2,2)
                    dis_label = Label(frame, image=dis_img)
                    dis_label.image = dis_img
                    dis_label.grid(row=row,column=0,pady=10,padx=10)
                except:
                    dis_img = PhotoImage(file = 'assets\\world.png')
                    dis_img = dis_img.subsample(2,2)
                    dis_img = dis_img.subsample(2,2)
                    dis_img = dis_img.subsample(2,2)
                    dis_img = dis_img.subsample(2,2)
                    dis_label = Label(frame, image=dis_img)
                    dis_label.image = dis_img
                    dis_label.grid(row=row,column=0,pady=10,padx=10)
                if len(decryptMessage(i[0])) > 18:
                    list_label = Label(frame, text = decryptMessage(i[0])[:18]+"..", font=( 'Segoe UI' ,16), cursor="hand2")
                else:
                    list_label = Label(frame, text = decryptMessage(i[0]), font=( 'Segoe UI' ,16), cursor="hand2")
                list_label.grid(row=row,column=1,sticky='nw',padx=10)
                list_label2 = Label(frame, text = decryptMessage(i[1]), font=( 'Segoe UI' ,12), cursor="hand2")
                list_label2.grid(row=row,column=1,sticky='sw',padx=10)
                list_label.bind("<Button-1>", lambda e, labelNum=i: onClick(labelNum))
                list_label2.bind("<Button-1>", lambda e, labelNum=i: onClick(labelNum))
                list_label.bind("<Enter>", lambda e, : e.widget.config(foreground="red", font=('Comic Sans MS', 16)))
                list_label.bind("<Leave>", lambda e, : e.widget.config(foreground="black", font=( 'Segoe UI' ,16)))
                list_label2.bind("<Enter>", lambda e, : e.widget.config(foreground="green", font=('Segoe UI', 12)))
                list_label2.bind("<Leave>", lambda e, : e.widget.config(foreground="black", font=( 'Segoe UI' ,12)))
                list_label.bind("<Button-3>", lambda e, labelNum=i[0]: onClear(labelNum))
                list_label2.bind("<Button-3>", lambda e, labelNum=i[1]: onCleuse(labelNum))
                column+=1

            if row < 1:
                list_label = Label(frame, text = "Empty", font=( 'Times' ,16, 'bold' ))
                list_label.grid(row=1,column=1,columnspan=2)
            total_etn.config(text="Total entries: " + str(row))
        except sqlite3.DatabaseError:
            pass
    def Delete_Account():
        for widget in frame2.winfo_children():
            widget.destroy()

        def verify_auth(event=None):
            try:
                passwd = verify_Entry.get()
                message = passwd.encode()
                hash_verify_password = encryptMessage(hashlib.blake2b(message).hexdigest())
                decryptKey()
                decrypt_now()
                c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                data = c.fetchone()
                encrypt_now()
                encryptKey()
                if hash_verify_password == data[0]:
                    access()
                else:
                    Label(frame2, text="Incorrect Password",foreground="red").grid(row=2,column=0,pady=10,padx=10,sticky='w')
                    verify_Entry.focus()
            except sqlite3.DatabaseError:
                pass

        Label(frame2, text = "Password", font=( 'Segoe UI' ,16), foreground="red3").grid(row = 0, column = 0, padx=10, sticky='w')

        verify_Entry = Entry(frame2, width = 30, font=("Segoe UI", 14), show="•")
        verify_Entry.grid(row = 1, column = 0, pady = (0,10), padx = 10)
        verify_Entry.focus()

        Button(frame2, text="Verify", command = verify_auth).grid(row = 2,column=0,pady=10,padx=10,sticky='ne')
        verify_Entry.bind("<Return>",verify_auth)
        def access():
            global root
            for widget in frame2.winfo_children():
                widget.destroy()
            try:
                res = messagebox.askquestion('Delete Account', 'This will delete your account and all records.Continue?')
                if res == 'yes':
                    c.close()
                    conn.close()
                    if os.path.isfile(r'C:\\Users\\' + user + '\\Notepad\\Logs.txt'):
                        os.remove(r'C:\\Users\\' + user + '\\Notepad\\Logs.txt')
                        os.rmdir(r'C:\\Users\\' + user + '\\Notepad\\')
                    if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db'):
                        os.remove(r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db')
                    if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db.aes'):
                        os.remove(r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db.aes')
                    if os.path.isdir(r'C:\\Users\\' + user + '\\AppData\\database\\'):
                        os.rmdir(r'C:\\Users\\' + user + '\\AppData\\database\\')
                    if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key'):
                        os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key')
                    if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key.aes'):
                        os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key.aes')
                    if os.path.isdir(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\'):
                        os.rmdir(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\')
                    if os.path.exists(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                        for file in os.listdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                            os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'+file)
                    if os.path.isdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                        os.rmdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\')
                    if os.path.isdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\'):
                        os.rmdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\')
                    if os.path.isdir(r'C:\\Users\\' + user + '\\manage\\Logs\\'):
                        if len(os.listdir(r'C:\\Users\\' + user + '\\manage\\Logs\\')) == 0:
                            os.rmdir(r'C:\\Users\\' + user + '\\manage\\Logs\\')
                            os.rmdir(r'C:\\Users\\' + user + '\\manage\\')
                        else:
                            filelist = [f for f in os.listdir(r'C:\\Users\\' + user + '\\manage\\Logs')]
                            for f in filelist:
                                os.remove(r'C:\\Users\\' + user + '\\manage\\Logs\\' + f)
                            os.rmdir(r'C:\\Users\\' + user + '\\manage\\Logs\\')
                            os.rmdir(r'C:\\Users\\' + user + '\\manage\\')
                    root.destroy()
                    MessageBox = ctypes.windll.user32.MessageBoxW
                    MessageBox(None, 'Account Deleted,open application again to make a new one', 'Deleted', 0)
                    sys.exit()
                else:
                    Label(frame2, text="Vault", font=("Times",200,"bold"), foreground="deep sky blue").grid(row=0,column=0)
            except FileNotFoundError:
                pass
            except sqlite3.DatabaseError:
                pass
            except OSError:
                messagebox.showerror('Error', 'Deletion could not be performed succesfully as the folder to be deleted is open, preventing the software from deleting it.Please close all open folders and press OK to perform successfull deletion.')
                if os.path.isfile(r'C:\\Users\\' + user + '\\Notepad\\Logs.txt'):
                    os.remove(r'C:\\Users\\' + user + '\\Notepad\\Logs.txt')
                    os.rmdir(r'C:\\Users\\' + user + '\\Notepad\\')
                if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db'):
                    os.remove(r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db')
                if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db.aes'):
                    os.remove(r'C:\\Users\\' + user + '\\AppData\\database\\schedule.db.aes')
                if os.path.isdir(r'C:\\Users\\' + user + '\\AppData\\database\\'):
                    os.rmdir(r'C:\\Users\\' + user + '\\AppData\\database\\')
                if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key'):
                    os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key')
                if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key.aes'):
                    os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\key.key.aes')
                if os.path.isdir(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\'):
                    os.rmdir(r'C:\\Users\\' + user + '\\AppData\\Local\\manage\\')
                if os.path.exists(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                    for file in os.listdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                        os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'+file)
                if os.path.isdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                    os.rmdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\')
                if os.path.isdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\'):
                    os.rmdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\')
                if os.path.isdir(r'C:\\Users\\' + user + '\\manage\\Logs\\'):
                    if len(os.listdir(r'C:\\Users\\' + user + '\\manage\\Logs\\')) == 0:
                        os.rmdir(r'C:\\Users\\' + user + '\\manage\\Logs\\')
                        os.rmdir(r'C:\\Users\\' + user + '\\manage\\')
                    else:
                        filelist = [f for f in os.listdir(r'C:\\Users\\' + user + '\\manage\\Logs')]
                        for f in filelist:
                            os.remove(r'C:\\Users\\' + user + '\\manage\\Logs\\' + f)
                        os.rmdir(r'C:\\Users\\' + user + '\\manage\\Logs\\')
                        os.rmdir(r'C:\\Users\\' + user + '\\manage\\')
                root.destroy()
                MessageBox = ctypes.windll.user32.MessageBoxW
                MessageBox(None, 'Account Deleted,open application again to make a new one', 'Deleted', 0)
                sys.exit()
    def Generate_Password():
        for widget in frame2.winfo_children():
            widget.destroy()

        style = Style()
        def form(event=None):
            for widget in frame2.winfo_children()[4:]:
                    widget.destroy()
            import array
            import secrets

            def COPY(event=None):
                pyperclip.copy(password)
                gen_password_entry.focus()
                file_record("-Password Generated and Copied")
                talkback("Password Copied")
                
            def Clear(event=None):
                gen_password_entry.delete(0, END)
                display.destroy()
                button_copy.destroy()
                clear.destroy()
                long_lbl.destroy()
                gen_password_entry.focus()
                
            if gen_password_entry.get() == '':
                messagebox.showwarning('Missing', 'Please enter the length')
            else:
                try:
                    MAX_LEN = int(gen_password_entry.get())

                    DIGITS = ['0','1','2','3','4','5','6','7','8','9']
                    LOCASE_CHARACTERS = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
                    UPCASE_CHARACTERS = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
                    SYMBOLS = ['!','@','#','$','%','^','&','*',':','~','`','+','-','.',',','?','=','<','>',';''|','/','(',')']

                    COMBINED_LIST = DIGITS+LOCASE_CHARACTERS+UPCASE_CHARACTERS+SYMBOLS

                    rand_digit = secrets.choice(DIGITS)
                    rand_lower = secrets.choice(LOCASE_CHARACTERS)
                    rand_upper = secrets.choice(UPCASE_CHARACTERS)
                    rand_symbol = secrets.choice(SYMBOLS)

                    temp_pass = rand_digit + rand_symbol + rand_lower + rand_upper

                    for x in range(MAX_LEN - 4):
                        temp_pass += secrets.choice(COMBINED_LIST)
                        temp_pass_list = array.array('u' ,temp_pass)
                        random.shuffle(temp_pass_list)
                    password=""
                    for x in temp_pass_list:
                        password += x

                    clear = Button(frame2, text="Clear", width = 5, command=Clear)
                    clear.grid(row = 3,column=0,pady=10,padx=10, sticky='w')
                    gen_password_entry.bind("<Delete>",Clear)

                    if len(password) > 20:
                        display = Label(frame2, text = password[0:20]+"..", font=( 'aria' ,16))
                        long_lbl = Label(frame2, text="Password Length too long", foreground="red")
                        long_lbl.grid(row = 5, column=0, padx=10,sticky='w')
                    else:
                        display = Label(frame2, text = password, font=( 'aria' ,16))
                    display.grid(row = 4, column = 0, pady = 10, padx = 10,sticky='w')

                    copying = PhotoImage(file = "assets\\copy.png")
                    copy = copying.subsample(2,2)
                    copy = copy.subsample(2,2)
                    copy = copy.subsample(2,2)
                    button_copy = tk.Button(frame2, image = copy, borderwidth=0, command=COPY, cursor='hand2')
                    button_copy.image = copy
                    button_copy.grid(row = 4,column=0,pady=10,padx=10,sticky='e')
                    file_record("-Password Generated")
                except ValueError:
                    messagebox.showerror('Non Numerical', 'Please enter the correct length')
                except UnboundLocalError:
                    messagebox.showerror('Too Small', 'No Strong Password can be less than five characters in length')
            gen_password_entry.focus()
        Label(frame2, text = "Password Generator", font=( 'Times' ,25)).grid(row = 0, column=0, columnspan=2, padx=10, pady=10, sticky='w')

        Label(frame2, text = "Enter Length of Password", font=( 'Segoe UI' ,16)).grid(row = 1, column = 0, pady=(10,0), padx=10, sticky='w')

        gen_password_entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
        gen_password_entry.grid(row = 2, column = 0, pady=(0,10), padx=10, sticky='we')
        gen_password_entry.focus()

        style.configure('W.TButton', font=('Segoe UI' , 11),width=17, borderwidth=5, padx=16,pady=8)
        style.map('W.TButton', foreground = [('active', '!disabled', '#1492e6')], background = [('active', '#1492e6')])
        Button(frame2, text="Generate Password", style = "W.TButton", command = form).grid(row =3,column=0, padx=10, sticky='e')
        gen_password_entry.bind("<Return>",form)

        
    def signin():
        auth = Tk()
        auth.title("Create Account")
        auth.resizable(False,False)
        w = 600
        h = 350
        auth.geometry("{}x{}+{}+{}".format(w, h, int(auth.winfo_screenwidth()/2 - w/2), int(auth.winfo_screenheight()/2 - h/2)))
        auth.iconbitmap('assets\\lock.ico')
        style = Style()

        def Import(event=None):
            importlbl.unbind("<Button-1>")
            from tkinter.filedialog import askopenfile

            def on_closing():
                importlbl.bind("<Button-1>", Import)
                imp.destroy()

            def hide_psd():
                check_show_psw.configure(image=show,command=show_psd)
                check_show_psw.image = show
                passwd_ent.config(show="•")
                
            def show_psd():
                hides = PhotoImage(file = "assets\\show.png")
                hide = hides.subsample(2,2)
                hide = hide.subsample(2,2)
                hide = hide.subsample(2,2)
                hide = hide.subsample(2,2)
                hide = hide.subsample(2,2)
                check_show_psw.configure(image=hide, command=hide_psd)
                check_show_psw.image = hide
                passwd_ent.config(show="")
                passwd_ent.focus()

            def open_file():
                if file_ent.get() != '':
                    file_ent.delete(0, END)
                file = askopenfile(filetypes = [('Vault Export', '*.aes')])
                if file is not None:
                        file_ent.insert(0, file.name)
                dec_key.focus()

            def import_db(event=None):
                if file_ent.get() == '' or dec_key.get() == '' or passwd_ent.get() == '':
                    messagebox.showwarning("Empty", "Incomplete information provided")
                elif os.path.exists(file_ent.get()):
                    if (file_ent.get().endswith('.zip.aes')):
                        user = getpass.getuser()
                        filename = file_ent.get()
                        password = passwd_ent.get()
                        message = password.encode()
                        hash_verify_password = encryptMessage(hashlib.blake2b(message).hexdigest())
                        key = dec_key.get()
                        message = key.encode()
                        hash_key = encryptMessage(hashlib.blake2b(message).hexdigest())                
                        if not os.path.exists('C:\\Users\\' + user + '\\AppData\\Local\\Vault\\'):
                            os.mkdir('C:\\Users\\' + user + '\\AppData\\Local\\Vault\\')
                        if not os.path.exists('C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                            os.mkdir('C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\')
                            ctypes.windll.kernel32.SetFileAttributesW('C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\', 2)
                        try:
                            pyAesCrypt.decryptFile(filename, 'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\' + filename.rsplit('/', 1)[1][:-4], hash_key, 64*1024)
                            pyAesCrypt.decryptFile(filename, filename[:-4], hash_key, 64*1024)
                            for file in ZipFile(filename[:-4]).namelist():
                                if ZipFile(filename[:-4]).getinfo(file).filename.endswith('.csv.aes.aes'):
                                    ZipFile(filename[:-4]).extract(file, os.getcwd())
                            os.remove(filename[:-4])
                            pyAesCrypt.decryptFile(filename.rsplit('/',1)[1][:-8]+'.csv.aes.aes', filename.rsplit('/',1)[1][:-8]+'.csv.aes', hash_verify_password, 64*1024)
                            pyAesCrypt.decryptFile(filename.rsplit('/',1)[1][:-8]+'.csv.aes', filename.rsplit('/',1)[1][:-8]+'.csv', hash_key, 64*1024)
                            os.remove(filename.rsplit('/',1)[1][:-8]+'.csv.aes.aes')
                            os.remove(filename.rsplit('/',1)[1][:-8]+'.csv.aes')
                        except ValueError:
                            if os.path.exists(filename.rsplit('/',1)[1][:-8]+'.csv.aes'):
                                os.remove(filename.rsplit('/',1)[1][:-8]+'.csv.aes')
                            messagebox.showerror('Authentication error', 'Extraction failed.Please enter correct password')
                            dec_key.focus()
                        else:
                            for file in ZipFile('C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\' + filename.rsplit('/', 1)[1][:-4]).namelist():
                                if ZipFile('C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\' + filename.rsplit('/', 1)[1][:-4]).getinfo(file).filename.endswith('.txt.aes'):
                                    ZipFile('C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\' + filename.rsplit('/', 1)[1][:-4]).extract(file, 'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\')
                            ZipFile('C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\' + filename.rsplit('/', 1)[1][:-4]).extract("url.aes", 'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\')
                            os.remove('C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\' + filename.rsplit('/', 1)[1][:-4])
                            unsafeKey()
                            decryptKey()
                            decrypt_now()
                            with open(filename.rsplit('/',1)[1][:-8]+'.csv', 'r') as fin:
                                dr = csv.DictReader(fin)
                                to_db = [(i['URL'], i['URN'], i['LAN'], i['date'], i['time'], i['WAN'], i['road'], i['image']) for i in dr]

                            conn.executemany("INSERT INTO schedule (URL, URN, LAN, date, time, WAN, road, image) VALUES (?, ?, ?, ?, ?, ?, ?, ?);", to_db)
                            conn.commit()
                            encrypt_now()
                            encryptKey()
                            safeKey()
                            if os.path.exists(filename.rsplit('/',1)[1][:-8]+'.csv'):
                                os.remove(filename.rsplit('/',1)[1][:-8]+'.csv')
                            c.close()
                            conn.close()
                            encryptFile()
                            auth.destroy()
                            file_record("-Passwords Imported")
                            MessageBox = ctypes.windll.user32.MessageBoxW
                            MessageBox(None, 'Import Complete. Run VAULT again to log in.', 'Success', 0)
                            sys.exit()
                    else:
                        messagebox.showerror('Corrupt File', 'File provided not VAULT exported file')
                else:
                    messagebox.showerror('File Not Found', 'File not found in specified path')
            imp = Toplevel()
            imp.title("Import Passwords")
            imp.geometry("280x500")
            imp.resizable(False, False)
            imp.iconbitmap('assets\\lock.ico')
            Label(imp, text = "Import Passwords", font=( 'Segoe UI' ,16, 'underline')).grid(row=0,column=0, columnspan=2, padx=10,pady=10)

            impo = PhotoImage(file = "assets\\import.png")
            impo = impo.subsample(2,2)
            impo = impo.subsample(2,2)
            img_lbl = Label(imp,image=impo)
            img_lbl.image = impo
            img_lbl.grid(row=1,column=0,columnspan=2,pady=10,padx=10)

            Label(imp, text = "Filename", font=( 'Segoe UI' ,15)).grid(row=2,column=0,padx=10,pady=(10,0), sticky='w')

            file_ent = Entry(imp, width = 26, font=("Segoe UI", 12))
            file_ent.grid(row=3,column=0,padx=(10,0),pady=(0,10),sticky='w')
            file_ent.focus()

            ope = PhotoImage(file = "assets\\open.png")
            ope = ope.subsample(2,2)
            ope = ope.subsample(2,2)
            ope = ope.subsample(2,2)
            ope = ope.subsample(2,2)
            ope = ope.subsample(2,2)
            open_btn = tk.Button(imp, image=ope, borderwidth=0, cursor="hand2", command=open_file)
            open_btn.image = ope
            open_btn.grid(row=3,column=1, sticky='w')
            CreateToolTip(open_btn, 15, 20,"Open Vault Export file")

            Label(imp, text = "Decryption Key", font=( 'Segoe UI' ,15)).grid(row=4,column=0,padx=10,pady=(10,0),sticky='w')

            dec_key = Entry(imp, width = 26, font=("Segoe UI", 12))
            dec_key.grid(row=5,column=0,padx=10,pady=(0,10),sticky='w')
            file_ent.bind("<Return>", lambda e: dec_key.focus_set())

            Label(imp, text = "Your Password", font=( 'Segoe UI' ,15)).grid(row=6,column=0,padx=10,pady=(10,0),sticky='w')

            passwd_ent = Entry(imp, width = 26, font=("Segoe UI", 12), show="•")
            passwd_ent.grid(row=7,column=0,padx=(10,0),pady=(0,10),sticky='w')
            dec_key.bind("<Return>", lambda e: passwd_ent.focus_set())
            passwd_ent.bind("<Return>", import_db)

            im = PhotoImage(file = "assets\\hide.png")
            im = im.subsample(2,2)
            im = im.subsample(2,2)
            im = im.subsample(2,2)
            im = im.subsample(2,2)
            im = im.subsample(2,2)
            check_show_psw = tk.Button(imp,image=im,borderwidth=0,command=show_psd, cursor="hand2")
            check_show_psw.image = im
            check_show_psw.grid(row=7,column=1,sticky='w')

            tk.Button(imp, text="Import", font=( 'Segoe UI' ,10), background="#1492e6",foreground="white", activebackground="#1492e6", activeforeground="white", width=13, command=import_db).grid(row=8,column=0,columnspan=2,padx=10,pady=(10,0))

            imp.protocol("WM_DELETE_WINDOW", on_closing)
            imp.mainloop()

        def print_choice(event=None):
            return choice_var.get()
        def hide_psd():
            check_show_psw.configure(image=show,command=show_psd)
            check_show_psw.image = show
            password_Entry.config(show="•")
            
        def show_psd():
            hides = PhotoImage(file = "assets\\show.png")
            hide = hides.subsample(2,2)
            hide = hide.subsample(2,2)
            hide = hide.subsample(2,2)
            hide = hide.subsample(2,2)
            hide = hide.subsample(2,2)
            check_show_psw.configure(image=hide, command=hide_psd)
            check_show_psw.image = hide
            password_Entry.config(show="")
            password_Entry.focus()

        def on_closing():
            c.close()
            conn.close()
            encryptFile()
            auth.destroy()
            sys.exit()

        def addition(event=None):
            pass_website = '42585f535e554305'
            pass_username = username_Entry.get()
            message = pass_username.encode()
            hash_username = encryptMessage(hashlib.blake2b(message).hexdigest())
            pass_password = password_Entry.get()
            message = pass_password.encode()
            hash_password = encryptMessage(hashlib.blake2b(message).hexdigest())
            security_question = print_choice()
            message = security_question.encode()
            hash_question = encryptMessage(hashlib.blake2b(message).hexdigest())
            security_answer = question_Entry.get()
            message = security_answer.encode()
            hash_answer = encryptMessage(hashlib.blake2b(message).hexdigest())

            if pass_username == '' or pass_password == '' or security_answer == '':
                messagebox.showwarning('Missing', 'Please fill in ALL Details')
            else:
                unsafeKey()
                decryptKey()
                decrypt_now()
                c.execute("INSERT INTO schedule (URL, URN, LAN, date, time) VALUES (?, ?, ?, ?, ?)", (pass_website, hash_username, hash_password, hash_question, hash_answer))
                conn.commit()
                encrypt_now()
                encryptKey()
                file_record("-Account Created")
                auth.destroy()

        frame1 = Frame(auth)
        frame1.pack(side=LEFT, fill=BOTH, expand=True)
        creation = PhotoImage(file = "assets\\create_acc.png")
        Label(frame1,image=creation).pack(side=BOTTOM, fill=BOTH, expand=True,anchor='w')

        frame2 = Frame(auth)
        frame2.pack(side=LEFT, fill=None, expand=True)

        Label(frame2, text = "Username", font=( 'Segoe UI' ,16)).grid(row = 0, column = 0,pady=(10,0), sticky='w')

        username_Entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
        username_Entry.grid(row = 1, column = 0, pady = (0,10))

        importlbl = Label(frame2, text = "Import Passwords", font=( 'Segoe UI' ,9, 'underline'), foreground="IndianRed1", cursor="hand2")
        importlbl.grid(row = 8, column = 0,pady=(5,10), sticky='nw')
        importlbl.bind("<Button-1>", Import)

        Label(frame2, text = "Password", font=( 'Segoe UI' ,16)).grid(row = 2, column = 0, sticky='w')

        password_Entry = Entry(frame2, width = 30, font=("Segoe UI", 14), show = "•")
        password_Entry.grid(row = 3, column = 0, pady = (0,10),sticky='w')
        username_Entry.focus()
        username_Entry.bind("<Return>", lambda e: password_Entry.focus_set())

        shows = PhotoImage(file = "assets\\hide.png")
        show = shows.subsample(2,2)
        show = show.subsample(2,2)
        show = show.subsample(2,2)
        show = show.subsample(2,2)
        show = show.subsample(2,2)
        check_show_psw = tk.Button(frame2,image=show,borderwidth=0,command=show_psd, cursor="hand2")
        check_show_psw.image = show
        check_show_psw.grid(row=3,column=1,pady=5,padx=(5,0),sticky='ne')

        Label(frame2, text = "Security Question", font=( 'Segoe UI' ,16)).grid(row = 4, column = 0, sticky='w')

        working_list = ["What is your Favorite Security Question?", "What is your dog's name?", "What is the name of your father?", "What is the name of your mother?", "What is the name of your favorite car?", "What is your Favorite Security Question?", "What is your favorite computer game?", "What is the name of your favorite song?", "What is the name of your favorite movie?", "What is your favorite dessert?", "What is your favorite place?", "What is the name of your favorite food?", "What is your dream job?", "What is the name of your favorite player?", "What is your nickname?", "What is name of the first beach your visited?"]
        choice_var = StringVar()
        OptionMenu(frame2, choice_var, *working_list, command=print_choice).grid(row = 5,column=0,pady=(0,10),sticky='w')

        Label(frame2, text = "Answer", font=( 'Segoe UI' ,16)).grid(row = 6, column = 0, sticky='w')
        question_Entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
        question_Entry.grid(row = 7, column = 0, pady =(0,10),sticky='w')
        password_Entry.bind("<Return>", lambda e: question_Entry.focus_set())

        rise = tk.Button(frame2, text="Create", font=( 'Segoe UI' ,11), background="#1492e6",foreground="white", activebackground="#1492e6", activeforeground="white", width=12, command = addition)
        rise.grid(row = 8,column=0, pady=(0,10),sticky='e')
        question_Entry.bind("<Return>",addition)

        auth.protocol("WM_DELETE_WINDOW", on_closing)
        auth.mainloop()

    def login():
        global password_Entry, username_Entry, attempt, second
        login = Tk()
        login.title("Log in")
        login.resizable(False,False)
        w = 610
        h = 270
        login.geometry("{}x{}+{}+{}".format(w, h, int(login.winfo_screenwidth()/2 - w/2), int(login.winfo_screenheight()/2 - h/2)))
        login.iconbitmap('assets\\lock.ico')
        style = Style()
        attempt = 3
        second = 30
        def seconds():
            global second
            tries.config(text="Try Again After " + str(second) + " seconds")
            second -= 1
            if second > 0:
                login.after(1000,seconds)
            else:
                return
        def Forget(event=None):
            forget.unbind("<Button-1>")
            file_record("-Password Reset Initiated")

            def on_closing():
                forget.bind("<Button-1>", Forget)
                recover.destroy()
            def print_choice(event=None):
                return choice_var.get()
            def hide_psd():
                check_show.configure(image=sho,command=show_psd)
                check_show.image = sho
                new_password_Entry.config(show="•")
                
            def show_psd():
                hide = PhotoImage(file = "assets\\show.png")
                hide = hide.subsample(2,2)
                hide = hide.subsample(2,2)
                hide = hide.subsample(2,2)
                hide = hide.subsample(2,2)
                hide = hide.subsample(2,2)
                check_show.configure(image=hide, command=hide_psd)
                check_show.image = hide
                new_password_Entry.config(show="")
                new_password_Entry.focus()

            def update_security(event=None):
                sec_ques = print_choice()
                message = sec_ques.encode()
                hash_ques = encryptMessage(hashlib.blake2b(message).hexdigest())
                sec_ans = answer_Entry.get()
                message = sec_ans.encode()
                hash_ans = encryptMessage(hashlib.blake2b(message).hexdigest())
                new_pass = new_password_Entry.get()
                message = new_pass.encode()
                new_hash_password = encryptMessage(hashlib.blake2b(message).hexdigest())
                unsafeKey()
                decryptKey()
                decrypt_now()
                c.execute("SELECT * FROM schedule WHERE URL='42585f535e554305'")
                data = c.fetchone()
                encrypt_now()
                encryptKey()
                safeKey()
                if sec_ans == '' or new_pass == '':
                    messagebox.showwarning("Missing", "Please fill in all fields")
                elif hash_ques == data[3] and hash_ans == data[4]:
                    unsafeKey()
                    for file in os.listdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                        if file.endswith('.txt.aes'):
                            filename = r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'+file
                            buffersize = 64*1024
                            decryptKey()
                            decrypt_now()
                            c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                            data = c.fetchone()
                            encrypt_now()
                            encryptKey()
                            password = decryptMessage(data[0])
                            pyAesCrypt.decryptFile(filename, filename[:-4], password, buffersize)
                            os.remove(filename)
                    if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes'):
                        buffersize = 64*1024
                        decryptKey()
                        decrypt_now()
                        c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                        data = c.fetchone()
                        encrypt_now()
                        encryptKey()
                        password = decryptMessage(data[0])
                        pyAesCrypt.decryptFile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes', r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url', password, buffersize)
                        os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes')
                    decryptKey()
                    decrypt_now()
                    c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                    data1 = c.fetchone()
                    c.execute("SELECT URL, URN, LAN FROM schedule")
                    data = c.fetchall()[1:]
                    with open('tally.csv', 'w') as out_csv_file:
                        csv_out = csv.writer(out_csv_file)
                        csv_out.writerow([d[0] for d in c.description])
                        for result in data:
                            decrypted = []
                            decrypted.append(result[0])
                            decrypted.append(result[1])
                            decrypted.append(decrypt_str(result[2], decryptMessage(data1[0])))
                            result = tuple(decrypted)
                            csv_out.writerow(result)
                    c.execute("UPDATE schedule SET LAN=? WHERE URL='42585f535e554305'", (new_hash_password,))
                    conn.commit()
                    with open('tally.csv', 'r') as fin:
                        dr = csv.DictReader(fin)
                        to_db = [(i['URL'], i['URN'], i['LAN']) for i in dr]

                    for i in to_db:
                        c.execute('UPDATE schedule SET LAN=? WHERE URL=? AND URN=?', (encrypt_str(i[2], decryptMessage(new_hash_password)), i[0], i[1]))
                        conn.commit()
                    encrypt_now()
                    encryptKey()
                    os.remove('tally.csv')
                    for file in os.listdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                        if file.endswith('.txt'):
                            filename = r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'+file
                            buffersize = 64*1024
                            decryptKey()
                            decrypt_now()
                            c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                            data = c.fetchone()
                            encrypt_now()
                            encryptKey()
                            password = decryptMessage(data[0])
                            pyAesCrypt.encryptFile(filename, filename+'.aes', password, buffersize)
                            os.remove(filename)
                    if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url'):
                        buffersize = 64*1024
                        decryptKey()
                        decrypt_now()
                        c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                        data = c.fetchone()
                        encrypt_now()
                        encryptKey()
                        password = decryptMessage(data[0])
                        pyAesCrypt.encryptFile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url', r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes', password, buffersize)
                        os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url')
                    safeKey()
                    file_record("-Account Password Changed using security question")
                    messagebox.showinfo('Changed', 'Account Password Changed')
                    forget.bind("<Button-1>", Forget)
                    recover.destroy()
                else:
                    file_record("-Account Password Updation Tried using security question")
                    messagebox.showerror('Wrong Answer', 'Security Question not correct')
            recover = Toplevel()
            recover.title("Forgot Password")
            recover.geometry("305x470")
            recover.resizable(False,False)
            recover.iconbitmap('assets\\lock.ico')
            
            Label(recover, text = "Reset Password", font=( 'Segoe UI' ,16)).pack(side=TOP,pady=10,padx=10,anchor="center")

            reset = PhotoImage(file = "assets\\forget.png")
            reset = reset.subsample(2,2)
            Label(recover,image=reset).pack(side=TOP,pady=10,padx=10,anchor="center")

            Label(recover, text = "Security Question", font=( 'Segoe UI' ,16)).pack(side=TOP,pady=(10,0),padx=10,anchor='w')

            working_list = ["What is your Favorite Security Question?", "What is your dog's name?", "What is the name of your father?", "What is the name of your mother?", "What is the name of your favorite car?", "What is your Favorite Security Question?", "What is your favorite computer game?", "What is the name of your favorite song?", "What is the name of your favorite movie?", "What is your favorite dessert?", "What is your favorite place?", "What is the name of your favorite food?", "What is your dream job?", "What is the name of your favorite player?", "What is your nickname?", "What is name of the first beach your visited?"]
            choice_var = StringVar()
            OptionMenu(recover, choice_var, *working_list, command=print_choice).pack(side=TOP,pady=(0,10),padx=10,anchor='w')

            Label(recover, text = "Answer", font=( 'Segoe UI' ,16)).pack(side=TOP,padx=10,anchor="w")

            answer_Entry = Entry(recover, width = 26, font=("Segoe UI", 14))
            answer_Entry.pack(side=TOP,pady = (0,10), padx = (10,0),anchor='w')
            answer_Entry.focus()

            Label(recover, text = "New Password", font=( 'Segoe UI' ,16)).pack(side=TOP,padx=10,anchor="w")

            frame_pass = Frame(recover)
            frame_pass.pack(side=TOP, fill='x',expand=True)

            new_password_Entry = Entry(frame_pass, width = 26, font=("Segoe UI", 14),show="•")
            new_password_Entry.pack(side=LEFT, padx = (10,0),anchor='w')
            answer_Entry.bind("<Return>", lambda e: new_password_Entry.focus_set())

            sho = PhotoImage(file = "assets\\hide.png")
            sho = sho.subsample(2,2)
            sho = sho.subsample(2,2)
            sho = sho.subsample(2,2)
            sho = sho.subsample(2,2)
            sho = sho.subsample(2,2)
            check_var = IntVar()
            check_show = tk.Button(frame_pass, image=sho,borderwidth=0,cursor="hand2",command=show_psd)
            check_show.image = sho
            check_show.pack(side=RIGHT,pady=5,padx=5,anchor='e')

            tk.Button(recover, text="Reset Password", font=( 'Segoe UI' ,11), background="#1492e6",foreground="white", activebackground="#1492e6", activeforeground="white", width=16,command=update_security).pack(side=TOP,pady=10,padx=10,anchor='center')
            new_password_Entry.bind("<Return>",update_security)

            recover.protocol("WM_DELETE_WINDOW", on_closing)
            recover.mainloop()
        
        def enable():
            login.overrideredirect(False)
            forget.bind("<Button-1>", Forget)
            forget.configure(foreground="blue")
            rise.configure(state=NORMAL)
            username_Entry.configure(state=NORMAL)
            password_Entry.configure(state=NORMAL)
            check_show.configure(state=NORMAL)
            tries.config(text="3 Tries Left")
            login.protocol("WM_DELETE_WINDOW", on_closing)

        def prev_closing():
            pass

        def pause():
            tries.config(text="Try Again After 30 seconds")
            forget.unbind("<Button-1>")
            forget.configure(foreground="grey")
            login.overrideredirect(True)
            rise.configure(state=DISABLED)
            username_Entry.configure(state=DISABLED)
            password_Entry.configure(state=DISABLED)
            check_show.configure(state=DISABLED)
            login.protocol("WM_DELETE_WINDOW", prev_closing)
            seconds()
            login.after(30000,enable)

        def hide_psd():
                check_show.configure(image=show,command=show_psd)
                password_Entry.config(show="•")
                
        def show_psd():
            hides = PhotoImage(file = "assets\\show.png")
            hide = hides.subsample(2,2)
            hide = hide.subsample(2,2)
            hide = hide.subsample(2,2)
            hide = hide.subsample(2,2)
            hide = hide.subsample(2,2)
            check_show.configure(image=hide, command=hide_psd)
            check_show.image = hide
            password_Entry.config(show="")
            password_Entry.focus()

        def on_closing():
            c.close()
            conn.close()
            encryptFile()
            login.destroy()
            sys.exit()

        def check(event=None):
            global attempt, tries, CONSTANT
            unsafeKey()
            decryptKey()
            decrypt_now()
            c.execute("SELECT * FROM schedule WHERE URL='42585f535e554305'")
            data = c.fetchone()
            encrypt_now()
            encryptKey()
            safeKey()
            check_user = username_Entry.get()
            message = check_user.encode()
            hash_check_user = encryptMessage(hashlib.blake2b(message).hexdigest())
            check_pass = password_Entry.get()
            message1 = check_pass.encode()
            hash_check_pass = encryptMessage(hashlib.blake2b(message1).hexdigest())
            if check_user == '' or check_pass == '':
                messagebox.showwarning("Empty", "Please enter your username AND password")
            elif hash_check_user == data[1] and hash_check_pass == data[2]:
                file_record("-Logged In")
                unsafeKey()
                login.destroy()
            else:
                file_record("-Login Attempt")
                attempt -= 1
                tries = Label(frame2, text=str(attempt)+" tries left",foreground="red")
                tries.grid(row=5,column=0,padx=10,sticky='nw')
                if attempt == 0:
                    webcam()
                    pause()
                    attempt = 3
                messagebox.showerror("Wrong credentials", "Unable to Log You In")
                
        frame1 = Frame(login)
        frame1.pack(side=LEFT, fill=BOTH, expand=True)
        add = PhotoImage(file = "assets\\login.png")
        add = add.subsample(2,2)
        Label(frame1,image=add).pack(side=BOTTOM, fill=BOTH, padx=5,pady=5,expand=True)

        frame2 = Frame(login)
        frame2.pack(side=LEFT, fill=None, expand=True)

        Label(frame2, text = "Welcome Back!", font=( 'Segoe UI' ,16),foreground="#1492e6").grid(row = 0, column = 0,padx=10,sticky='n')

        Label(frame2, text = "Username", font=( 'Segoe UI' ,16)).grid(row = 1, column = 0, padx=10,sticky='w')

        username_Entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
        username_Entry.grid(row = 2, column = 0, pady = (0,10), padx = (10,0), sticky='we')

        Label(frame2, text = "Password", font=( 'Segoe UI' ,16)).grid(row = 3, column = 0,padx=10,sticky='w')

        password_Entry = Entry(frame2, width = 30, font=("Segoe UI", 14), show="•")
        password_Entry.grid(row = 4, column = 0, pady=(0,5),padx = (10,0),sticky='we')
        username_Entry.focus()
        username_Entry.bind("<Return>", lambda e: password_Entry.focus_set())

        shows = PhotoImage(file = "assets\\hide.png")
        show = shows.subsample(2,2)
        show = show.subsample(2,2)
        show = show.subsample(2,2)
        show = show.subsample(2,2)
        show = show.subsample(2,2)
        check_show = tk.Button(frame2 ,image=show,borderwidth=0,cursor="hand2",command=show_psd)
        check_show.image = show
        check_show.grid(row=4,column=1,pady=5,padx=5,sticky='w')


        rise = tk.Button(frame2, text="Login", font=( 'Segoe UI' ,11), background="#1492e6",foreground="white", activebackground="#1492e6", activeforeground="white", command = check)
        rise.grid(row = 6,column=0, pady=(5,10),padx=(10,0),sticky='we')
        password_Entry.bind("<Return>",check)

        forget = Label(frame2, text="Forgot Password?",foreground="blue",font=('Segeo UI', 9, 'underline'), cursor="hand2")
        forget.bind("<Button-1>", Forget)
        forget.grid(row=5,column=0,pady=(0,10),sticky='se')

        login.protocol("WM_DELETE_WINDOW", on_closing)
        totalRows = 4
        totalCols = 0

        for row in range(totalRows+1):
            login.grid_rowconfigure(row, weight=1)
        for col in range(totalCols+1):
            login.grid_columnconfigure(col, weight=1)
        
        login.mainloop()

    def account_pass():
        try:
            unsafeKey()
            decryptKey()
            decrypt_now()
            c.execute("SELECT * FROM schedule WHERE URL='42585f535e554305'")
            data = c.fetchone()
            encrypt_now()
            encryptKey()
            safeKey()
            if data[0] == '42585f535e554305':
                login()
        except TypeError:
            signin()
                
    def Restricted(event=None):
        style = Style()
        for widget in frame2.winfo_children():
            widget.destroy()

        backend = PhotoImage(file = "assets\\back.png")
        bak = backend.subsample(2,2)
        bak = bak.subsample(2,2)
        bak = bak.subsample(2,2)
        bak = bak.subsample(2,2)
        bak = bak.subsample(2,2)
        def username():
            for widget in frame2.winfo_children():
                widget.destroy()

            def Clear(event=None):
                new_username_Entry.delete(0,END)
                new_username_Entry.focus()
                
            def update(event=None):
                new_username = new_username_Entry.get()
                message = new_username.encode()
                hash_new_username = encryptMessage(hashlib.blake2b(message).hexdigest())
                if new_username == '':
                    messagebox.showerror('Empty', 'New Username not entered')
                    new_username_Entry.focus()
                else:
                    try:
                        decryptKey()
                        decrypt_now()
                        c.execute("UPDATE schedule SET URN=? WHERE URL='42585f535e554305'", (hash_new_username,))
                        conn.commit()
                        encrypt_now()
                        encryptKey()
                        file_record("-Account Username Updated")
                        messagebox.showinfo('Updated', 'Account Username Updated')
                    except sqlite3.DatabaseError:
                        pass
                new_username_Entry.focus()
                
            bak_btn = tk.Button(frame2, image = bak, width = 10, command = Restricted, borderwidth=0, cursor="hand2")
            bak_btn.image = bak
            bak_btn.grid(row =0,column=0,sticky='w')

            Label(frame2, text = "Enter New Username", font=( 'Segoe UI' ,16)).grid(row = 1, column = 0, pady=(10,0), padx=10, sticky='w')

            new_username_Entry = Entry(frame2, width = 30, font=("Times", 15))
            new_username_Entry.grid(row = 2, column = 0, pady = (0,10), padx = 10, sticky='w')
            new_username_Entry.focus()

            Button(frame2, text="Update", width = 10, command = update).grid(row=3,column=0, pady=10,padx=10, sticky='e')
            new_username_Entry.bind("<Return>",update)
            new_username_Entry.bind("<Escape>",Restricted)

            Button(frame2, text="Clear", width = 5, command = Clear).grid(row=3,column=0,pady=10,padx=10, sticky='w')
            new_username_Entry.bind("<Delete>",Clear)
            
        def password():
            for widget in frame2.winfo_children():
                widget.destroy()

            def Clear(event=None):
                old_password_Entry.delete(0,END)
                new_password_Entry.delete(0,END)
                old_password_Entry.focus()

            def hide_psd():
                check_show.configure(image=sho,command=show_psd)
                check_show.image = sho
                new_password_Entry.config(show="•")
                
            def show_psd():
                hides = PhotoImage(file = "assets\\show.png")
                hide = hides.subsample(2,2)
                hide = hide.subsample(2,2)
                hide = hide.subsample(2,2)
                hide = hide.subsample(2,2)
                hide = hide.subsample(2,2)
                check_show.configure(image=hide, command=hide_psd)
                check_show.image = hide
                new_password_Entry.config(show="")
                new_password_Entry.focus()
            
            def update(event=None):
                old_password = old_password_Entry.get()
                message = old_password.encode()
                hash_old_password = encryptMessage(hashlib.blake2b(message).hexdigest())
                new_password = new_password_Entry.get()
                message = new_password.encode()
                hash_new_password = encryptMessage(hashlib.blake2b(message).hexdigest())
                if old_password == '' or new_password == '':
                    messagebox.showwarning('Missing', 'Please fill in all Fields')
                    old_password_Entry.focus()
                else:
                    try:
                        decryptKey()
                        decrypt_now()
                        c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                        data = c.fetchone()
                        encrypt_now()
                        encryptKey()
                        if hash_new_password == data[0]:
                            messagebox.showwarning('Match', 'Old Password cannot be the new Password')
                        elif hash_old_password == data[0]:
                            for file in os.listdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                                if file.endswith('.txt.aes'):
                                    filename = r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'+file
                                    buffersize = 64*1024
                                    decryptKey()
                                    decrypt_now()
                                    c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                                    data = c.fetchone()
                                    encrypt_now()
                                    encryptKey()
                                    password = decryptMessage(data[0])
                                    pyAesCrypt.decryptFile(filename, filename[:-4], password, buffersize)
                                    os.remove(filename)
                            if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes'):
                                    buffersize = 64*1024
                                    decryptKey()
                                    decrypt_now()
                                    c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                                    data = c.fetchone()
                                    encrypt_now()
                                    encryptKey()
                                    password = decryptMessage(data[0])
                                    pyAesCrypt.decryptFile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes', r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url', password, buffersize)
                                    os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes')
                            decryptKey()
                            decrypt_now()
                            c.execute("SELECT URL, URN, LAN FROM schedule")
                            data = c.fetchall()[1:]
                            with open('tally.csv', 'w') as out_csv_file:
                                csv_out = csv.writer(out_csv_file)
                                csv_out.writerow([d[0] for d in c.description])
                                for result in data:
                                    decrypted = []
                                    decrypted.append(result[0])
                                    decrypted.append(result[1])
                                    decrypted.append(decrypt_str(result[2], decryptMessage(hash_old_password)))
                                    result = tuple(decrypted)
                                    csv_out.writerow(result)
                            c.execute("UPDATE schedule SET LAN=? WHERE URL='42585f535e554305'", (hash_new_password,))
                            conn.commit()
                            with open('tally.csv', 'r') as fin:
                                dr = csv.DictReader(fin)
                                to_db = [(i['URL'], i['URN'], i['LAN']) for i in dr]

                            for i in to_db:
                                c.execute('UPDATE schedule SET LAN=? WHERE URL=? AND URN=?', (encrypt_str(i[2], decryptMessage(hash_new_password)), i[0], i[1]))
                                conn.commit()
                            encrypt_now()
                            encryptKey()
                            os.remove('tally.csv')
                            for file in os.listdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                                if file.endswith('.txt'):
                                    filename = r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'+file
                                    buffersize = 64*1024
                                    decryptKey()
                                    decrypt_now()
                                    c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                                    data = c.fetchone()
                                    encrypt_now()
                                    encryptKey()
                                    password = decryptMessage(data[0])
                                    pyAesCrypt.encryptFile(filename, filename+'.aes', password, buffersize)
                                    os.remove(filename)
                            if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url'):
                                    buffersize = 64*1024
                                    decryptKey()
                                    decrypt_now()
                                    c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                                    data = c.fetchone()
                                    encrypt_now()
                                    encryptKey()
                                    password = decryptMessage(data[0])
                                    pyAesCrypt.encryptFile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url', r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes', password, buffersize)
                                    os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url')
                            file_record("-Account Password Updated")
                            messagebox.showinfo('Updated', 'Account Password Updated')
                            old_password_Entry.delete(0, END)
                            new_password_Entry.delete(0, END)
                        else:
                            file_record("-Account Password Updation Tried")
                            messagebox.showerror('Wrong Password', 'Old Password does not match')
                    except sqlite3.DatabaseError:
                        pass

            bak_btn = tk.Button(frame2, image = bak, width = 10, command = Restricted, borderwidth=0, cursor="hand2")
            bak_btn.image = bak
            bak_btn.grid(row =0,column=0,sticky='w')
                    
            Label(frame2, text = "Enter Old Password", font=( 'Segoe UI', 14)).grid(row = 1, column = 0, pady=(10,0), padx=10, sticky='w')

            old_password_Entry = Entry(frame2, width = 30, font=("Segoe UI", 14), show="•")
            old_password_Entry.grid(row = 2, column = 0, pady = (0,10), padx = 10, sticky='w')

            Label(frame2, text = "Enter New Password", font=( 'Segoe UI', 14)).grid(row = 3, column = 0, pady=(10,0), padx=10, sticky='w')

            new_password_Entry = Entry(frame2, width = 30, font=("Segoe UI", 14), show="•")
            new_password_Entry.grid(row = 4, column = 0, pady = (0,10), padx = 10, sticky='w')
            old_password_Entry.focus()
            old_password_Entry.bind("<Return>", lambda e: new_password_Entry.focus_set())

            sho = PhotoImage(file = "assets\\hide.png")
            sho = sho.subsample(2,2)
            sho = sho.subsample(2,2)
            sho = sho.subsample(2,2)
            sho = sho.subsample(2,2)
            sho = sho.subsample(2,2)
            check_show = tk.Button(frame2, image=sho,borderwidth=0,cursor="hand2",command=show_psd)
            check_show.image = sho
            check_show.grid(row=4,column=1,pady=10)

            Button(frame2, text="Update", command = update).grid(row = 5,column=0,pady=10,padx=10,sticky='e')
            new_password_Entry.bind("<Return>",update)
            old_password_Entry.bind("<Escape>",Restricted)
            new_password_Entry.bind("<Escape>",Restricted)

            Button(frame2, text="Clear",width = 5, command = Clear).grid(row = 5,column=0,pady=10,padx=10, sticky='w')
            old_password_Entry.bind("<Delete>",Clear)
            new_password_Entry.bind("<Delete>",Clear)
        def security_question():
            for widget in frame2.winfo_children():
                widget.destroy()

            def Clear(event=None):
                answer_Entry.delete(0,END)
                answer_Entry.focus()

            def print_choice(event=None):
                return choice_var.get()

            def update(event=None):
                new_ques = print_choice()
                message = new_ques.encode()
                new_hash_ques = encryptMessage(hashlib.blake2b(message).hexdigest())
                new_ans = answer_Entry.get()
                message = new_ans.encode()
                new_hash_ans = encryptMessage(hashlib.blake2b(message).hexdigest())
                if new_ans == '':
                    messagebox.showwarning('Missing', 'Please enter the answer')
                    answer_Entry.focus()
                else:
                    try:
                        decryptKey()
                        decrypt_now()
                        c.execute("UPDATE schedule SET date=?, time=? WHERE URL='42585f535e554305'", (new_hash_ques, new_hash_ans))
                        conn.commit()
                        encrypt_now()
                        encryptKey()
                        file_record("-Account Security Question Updated")
                        messagebox.showinfo('Updated', 'Account Security Question Updated')
                    except sqlite3.DatabaseError:
                        pass

            bak_btn = tk.Button(frame2, image = bak, width = 10, command = Restricted, borderwidth=0, cursor="hand2")
            bak_btn.image = bak
            bak_btn.grid(row =0,column=0,sticky='w')
            
            Label(frame2, text = "Select New Security Question", font=( 'Segoe UI' ,16)).grid(row=1,column=0,pady=(10,0),padx=10,sticky='w')

            working_list = ["What is your Favorite Security Question?", "What is your dog's name?", "What is the name of your father?", "What is the name of your mother?", "What is the name of your favorite car?", "What is your Favorite Security Question?", "What is your favorite computer game?", "What is the name of your favorite song?", "What is the name of your favorite movie?", "What is your favorite dessert?", "What is your favorite place?", "What is the name of your favorite food?", "What is your dream job?", "What is the name of your favorite player?", "What is your nickname?", "What is name of the first beach your visited?"]
            choice_var = StringVar()
            OptionMenu(frame2, choice_var, *working_list, command=print_choice).grid(row=2,column=0,pady=(0,10),padx=10,sticky='w')

            Label(frame2, text = "Answer", font=( 'Segoe UI' ,16)).grid(row=3,column=0,pady=(10,0),padx=10,sticky='w')

            answer_Entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
            answer_Entry.grid(row=4,column=0,pady=(0,10),padx=10,sticky='w')
            answer_Entry.focus()

            Button(frame2, text="Update", command = update).grid(row = 5,column=0,pady=10,padx=10,sticky='e')
            answer_Entry.bind("<Return>",update)
            answer_Entry.bind("<Escape>",Restricted)

            Button(frame2, text="Clear",width = 5, command = Clear).grid(row = 5,column=0,pady=10,padx=10,sticky='w')
            answer_Entry.bind("<Delete>",Clear)
            
        Label(frame2, text = "Update Account Details", font=( 'Times' ,25)).grid(row = 0, column=0, columnspan = 3, padx=10, pady=10)

        Label(frame2, text = "Choose what you want to update", font=( 'Segoe UI' ,16)).grid(row = 1, column = 0, columnspan = 3, pady=10, padx=10)

        style.configure('W.TButton', font=('Segoe UI' , 14),width=16, borderwidth='5')
        style.map('W.TButton', foreground = [('active', '!disabled', '#1492e6')], background = [('active', '#1492e6')])
        username_btn = Button(frame2, text="Update Username", style = "W.TButton", command = username)
        username_btn.grid(row=2,column=0, pady=10, padx=10)

        Button(frame2, text="Update Password", style = "W.TButton", command = password).grid(row=2,column=1, pady=10, padx=10)

        Button(frame2, text="Update Question", style = "W.TButton", command = security_question).grid(row=2,column=3, pady=10, padx=10)

    def myfunction(event):
        canvas.configure(scrollregion=canvas.bbox("all"))

    def vault():
        dis = 0
        for widget in frame2.winfo_children():
            dis += 1
        import glob
        user = getpass.getuser()

        if (os.path.isdir('C:\\Users\\' + user + '\\manage\\Logs\\')) == True:
            if len(os.listdir('C:\\Users\\' + user + '\\manage\\Logs\\')) == 0:
                messagebox.showerror('Breach', "Someone has tampered with the Security Logs")
            else:
                if testDevice() == True:
                    def open_img():
                            list_of_files = glob.iglob('C:\\Users\\' + user + '\\manage\\Logs\\*.png')
                            latest_file = max(list_of_files, key=os.path.getctime)
                            img = Image.open(latest_file)
                            img = img.resize((900,700), Image.ANTIALIAS)
                            img = ImageTk.PhotoImage(img)
                            panel = Label(cam, image = img)
                            panel.image = img
                            panel.grid(row = 2)


                    cam = Toplevel()
                    cam.title("Security")
                    cam.geometry("900x700+300+50")
                    cam.resizable(False, False)
                    cam.iconbitmap('assets\\lock.ico')
                    open_img()
                    cam.mainloop()
                else:
                    def open_img():
                            list_of_files = glob.iglob('C:\\Users\\' + user + '\\manage\\Logs\\*jpg')
                            latest_file = max(list_of_files, key=os.path.getctime)
                            img = Image.open(latest_file)
                            img = img.resize((900,700), Image.ANTIALIAS)
                            img = ImageTk.PhotoImage(img)
                            panel = Label(ss, image = img)
                            panel.image = img
                            panel.grid(row = 2)


                    ss = Toplevel()
                    ss.title("Security")
                    ss.geometry("900x700+300+50")
                    ss.resizable(False, False)
                    ss.iconbitmap('assets\\lock.ico')
                    open_img()
                    ss.mainloop()
        else:
            messagebox.showinfo("Secure", "No one Recently tried to access the Vault")
        file_record("-Security Log Accessed")
        if dis == 0:
                Label(frame2, text="Vault", font=("Times",200,"bold"), foreground="deep sky blue").grid(row=0,column=0)

    def verify(event=None):
        for widget in frame2.winfo_children():
            widget.destroy()
        style = Style()

        def passwd(event=None):
            try:
                for widget in frame2.winfo_children()[5:]:
                    widget.destroy()
                p = check_password_entry.get()
                x = True
                vul = ''
                t = 2
                while x:
                    if(len(p)<6):
                            vul = 'Length is too small'
                            t -= 1
                            break
                    elif not re.search("[a-z]",p):
                            vul = 'No lowercase English character found'
                            t -= 1
                            break
                    elif not re.search("[A-Z]",p):
                            vul = 'No uppercase English character found'
                            t -= 1
                            break
                    elif not re.search("[0-9]",p):
                            vul = 'No digit present'
                            t -= 1
                            break
                    elif not re.search("[!@#$%^&*:~`+-.?=<>;|/()]",p):
                            vul = 'No special characters present'
                            t -= 1
                            break
                    else:
                            t += 1
                            vul = 'No Vulnerabilities'
                            good = PhotoImage(file = "assets\\good.png")
                            good = good.subsample(2,2)
                            good = good.subsample(2,2)
                            str_lab = Label(frame2, text = "Strong Password: " + vul, font=( 'Segoe UI',8), image=good, compound=TOP)
                            str_lab.image = good
                            str_lab.grid(row=4,column=0,pady=10,padx=10)
                            x=False
                            break
                if x:
                    bad = PhotoImage(file = "assets\\bad.png")
                    bad = bad.subsample(2,2)
                    bad = bad.subsample(2,2)
                    str_lab = Label(frame2, text = "Weak Password: " + vul, font=( 'Segoe UI',8), image=bad, compound=TOP)
                    str_lab.image = bad
                    str_lab.grid(row=4,column=0,padx=10,pady=10)

                file_record("-Password Strength Checked")
            except:
                messagebox.showerror("Invalid", "Please input valid Password")
                verify()
        Label(frame2, text = "Password Strength Checker", font=( 'Times' ,25)).grid(row = 0, column=0, padx=10, pady=10, sticky='w')

        Label(frame2, text = "Enter the password", font=( 'Segoe UI' ,16)).grid(row = 1, column = 0, pady=(10,0), padx=10, sticky='w')

        check_password_entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
        check_password_entry.grid(row = 2, column = 0, pady=(0,10), padx=10, sticky='we')
        check_password_entry.focus()

        style.configure('W.TButton', font=('Segoe UI' , 11),width=15, borderwidth=5, padx=16,pady=8)
        style.map('W.TButton', foreground = [('active', '!disabled', '#1492e6')], background = [('active', '#1492e6')])
        Button(frame2, text="Check Strength", style = "W.TButton", command = passwd).grid(row = 3,column= 0,padx=10, sticky='e')
        check_password_entry.bind("<Return>",passwd)

        Button(frame2, text="Clear", width = 5, command = verify).grid(row = 3,column=0,padx=10, sticky='w')
        check_password_entry.bind("<Delete>",verify)

    def Export():
        for widget in frame2.winfo_children():
            widget.destroy()

        def print_choice(event=None):
            return choice_var.get()

        def verify_auth(event=None):
            try:
                new_ques = print_choice()
                message = new_ques.encode()
                new_hash_ques = encryptMessage(hashlib.blake2b(message).hexdigest())
                new_ans = answer_Entry.get()
                message = new_ans.encode()
                new_hash_ans = encryptMessage(hashlib.blake2b(message).hexdigest())
                passwd = verify_Entry.get()
                message = passwd.encode()
                hash_verify_password = encryptMessage(hashlib.blake2b(message).hexdigest())
                decryptKey()
                decrypt_now()
                c.execute("SELECT * FROM schedule WHERE URL='42585f535e554305'")
                data = c.fetchone()
                encrypt_now()
                encryptKey()
                if new_ans == '' or passwd == '':
                    messagebox.showwarning("Empty", "Please fill in all fields")
                elif hash_verify_password == data[2] and new_hash_ques == data[3] and new_hash_ans == data[4]:
                    for widget in frame2.winfo_children():
                        widget.destroy()
                    access()
                else:
                    Label(frame2, text="Authentication Error",foreground="red").grid(row=6,column=0,pady=10,padx=10,sticky='w')
                    verify_Entry.focus()
            except sqlite3.DatabaseError:
                pass

        Label(frame2, text = "Security Question", font=( 'Segoe UI' ,16)).grid(row = 0, column = 0, padx=10, pady=(10,0), sticky='w')

        working_list = ["What is your Favorite Security Question?", "What is your dog's name?", "What is the name of your father?", "What is the name of your mother?", "What is the name of your favorite car?", "What is your Favorite Security Question?", "What is your favorite computer game?", "What is the name of your favorite song?", "What is the name of your favorite movie?", "What is your favorite dessert?", "What is your favorite place?", "What is the name of your favorite food?", "What is your dream job?", "What is the name of your favorite player?", "What is your nickname?", "What is name of the first beach your visited?"]
        choice_var = StringVar()
        OptionMenu(frame2, choice_var, *working_list, command=print_choice).grid(row = 1, column = 0, padx=10, pady=(0,10), sticky='w')

        Label(frame2, text = "Answer", font=( 'Segoe UI' ,16)).grid(row = 2, column = 0, padx=10, pady=(10,0), sticky='w')

        answer_Entry = Entry(frame2, width = 26, font=("Segoe UI", 14))
        answer_Entry.grid(row = 3, column = 0, padx=10, pady=(0,10), sticky='w')
        answer_Entry.focus()
        
        Label(frame2, text = "Password", font=( 'Segoe UI' ,16)).grid(row = 4, column = 0, padx=10, pady=(10,0), sticky='w')

        verify_Entry = Entry(frame2, width = 26, font=("Segoe UI", 14), show="•")
        verify_Entry.grid(row = 5, column = 0, pady = (0,10), padx = 10)
        answer_Entry.bind("<Return>", lambda e: verify_Entry.focus_set())

        Button(frame2, text="Verify", command = verify_auth).grid(row = 6,column=0,pady=10,padx=10,sticky='ne')
        verify_Entry.bind("<Return>",verify_auth)
        def access():
            from tkinter.filedialog import asksaveasfile
            for widget in frame2.winfo_children():
                widget.destroy()

            def save():
                if filename_entry.get() != '':
                    filename_entry.delete(0,END)
                file = asksaveasfile(filetypes=[('Vault Export', '*.csv')], defaultextension='.csv')
                if file is not None:
                    filename_entry.config(state="normal")
                    filename_entry.insert(0, file.name)
                    filename_entry.config(state="disabled")
                    file.close()
                    os.remove(file.name)
            def export_db():
                filename = filename_entry.get()
                key = key_entry.get()
                message = key.encode()
                hash_key = encryptMessage(hashlib.blake2b(message).hexdigest())
                if filename == '' or key == '':
                    messagebox.showwarning("Missing", "Please fill in the required fields")
                else:
                    try:
                        user = getpass.getuser()
                        zip_file = []
                        decryptKey()
                        decrypt_now()
                        c.execute("SELECT * FROM schedule")
                        with open(filename, 'w') as out_csv_file:
                            csv_out = csv.writer(out_csv_file)
                            csv_out.writerow([d[0] for d in c.description])
                            for result in c:
                                csv_out.writerow(result)
                        c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                        data = c.fetchone()
                        encrypt_now()
                        encryptKey()
                        pyAesCrypt.encryptFile(filename, filename+".aes", hash_key, 64*1024)
                        os.remove(filename)
                        pyAesCrypt.encryptFile(filename+".aes", filename+".aes.aes", data[0], 64*1024)
                        os.remove(filename+".aes")
                        zip_file.append(filename+".aes.aes")
                        for file in os.listdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                            if file.endswith('.txt.aes'):
                                zip_file.append(r'C:/Users/' + user + '/AppData/Local/Vault/notes/'+file)
                        zipObj = ZipFile(filename.rsplit('/', 1)[1][:-4]+'.zip', 'w')
                        if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes'):
                            shutil.copy(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes', os.getcwd())
                            zipObj.write('url.aes')
                        for i in zip_file:
                            shutil.copy(i, os.getcwd())
                            zipObj.write(i.rsplit('/', 1)[1])
                            os.remove(i.rsplit('/',1)[1])
                        if os.path.isfile(filename+".aes.aes"):
                            os.remove(filename+".aes.aes")
                        zipObj.close()
                        pyAesCrypt.encryptFile(filename.rsplit('/', 1)[1][:-4]+'.zip', filename.rsplit('/', 1)[1][:-4]+'.zip.aes', hash_key, 64*1024)
                        os.remove(filename.rsplit('/', 1)[1][:-4]+'.zip')
                        shutil.move(filename.rsplit('/', 1)[1][:-4]+'.zip.aes', filename.rsplit('/', 1)[0])
                        file_record("-Passwords Exported")
                        messagebox.showinfo("Export Complete", "Passwords Exported")
                    except OSError:
                        messagebox.showerror('Corrupt Extension', "File Extension not correct")
                    except FileNotFoundError:
                        messagebox.showerror('File Missing', "File specified not found")
            Label(frame2, text = "Export Passwords", font=( 'Times' ,25, 'underline' )).grid(row = 0, column=0, columnspan=2, padx=10, pady=10, sticky='w')

            Label(frame2, text = "Select export location", font=( 'Segoe UI' ,16)).grid(row = 1, column = 0, pady=(10,0), padx=10, sticky='w')

            filename_entry = Entry(frame2, width = 30, font=("Segoe UI", 14), state='disabled')
            filename_entry.grid(row = 2, column = 0, pady=(0,10), padx=10, sticky='w')

            
            savet = PhotoImage(file = "assets\\save.png")
            savet = savet.subsample(2,2)
            savet = savet.subsample(2,2)
            savet = savet.subsample(2,2)
            savet = savet.subsample(2,2)
            savet = savet.subsample(2,2)
            save_btn = tk.Button(frame2, image=savet, borderwidth=0, cursor = 'hand2', command = save)
            save_btn.image = savet
            save_btn.grid(row=2,column=1,pady=(0,10),sticky='w')

            Label(frame2, text = "Enter an encryption key", font=( 'Segoe UI' ,16)).grid(row = 3, column = 0, pady=(10,0), padx=10, sticky='w')

            key_entry = Entry(frame2, width = 30, font=("Segoe UI", 14))
            key_entry.grid(row = 4, column = 0, pady=(0,10), padx=10, sticky='w')
            key_entry.focus()

            style.configure('W.TButton', font=('Segoe UI' , 11),width=10, borderwidth=5, padx=16,pady=8)
            style.map('W.TButton', foreground = [('active', '!disabled', '#1492e6')], background = [('active', '#1492e6')])
            Button(frame2, text="Export", style = "W.TButton", command=export_db).grid(row =5,column=0,pady=10,padx=10, sticky='e')

    def store():
        global store_text
        def handle_focus_in(event=None):
            if store_text.cget('foreground') == 'grey':
                store_text.delete("1.0", END)
                store_text.configure(foreground="black")

        def handle_focus_out(event=None):
            if store_text.get("1.0", "end-1c") == '':
                store_text.insert(INSERT, "Temporary Space.Data would not be saved")
                store_text.configure(foreground="grey")

        store_text = Text(frame4, height=3, foreground="grey")
        store_text.pack(side=LEFT, fill = 'x', expand=True)
        store_text.insert(INSERT, "Temporary Space.Data would not be saved")
        store_text.bind("<FocusIn>", handle_focus_in)
        store_text.bind("<FocusOut>", handle_focus_out)

    def filter_out(event=None):
        try:
            if filter_entry.get() == '':
                messagebox.showerror('Empty', 'Filter Condition Empty')
            else:
                def onClick(labelNum):
                    Search_Focus(labelNum)
                def onCliuse(labelNum):
                    Search_user(decryptMessage(labelNum[0]))
                def onClear(labelNum):
                    pyperclip.copy(decryptMessage(labelNum[0]))
                    talkback("Website Copied")
                def onCleuse(labelNum):
                    pyperclip.copy(decryptMessage(labelNum[0]))
                    talkback("Username Copied")
                for widget in frame.winfo_children():
                    widget.destroy()
                sort = filter_entry.get()
                row = 0
                decryptKey()
                decrypt_now()
                c.execute('SELECT URL, URN, image FROM schedule')
                data = c.fetchall()[1:]
                encrypt_now()
                encryptKey()
                for i in data:
                    if decryptMessage(i[0])[0] == '~' and decryptMessage(i[1])[0] == '~':
                        continue
                    if decryptMessage(i[0])[:len(sort)].lower() == sort.lower():
                        row += 1
                        try:
                            dis_img = PhotoImage(file = decryptMessage(i[2]))
                            dis_img = dis_img.subsample(2,2)
                            dis_img = dis_img.subsample(2,2)
                            dis_img = dis_img.subsample(2,2)
                            dis_img = dis_img.subsample(2,2)
                            dis_label = Label(frame, image=dis_img)
                            dis_label.image = dis_img
                            dis_label.grid(row=row,column=0,pady=10,padx=10)
                        except:
                            dis_img = PhotoImage(file = 'assets\\world.png')
                            dis_img = dis_img.subsample(2,2)
                            dis_img = dis_img.subsample(2,2)
                            dis_img = dis_img.subsample(2,2)
                            dis_img = dis_img.subsample(2,2)
                            dis_label = Label(frame, image=dis_img)
                            dis_label.image = dis_img
                            dis_label.grid(row=row,column=0,pady=10,padx=10)
                        if len(decryptMessage(i[0])) > 18:
                            list_label = Label(frame, text = decryptMessage(i[0])[:18]+"..", font=( 'Segoe UI' ,16), cursor="hand2")
                        else:
                            list_label = Label(frame, text = decryptMessage(i[0]), font=( 'Segoe UI' ,16), cursor="hand2")
                        list_label.grid(row=row,column=1,sticky='nw',padx=10)
                        list_label2 = Label(frame, text = decryptMessage(i[1]), font=( 'Segoe UI' ,12), cursor="hand2")
                        list_label2.grid(row=row,column=1,sticky='sw',padx=10)
                        list_label.bind("<Button-1>", lambda e, labelNum=i: onClick(labelNum))
                        list_label2.bind("<Button-1>", lambda e, labelNum=i: onClick(labelNum))
                        list_label.bind("<Enter>", lambda e, : e.widget.config(foreground="red", font=('Comic Sans MS', 16)))
                        list_label.bind("<Leave>", lambda e, : e.widget.config(foreground="black", font=( 'Segoe UI' ,16)))
                        list_label2.bind("<Enter>", lambda e, : e.widget.config(foreground="green"))
                        list_label2.bind("<Leave>", lambda e, : e.widget.config(foreground="black"))
                        list_label.bind("<Button-3>", lambda e, labelNum=i[0]: onClear(labelNum))
                        list_label2.bind("<Button-3>", lambda e, labelNum=i[1]: onCleuse(labelNum))
                if row < 1:
                    list_label = Label(frame, text = "No websites starting with "+sort, font=( 'Times' ,16, 'bold' ))
                    list_label.grid(row=1,columnspan=2,padx=10,pady=10)
        except sqlite3.DatabaseError:
            pass

    def face_link():
        webbrowser.open('https://www.facebook.com/')

    def insta_link():
        webbrowser.open('https://www.instagram.com/accounts/login/')

    def gmail_link():
        webbrowser.open('https://accounts.google.com/ServiceLogin?sacu=1&continue=https%3A%2F%2Faccounts.google.com%2F&followup=https%3A%2F%2Faccounts.google.com%2F')

    def tweet_link():
        webbrowser.open('https://twitter.com/login/')

    def snap_link():
        webbrowser.open('https://accounts.snapchat.com/accounts/login?continue=https%3A%2F%2Faccounts.snapchat.com%2Faccounts%2Fwelcome')

    def paypal_link():
        webbrowser.open('https://www.paypal.com/in/signin')

    def flip_link():
        webbrowser.open('https://www.flipkart.com/account/login?')

    def amazon_link():
        webbrowser.open('https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2Fgp%2Fcss%2Fhomepage.html%2F%3Fie%3DUTF8%26from%3Dhz%26ref_%3Dnav_ya_signin&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&')

    def linked_link():
        webbrowser.open('https://www.linkedin.com/uas/login')

    def dev_contact():
        if store_text.cget('foreground') == 'grey':
            store_text.delete("1.0", END)
            store_text.configure(foreground="black")
            store_text.insert(INSERT, "Developer email:\ndasdebjeet39@gmail.com")
        else:
            store_text.insert(END,"\n")
            store_text.insert(INSERT, "Developer email:\ndasdebjeet39@gmail.com")

    def common():
        try:
            for widget in frame2.winfo_children():
                widget.destroy()
            from collections import Counter
            
            def destroy():
                c=0
                pass_count.destroy()
                scrollbar.destroy()
                for widget in frame2.winfo_children():
                    c+=1
                if c == 0:
                    Label(frame2, text="Vault", font=("Times",200,"bold"), foreground="deep sky blue").grid(row=0,column=0)
            file_record("-Password Repetition Checked")
            pass_count = tk.Text(frame2,height=6,width=50,wrap=NONE, foreground="red", background="SystemButtonFace", borderwidth=0, font=("Segoe UI", 10))
            pass_count.grid(row=0,column=0,padx=10,sticky='nswe')
            pass_count.configure(state="disabled")
            scrollbar = Scrollbar(frame2,orient="horizontal")
            scrollbar.grid(row=0,column=0,padx=10,sticky='swe')
            pass_count.config(xscrollcommand=scrollbar.set)
            scrollbar.config(command=pass_count.xview)
            mcom = []
            trac = 0
            decryptKey()
            decrypt_now()
            c.execute('SELECT LAN FROM schedule')
            data = c.fetchall()
            c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
            data1 = c.fetchone()
            encrypt_now()
            encryptKey()
            for i in data[1:]:
                mcom.append(decryptMessage(decrypt_str(i[0], decryptMessage(data1[0]))))
            count = Counter(mcom).most_common(3)
                                
            pass_count.configure(state="normal")
            pass_count.insert(INSERT, "Do not use the same password in multiple places\n")
            pass_count.configure(state="disabled")
            if len(count) == 1:
                first, c1 = count[0]
                if c1>1:
                    trac += 1
                    pass_count.configure(state="normal")
                    pass_count.insert(INSERT, first + " " + str(c1) + "\n")
                    pass_count.configure(state="disabled")
            elif len(count) == 2:
                first, c1 = count[0]
                second, c2 = count[1]
                if c1>1:
                    trac += 1
                    pass_count.configure(state="normal")
                    pass_count.insert(INSERT, first + " " + str(c1) + "\n")
                    pass_count.configure(state="disabled")
                if c2>1:
                    pass_count.configure(state="normal")
                    pass_count.insert(INSERT, second + " " + str(c2) + "\n")
                    pass_count.configure(state="disabled")
            else:
                first, c1 = count[0]
                second, c2 = count[1]
                third, c3 = count[2]
                if c1>1:
                    trac += 1
                    pass_count.configure(state="normal")
                    pass_count.insert(INSERT, first + " " + str(c1) + "\n")
                    pass_count.configure(state="disabled")
                if c2>1:
                    pass_count.configure(state="normal")
                    pass_count.insert(INSERT, second + " " + str(c2) + "\n")
                    pass_count.configure(state="disabled")
                if c3>1:
                    pass_count.configure(state="disabled")
                    pass_count.insert(INSERT, third + " " + str(c3))
                    pass_count.configure(state="normal")
            if trac == 0:
                pass_count.configure(state="normal")
                pass_count.insert(INSERT, "No password Repeated")
                pass_count.configure(state="disabled")
            frame1.after(5000,destroy)
        except IndexError:
            pass_count.configure(state="normal")
            pass_count.insert(INSERT, "No Passwords Currently in Database\n")
            pass_count.configure(state="disabled")
            frame1.after(5000,destroy)
        except sqlite3.DatabaseError:
            access()
    after_id = None
    def session_end():
        c.close()
        conn.close()
        encryptFile()
        root.destroy()
        MessageBox = ctypes.windll.user32.MessageBoxW
        MessageBox(None, 'Vault was idle for 5 minutes', 'Session Expired', 0)
        sys.exit()
    def reset_timer(event=None):
        global after_id
        if after_id is not None:
            root.after_cancel(after_id)
        after_id = root.after(300000, session_end)

    def Notepad(event=None):
        file_record("-Secure Notes Accessed")

        def increment_note(s):
            s =  s[::-1]
            note = ""
            note2 = ""
            note3 = ""
            for i in range(len(s)):
                note += (chr(ord(s[i])*13))
            for i in range(len(note)):
                note2 += (chr(ord(note[i])*7))
            for i in range(len(note2)):
                note3 += (chr(ord(note2[i])*25))
            return note3

        def decrement_note(x):
            x =  x[::-1]
            notei = ""
            notei2 = ""
            notei3 = ""
            for i in range(len(x)):
                notei += (chr(int(ord(x[i])/13)))
            for i in range(len(notei)):
                notei2 += (chr(int(ord(notei[i])/7)))
            for i in range(len(notei2)):
                notei3 += (chr(int(ord(notei2[i])/25)))
            return notei3

        def filter_note_list():
            if title_search.get() != '':
                user = getpass.getuser()
                if os.path.exists(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                    for widget in frame.winfo_children():
                        widget.destroy()
                    row = 0
                    for file in os.listdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                        if file.endswith('.txt.aes'):
                            if decrement_note(file[:-8])[:len(title_search.get())] == title_search.get():
                                study_png = PhotoImage(file = 'assets\\study.png')
                                study_png = study_png.subsample(2,2)
                                study_png = study_png.subsample(2,2)
                                study_png = study_png.subsample(2,2)
                                study_png = study_png.subsample(2,2)
                                study_png_label = Label(frame, image=study_png)
                                study_png_label.image = study_png
                                study_png_label.grid(row=row,column=0,pady=10,padx=10)
                                list_note_label = Label(frame, text=decrement_note(file[:-8]), font=( 'Segoe UI' ,16), cursor="hand2")
                                list_note_label.grid(row=row,column=1,padx=10,sticky='nw')
                                Label(frame, text=time.ctime(os.path.getmtime(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'+file)), font=( 'Segoe UI' ,12)).grid(row=row,column=1,padx=10,sticky='sw')
                                list_note_label.bind("<Button-1>", lambda e, labelNum=file[:-8]: open_note_list(labelNum))
                                list_note_label.bind("<Enter>", lambda e, : e.widget.config(foreground="red", font=('Comic Sans MS', 16)))
                                list_note_label.bind("<Leave>", lambda e, : e.widget.config(foreground="black", font=( 'Segoe UI' ,16)))
                                list_note_label.bind("<Button-3>", lambda e, labelNum=file[:-8]: delete_note_list(labelNum))
                                row += 1
                    if row == 0:
                        Label(frame, text="No Notes beginning with "+title_search.get(),font=( 'Segoe UI' ,12)).grid(row=0,column=0,padx=5,pady=5,sticky='w')
                else:
                    messagebox.showwarning('Missing', 'No Notes saved yet')
            else:
                messagebox.showerror('Empty', 'Filter Index is Empty')
                    
        def open_note_list(labelNum):
            user = getpass.getuser()
            filename = r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\' + labelNum + '.txt'
            if os.path.isfile(filename+".aes"):
                buffersize = 64*1024
                decryptKey()
                decrypt_now()
                c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                data = c.fetchone()
                encrypt_now()
                encryptKey()
                password = decryptMessage(data[0])
                pyAesCrypt.decryptFile(filename+".aes", filename, password, buffersize)
                try:
                    if os.path.isfile(filename):
                        file = open(filename,"r")
                        if text.get(1.0, END) != '':
                            text.delete(1.0, END)
                        text.insert(1.0, decryptMessage(file.read()))
                        file.close()
                        os.remove(filename)
                    if title_name.get() != '':
                        title_name.delete(0, END)
                        title_name.insert(0, decrement_note(labelNum))
                    else:
                        title_name.insert(0, decrement_note(labelNum))
                except:
                    messagebox.showerror('Error', 'The Secure notes has been removed, please refresh the Secure Notes 2-3 times, and do remove the Secure Notes list when going away from the Secure Notes option')

        def delete_note_list(labelNum):
            res = messagebox.askquestion('Delete Notes', 'This will delete all info inside ' + decrement_note(labelNum) + ' .Continue?')
            if res == 'yes':
                if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\' + labelNum + '.txt.aes'):
                    os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\' + labelNum + '.txt.aes')
                    list_note()
                else:
                    messagebox.showerror('Missing', 'No note with the heading ' + labelNum)
                    
        def list_note():
            user = getpass.getuser()
            if os.path.exists(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                for widget in frame.winfo_children():
                    widget.destroy()
                row = 0
                for file in os.listdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                    if file.endswith('.txt.aes'):
                        study_png = PhotoImage(file = 'assets\\study.png')
                        study_png = study_png.subsample(2,2)
                        study_png = study_png.subsample(2,2)
                        study_png = study_png.subsample(2,2)
                        study_png = study_png.subsample(2,2)
                        study_png_label = Label(frame, image=study_png)
                        study_png_label.image = study_png
                        study_png_label.grid(row=row,column=0,pady=10,padx=10)
                        list_note_label = Label(frame, text=decrement_note(file[:-8]), font=( 'Segoe UI' ,16), cursor="hand2")
                        list_note_label.grid(row=row,column=1,padx=10,sticky='nw')
                        Label(frame, text=time.ctime(os.path.getmtime(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'+file)), font=( 'Segoe UI' ,12)).grid(row=row,column=1,padx=10,sticky='sw')
                        list_note_label.bind("<Button-1>", lambda e, labelNum=file[:-8]: open_note_list(labelNum))
                        list_note_label.bind("<Enter>", lambda e, : e.widget.config(foreground="red", font=('Comic Sans MS', 16)))
                        list_note_label.bind("<Leave>", lambda e, : e.widget.config(foreground="black", font=( 'Segoe UI' ,16)))
                        list_note_label.bind("<Button-3>", lambda e, labelNum=file[:-8]: delete_note_list(labelNum))
                        row += 1
                if row == 0:
                    Label(frame, text="All Notes Deleted" ,font=( 'Segoe UI' ,12)).grid(row=0,column=0,padx=5,pady=5,sticky='w')
            else:
                messagebox.showwarning('Missing', 'No Notes saved yet')
        def dark():
            on = PhotoImage(file = "assets\\on.png")
            on = on.subsample(2,2)
            on = on.subsample(2,2)
            on = on.subsample(2,2)
            on = on.subsample(2,2)
            text.config(foreground="green2", background="gray10")
            off_btn.config(command=light, image=on)
            off_btn.image = on
        def light():
            text.config(foreground="black", background="snow")
            off_btn.config(command=dark, image=off)

        def save_note(event=None):
            if title_name.get() == '':
                title_name.insert(0, "enter note heading")
            else:
                user = getpass.getuser()
                path = r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes'
                if not os.path.exists(path):
                    os.makedirs(path)
                    ctypes.windll.kernel32.SetFileAttributesW(path, 2)
                filename = r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\' + increment_note(title_name.get()) + '.txt'
                if os.path.isfile(filename+".aes"):
                    buffersize = 64*1024
                    decryptKey()
                    decrypt_now()
                    c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                    data = c.fetchone()
                    encrypt_now()
                    encryptKey()
                    password = decryptMessage(data[0])
                    pyAesCrypt.decryptFile(filename+".aes", filename, password, buffersize)
                    os.remove(filename+".aes")

                file = open(filename,"w")
                file.write(encryptMessage(text.get(1.0, 'end-1c'))) 
                file.close()

                if os.path.isfile(filename):
                    buffersize = 64*1024
                    decryptKey()
                    decrypt_now()
                    c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                    data = c.fetchone()
                    encrypt_now()
                    encryptKey()
                    password = decryptMessage(data[0])
                    pyAesCrypt.encryptFile(filename, filename+".aes", password, buffersize)
                    os.remove(filename)
                    file_record("-Secure Notes Updated")
                    talkback('Saved')
                    list_note()

        def copy_text():
            pyperclip.copy(text.get(SEL_FIRST, SEL_LAST))
            talkback('Copied')
            file_record("-Text Copied from Secure Notes")

        def cut_text():
            pyperclip.copy(text.get(SEL_FIRST, SEL_LAST))
            text.delete(SEL_FIRST, SEL_LAST)
            talkback('Text Cut')
            file_record("-Text Cut from Secure Notes")

        def paste_text():
            text.insert(END, pyperclip.paste())

        def open_file(event=None):
            def close_open(event=None):
                open_f.destroy()
                
            def open_note(event=None):
                if title_entry.get() != '':
                    filename = r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\' + increment_note(title_entry.get()) + '.txt'
                    if os.path.isfile(filename+".aes"):
                        buffersize = 64*1024
                        decryptKey()
                        decrypt_now()
                        c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                        data = c.fetchone()
                        encrypt_now()
                        encryptKey()
                        password = decryptMessage(data[0])
                        pyAesCrypt.decryptFile(filename+".aes", filename, password, buffersize)
                        if os.path.isfile(filename):
                            file = open(filename,"r")
                            if text.get(1.0, END) != '':
                                text.delete(1.0, END)
                            text.insert(1.0, decryptMessage(file.read()))
                            file.close()
                            os.remove(filename)
                        if title_name.get() != '':                            
                            title_name.delete(0, END)
                            title_name.insert(0, title_entry.get())                            
                        else:                            
                            title_name.insert(0, title_entry.get())
                        open_f.destroy()
                    else:
                        messagebox.showerror('File Not Found', 'No Notes found with the heading ' + title_entry.get())
                else:
                    messagebox.showerror('Empty', 'Please enter the heading of the note you want to open')
            open_f = Toplevel()
            open_f.overrideredirect(True)
            open_f.resizable(False, False)
            open_f.attributes("-topmost", 1)
            
            Label(open_f, text = "Enter Title", font=( 'Segoe UI' ,12)).grid(row=0,column=0,padx=10,pady=(10,0),sticky='w')

            close_lbl = Label(open_f, text='  X  ', background="red",foreground="white", cursor="hand2")
            close_lbl.grid(row=0,column=0,sticky='ne')
            close_lbl.bind("<Button-1>", close_open)

            title_entry = Entry(open_f, width = 26, font=("Segoe UI", 10))
            title_entry.grid(row=1,column=0, padx =10,pady=(0,10),sticky='w')
            title_entry.focus()
            title_entry.bind("<Return>", open_note)

            tk.Button(open_f, text="Open", font=( 'Segoe UI' ,8), background="#1492e6",foreground="white", activebackground="#1492e6", activeforeground="white", width=7, command=open_note).grid(row=2,column=0,pady=(0,10),padx=10,sticky='e')

        def delete_note():
            if title_name.get() == '':
                title_name.configure(state='normal')
                title_name.insert(0, "enter note heading")
            else:
                if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\' + increment_note(title_name.get()) + '.txt.aes'):
                    os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\' + increment_note(title_name.get()) + '.txt.aes')
                    list_note()
                    new_note_clear()
                else:
                    messagebox.showerror('Missing', 'No note with the heading ' + title_name.get())

        def myfunction(event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def new_note_clear():
            text.delete(1.0, END)
            title_name.delete(0, END)
            
        for widget in frame2.winfo_children():
                widget.destroy()
        
        off = PhotoImage(file = "assets\\off.png")
        off = off.subsample(2,2)
        off = off.subsample(2,2)
        off = off.subsample(2,2)
        off = off.subsample(2,2)
        off_btn = tk.Button(frame2,  image = off, borderwidth=0,  cursor="hand2", command=dark)
        off_btn.image = off
        off_btn.grid(row=0,column=0,padx=10,sticky='ne')

        menu = Frame(frame2)
        menu.grid(row=0,column=0,sticky='w')

        new_note = PhotoImage(file = "assets\\new_note.png")
        new_note = new_note.subsample(2,2)
        new_note = new_note.subsample(2,2)
        new_note = new_note.subsample(2,2)
        new_note = new_note.subsample(2,2)
        new_note = new_note.subsample(2,2)
        new_note_btn = tk.Button(menu,  image = new_note, borderwidth=0,  cursor="hand2", command=new_note_clear)
        new_note_btn.image = new_note
        new_note_btn.grid(row=0,column=0,sticky='w',pady=5,padx=(10,5))
        CreateToolTip(new_note_btn, 15, 20, "New note")

        open_note = PhotoImage(file = "assets\\open_note.png")
        open_note = open_note.subsample(2,2)
        open_note = open_note.subsample(2,2)
        open_note = open_note.subsample(2,2)
        open_note = open_note.subsample(2,2)
        open_note = open_note.subsample(2,2)
        open_note_btn = tk.Button(menu,  image = open_note, borderwidth=0,  cursor="hand2", command=open_file)
        open_note_btn.image = open_note
        open_note_btn.grid(row=0,column=1,sticky='w',pady=5,padx=5)
        CreateToolTip(open_note_btn, 15, 20, "Open note")
        
        save = PhotoImage(file = "assets\\save.png")
        save = save.subsample(2,2)
        save = save.subsample(2,2)
        save = save.subsample(2,2)
        save = save.subsample(2,2)
        save = save.subsample(2,2)
        save_btn = tk.Button(menu,  image = save, borderwidth=0,  cursor="hand2", command=save_note)
        save_btn.image = save
        save_btn.grid(row=0,column=2,sticky='w',pady=5,padx=5)
        CreateToolTip(save_btn, 15, 20, "Save")
        
        cut = PhotoImage(file = "assets\\cut.png")
        cut = cut.subsample(2,2)
        cut = cut.subsample(2,2)
        cut = cut.subsample(2,2)
        cut = cut.subsample(2,2)
        cut = cut.subsample(2,2)
        cut_btn = tk.Button(menu,  image = cut, borderwidth=0,  cursor="hand2", command=cut_text)
        cut_btn.image = cut
        cut_btn.grid(row=0,column=3,sticky='w',pady=5,padx=5)
        CreateToolTip(cut_btn, 15, 20, "Cut")

        copy_note = PhotoImage(file = "assets\\copy_note.png")
        copy_note = copy_note.subsample(2,2)
        copy_note = copy_note.subsample(2,2)
        copy_note = copy_note.subsample(2,2)
        copy_note = copy_note.subsample(2,2)
        copy_note = copy_note.subsample(2,2)
        copy_note_btn = tk.Button(menu,  image = copy_note, borderwidth=0,  cursor="hand2", command=copy_text)
        copy_note_btn.image = copy_note
        copy_note_btn.grid(row=0,column=4,sticky='w',pady=5,padx=5)
        CreateToolTip(copy_note_btn, 15, 20, "Copy")

        paste_note = PhotoImage(file = "assets\\paste.png")
        paste_note = paste_note.subsample(2,2)
        paste_note = paste_note.subsample(2,2)
        paste_note = paste_note.subsample(2,2)
        paste_note = paste_note.subsample(2,2)
        paste_note = paste_note.subsample(2,2)
        paste_note_btn = tk.Button(menu,  image = paste_note, borderwidth=0,  cursor="hand2", command=paste_text)
        paste_note_btn.image = paste_note
        paste_note_btn.grid(row=0,column=5,sticky='w',pady=5,padx=5)
        CreateToolTip(paste_note_btn, 15, 20, "Paste")

        del_note = PhotoImage(file = "assets\\delete_note.png")
        del_note = del_note.subsample(2,2)
        del_note = del_note.subsample(2,2)
        del_note = del_note.subsample(2,2)
        del_note = del_note.subsample(2,2)
        del_note = del_note.subsample(2,2)
        del_note_btn = tk.Button(menu,  image = del_note, borderwidth=0,  cursor="hand2", command=delete_note)
        del_note_btn.image = del_note
        del_note_btn.grid(row=0,column=6,sticky='w',pady=5,padx=5)
        CreateToolTip(del_note_btn, 15, 20, "Delete note")

        title_name = Entry(menu, width = 25, font=("Segoe UI", 9))
        title_name.grid(row=0,column=7, pady = 5,padx=5, sticky='w')

        list_notes = PhotoImage(file = "assets\\list.png")
        list_notes = list_notes.subsample(2,2)
        list_notes = list_notes.subsample(2,2)
        list_notes = list_notes.subsample(2,2)
        list_notes = list_notes.subsample(2,2)
        list_notes = list_notes.subsample(2,2)
        list_notes_btn = tk.Button(menu,  image = list_notes, borderwidth=0,  cursor="hand2", command=list_note)
        list_notes_btn.image = list_notes
        list_notes_btn.grid(row=0,column=8,pady=5,padx=5,sticky='w')
        CreateToolTip(list_notes_btn, 15, 20, "Display Notes List")

        title_search = Entry(menu, width = 15, font=("Segoe UI", 9))
        title_search.grid(row=0,column=9,pady=5,padx=5,sticky='w')

        search_notes = PhotoImage(file = "assets\\filter.png")
        search_notes = search_notes.subsample(2,2)
        search_notes = search_notes.subsample(2,2)
        search_notes = search_notes.subsample(2,2)
        search_notes = search_notes.subsample(2,2)
        search_notes = search_notes.subsample(2,2)
        search_notes_btn = tk.Button(menu,  image = search_notes, borderwidth=0,  cursor="hand2", command=filter_note_list)
        search_notes_btn.image = search_notes
        search_notes_btn.grid(row=0,column=10,pady=5,padx=5,sticky='w')
        CreateToolTip(search_notes_btn, 15, 20, "Search")

        text = Text(frame2, font=('Segoe UI', 12), background="snow", foreground="black", undo=True, autoseparators=True,maxundo=-1)
        text.grid(row=1,column=0,padx=10,pady=(0,10),sticky='nw')
        text.focus()
        text.bind('<Control-s>', save_note)
        text.bind('<Control-o>', open_file)
        text.bind('<Control-n>', Notepad)
        text_scroll = Scrollbar(frame2)
        text_scroll.config(command=text.yview)      
        text.config(yscrollcommand=text_scroll.set)
        text_scroll.grid(row=1,column=0,padx=(0,10),pady=(0,10),sticky='nse')

    def secure_url():
        def open_in_web(labelNum):
            webbrowser.open(labelNum)

        def copy_url(labelNum):
            pyperclip.copy(labelNum)
            talkback('URL Copied')
            
        def display_url():
            for widget in frame.winfo_children():
                widget.destroy()
            user = getpass.getuser()
            if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes'):
                buffersize = 64*1024
                decryptKey()
                decrypt_now()
                c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                data = c.fetchone()
                encrypt_now()
                encryptKey()
                password = decryptMessage(data[0])
                pyAesCrypt.decryptFile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes', r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url', password, buffersize)
                file = open(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url', 'r')
                Lines = file.readlines()
                file.close()
                check_url = 0
                os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url')
                for line in Lines:
                    check_url += 1
                    list_url_label = Label(frame, text=line.strip(), font=( 'Segoe UI' ,12), cursor="hand2")
                    list_url_label.pack(side=TOP, pady=5,padx=5, anchor='w')
                    list_url_label.bind("<Button-1>", lambda e, labelNum=line.strip(): open_in_web(labelNum))
                    list_url_label.bind("<Enter>", lambda e, : e.widget.config(foreground="blue", font=('arial', 12, 'underline')))
                    list_url_label.bind("<Leave>", lambda e, : e.widget.config(foreground="black", font=( 'Segoe UI' ,12)))
                    list_url_label.bind("<Button-3>", lambda e, labelNum=line.strip(): copy_url(labelNum))
                if check_url == 0:
                    Label(frame, text="All URLs deleted.", font=( 'Segoe UI' ,12), cursor="hand2").pack(side=TOP, pady=5,padx=5, anchor='w')
            else:
                Label(frame, text="No URls saved yet", font=( 'Segoe UI' ,12), cursor="hand2").pack(side=TOP, pady=5,padx=5, anchor='w')

        def filter_url():
            for widget in frame.winfo_children():
                widget.destroy()
            user = getpass.getuser()
            if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes'):
                buffersize = 64*1024
                decryptKey()
                decrypt_now()
                c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                data = c.fetchone()
                encrypt_now()
                encryptKey()
                password = decryptMessage(data[0])
                pyAesCrypt.decryptFile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes', r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url', password, buffersize)
                file = open(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url', 'r')
                Lines = file.readlines()
                file.close()
                check_url = 0
                os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url')
                for line in Lines:
                    if get_fld(line.strip())[:len(url_search.get())] == url_search.get():
                        check_url += 1
                        list_url_label = Label(frame, text=line.strip(), font=( 'Segoe UI' ,12), cursor="hand2")
                        list_url_label.pack(side=TOP, pady=5,padx=5, anchor='w')
                        list_url_label.bind("<Button-1>", lambda e, labelNum=line.strip(): open_in_web(labelNum))
                        list_url_label.bind("<Enter>", lambda e, : e.widget.config(foreground="blue", font=('arial', 12, 'underline')))
                        list_url_label.bind("<Leave>", lambda e, : e.widget.config(foreground="black", font=( 'Segoe UI' ,12)))
                        list_url_label.bind("<Button-3>", lambda e, labelNum=line.strip(): copy_url(labelNum))
                if check_url == 0:
                    Label(frame, text="All URLs deleted.", font=( 'Segoe UI' ,12), cursor="hand2").pack(side=TOP, pady=5,padx=5, anchor='w')
            else:
                Label(frame, text="No URls saved yet", font=( 'Segoe UI' ,12), cursor="hand2").pack(side=TOP, pady=5,padx=5, anchor='w')
                
        def myfunction(event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def add_url():
            
            def close_add(event=None):
                add_link.destroy()

            def add(event=None):
                user = getpass.getuser()
                if not os.path.exists(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\'):
                    os.mkdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\')
                if not os.path.exists(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\'):
                    os.mkdir(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\')
                if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes'):
                    buffersize = 64*1024
                    decryptKey()
                    decrypt_now()
                    c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                    data = c.fetchone()
                    encrypt_now()
                    encryptKey()
                    password = decryptMessage(data[0])
                    pyAesCrypt.decryptFile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes', r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url', password, buffersize)
                    os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes')
                file = open(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url', 'a')
                file.write(add_link_entry.get())
                file.write("\n")
                file.close()
                if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url'):
                    buffersize = 64*1024
                    decryptKey()
                    decrypt_now()
                    c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                    data = c.fetchone()
                    encrypt_now()
                    encryptKey()
                    password = decryptMessage(data[0])
                    pyAesCrypt.encryptFile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url', r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes', password, buffersize)
                    os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url')
                display_url()
                talkback('URL added')
            
            add_link = Toplevel()
            add_link.overrideredirect(True)
            add_link.resizable(False, False)
            add_link.attributes("-topmost", 1)
            
            Label(add_link, text = "Enter URL", font=( 'Segoe UI' ,12)).grid(row=0,column=0,padx=10,pady=(10,0),sticky='w')

            add_link_lbl = Label(add_link, text='  X  ', background="red",foreground="white", cursor="hand2")
            add_link_lbl.grid(row=0,column=0,sticky='ne')
            add_link_lbl.bind("<Button-1>", close_add)

            add_link_entry = Entry(add_link, width = 35, font=("Segoe UI", 10))
            add_link_entry.grid(row=1,column=0, padx =10,pady=(0,10),sticky='w')
            add_link_entry.focus()
            add_link_entry.bind("<Return>", add)

            tk.Button(add_link, text="Add", font=( 'Segoe UI' ,8), background="#1492e6",foreground="white", activebackground="#1492e6", activeforeground="white", width=7, command=add).grid(row=2,column=0,pady=(0,10),padx=10,sticky='e')

        def delete_url():
            
            def close_delete(event=None):
                delete_link.destroy()

            def delete(event=None):
                user = getpass.getuser()
                if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes'):
                    buffersize = 64*1024
                    decryptKey()
                    decrypt_now()
                    c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                    data = c.fetchone()
                    encrypt_now()
                    encryptKey()
                    password = decryptMessage(data[0])
                    pyAesCrypt.decryptFile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes', r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url', password, buffersize)
                    os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes')
                fin = open(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url', 'r')
                Lines = fin.readlines()
                fin.close()
                count = 0
                fout = open(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url', 'w')
                for line in Lines:
                    if line.strip() != delete_link_entry.get():
                        fout.write(line)
                    else:
                        count += 1
                fout.close()
                if os.path.isfile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url'):
                    buffersize = 64*1024
                    decryptKey()
                    decrypt_now()
                    c.execute("SELECT LAN FROM schedule WHERE URL='42585f535e554305'")
                    data = c.fetchone()
                    encrypt_now()
                    encryptKey()
                    password = decryptMessage(data[0])
                    pyAesCrypt.encryptFile(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url', r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url.aes', password, buffersize)
                    os.remove(r'C:\\Users\\' + user + '\\AppData\\Local\\Vault\\notes\\url')
                if count == 0:
                    print(url_change + " not found")
                else:
                    display_url()
                    talkback('URL deleted')
            
            delete_link = Toplevel()
            delete_link.overrideredirect(True)
            delete_link.resizable(False, False)
            delete_link.attributes("-topmost", 1)
            
            Label(delete_link, text = "Enter URL", font=( 'Segoe UI' ,12)).grid(row=0,column=0,padx=10,pady=(10,0),sticky='w')

            delete_link_lbl = Label(delete_link, text='  X  ', background="red",foreground="white", cursor="hand2")
            delete_link_lbl.grid(row=0,column=0,sticky='ne')
            delete_link_lbl.bind("<Button-1>", close_delete)

            delete_link_entry = Entry(delete_link, width = 35, font=("Segoe UI", 10))
            delete_link_entry.grid(row=1,column=0, padx =10,pady=(0,10),sticky='w')
            delete_link_entry.focus()
            delete_link_entry.bind("<Return>", delete)

            tk.Button(delete_link, text="Delete", font=( 'Segoe UI' ,8), background="#1492e6",foreground="white", activebackground="#1492e6", activeforeground="white", width=7, command=delete).grid(row=2,column=0,pady=(0,10),padx=10,sticky='e')
            
        for widget in frame2.winfo_children():
            widget.destroy()
        
        frame_options = Frame(frame2)
        frame_options.grid(row=0,column=0,sticky=W+E)
        
        refresh = PhotoImage(file = "assets\\unfilter.png")
        refresh = refresh.subsample(2,2)
        refresh = refresh.subsample(2,2)
        refresh = refresh.subsample(2,2)
        refresh = refresh.subsample(2,2)
        refresh = refresh.subsample(2,2)
        refresh_btn = tk.Button(frame2,  image = refresh, borderwidth=0,  cursor="hand2", command=display_url)
        refresh_btn.image = refresh
        refresh_btn.grid(row=0,column=1, padx=5, pady=5, sticky='e')
        
        CreateToolTip(lis_btn, 20, 30, "Refresh List")
        frame_display = Frame(frame2)
        frame_display.grid(row=1, columnspan=2, sticky=N+S+W+E)
        
        add_link = PhotoImage(file = "assets\\add_link.png")
        add_link = add_link.subsample(2,2)
        add_link = add_link.subsample(2,2)
        add_link = add_link.subsample(2,2)
        add_link = add_link.subsample(2,2)
        add_link = add_link.subsample(2,2)
        add_link_btn = tk.Button(frame_options,  image = add_link, borderwidth=0,  cursor="hand2", command=add_url)
        add_link_btn.image = add_link
        add_link_btn.grid(row=0,column=0,pady=5,padx=5,sticky='w')
        CreateToolTip(add_link_btn, 15, 20, "Add")
        
        trash_note = PhotoImage(file = "assets\\trash.png")
        trash_note = trash_note.subsample(2,2)
        trash_note = trash_note.subsample(2,2)
        trash_note = trash_note.subsample(2,2)
        trash_note = trash_note.subsample(2,2)
        trash_note = trash_note.subsample(2,2)
        trash_note_btn = tk.Button(frame_options,  image = trash_note, borderwidth=0,  cursor="hand2", command=delete_url)
        trash_note_btn.image = trash_note
        trash_note_btn.grid(row=0,column=1,pady=5,padx=5,sticky='w')
        CreateToolTip(trash_note_btn, 15, 20, "Delete")

        url_search = Entry(frame_options, width = 20, font=("Segoe UI", 8))
        url_search.grid(row=0,column=2,pady=5,padx=5,sticky='w')

        search_url = PhotoImage(file = "assets\\filter.png")
        search_url = search_url.subsample(2,2)
        search_url = search_url.subsample(2,2)
        search_url = search_url.subsample(2,2)
        search_url = search_url.subsample(2,2)
        search_url = search_url.subsample(2,2)
        search_url_btn = tk.Button(frame_options,  image = search_url, borderwidth=0,  cursor="hand2", command=filter_url)
        search_url_btn.image = search_url
        search_url_btn.grid(row=0,column=3,pady=5,padx=5,sticky='w')
        CreateToolTip(search_url_btn, 15, 20, "Search")

        canvas = Canvas(frame_display)
        frame = Frame(canvas)
        myscrollbar = Scrollbar(frame_display, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=myscrollbar.set)
        myscrollbar.pack(side=RIGHT, fill=Y)
        myhoriscrollbar = Scrollbar(frame_display, orient="horizontal", command=canvas.xview)
        canvas.configure(xscrollcommand=myhoriscrollbar.set)
        myhoriscrollbar.pack(side=BOTTOM, fill=X)
        canvas.pack(side=RIGHT, fill=BOTH, expand=True)
        canvas.create_window((0,0), window=frame, anchor='nw')
        frame.bind("<Configure>", myfunction)
        display_url()
            
    def HELP():
        messagebox.showinfo("HELP", """VAULT can be used to store all your passwords securely, everything will be saved on your local machine, therefore preventing any network based attacks.To use it effectively:
1) The add options is used to add new passwords.In it, it is compulsory to enter the website name, the username and the password. The url and notes are optional. There is also a secure option, which when enabled will prevent the password from being displayed in the list on the left. You can access these passwords from the search option.
2) The search option asks for the website name and username to fetch and display the details related to these. It requires both the website name and the usernamme because different websites can have the same username. Alternatively, you can scroll down to the desired website name in the list on the left, and tap on the desired name to display all details related to it. There is also a 'filter' option provided just above the list, which can be used to filter the list according to the starting letters provided.The button(the one with the list as an image) can be used to display the original list anytime.
3) The delete option too asks for the website name and username and deletes the correspoding record. Be careful when deleting as any deleted password record cannot be retrieved. Due to this, the 'enter the execute' has been disabled here, to prevent accident deletion. Once you press the delete button, the password will be permanently deleted.
4) The update options asks for the same details, the website name and username, and then there are 4 options provided, you can either update the username, password, notes or the url of the desired record. Record updation too, is irreversible. Do it carefully.
5) The update account option is used to update your account username, password or your security question.
6) The delete account option SHOULD BE USED VERY CAREFULLY.It will delete your account, including your password database, logs, security logs etc.
7) The generate password option can be used to generate strong reliable passwords.
8) The check password option can be used to check the strength of a password. DO NOT USE WEAK PASSWORDS.
9) The security option is present as a security measure. If someone enters the wrong username or password in the login screen 3 times, VAULT will take a screenshot of your screen(or if a webcam is present, it will take a picture through it) mentioning the current date and time the login was tried, and also the username and password with which login was attempted. Upon clicking the security button, it will display the last screenshot or webcam picture taken.
10) The repeated option is used to see which password you use most(it determines this from the passwords present in the database), and displays the top 3 most used passwords, along with the number of times it was used.YOU ARE ADVISED NOT TO USE THE SAME PASSWORD IN MULTIPLE PLACES.Use the password generator to generate different passwords and let VAULT remember them for you.
11) The export option should be used carefully, as it may pose as a security vulnerability. Although the exported will be heavily encrypted, still nothing is 100% safe. On exporting, VAULT will create a file with all your passwords, notes and links in it. You can then import this file in another machine which has vault installed, you would have to provide your correct password and only then will the passwords be imported. The import option can be found in the create account screen and nowhere else.
12) The notes option is there to store your notes securely. You can store any number of notes you want provided a proper heading is given to the note. You can later search the notes using the list option or search option provided there. Remeber to remove the notes list once your work is over otherwise the software may crash.
13) The url is a low security place to store any and all urls you may have. It is low security, but is still AES encrypted, not easily breakable as long as your master password is strong.
There are some other options, feel free to explore them and if you have any suggestions or you have found some bug in the software, feel free to contact me at my email address. I would love to hear from you.
And i apologize if the software causes you any problems, please do inform me of the problem so that i may rectify it.
                                                                                                                                                                                                                        -Debjeet Das
                                                                                                                                                                                                                         dasdebjeet39@gmail.com""")

    if __name__ == "__main__":
        global root, running
        user = getpass.getuser()
        path = r'C:\\Users\\' + user + '\\AppData\\database\\'
        if not os.path.exists(path):
            os.makedirs(path)
        dir = r'C:\\Users\\' + user + '\\Notepad\\'
        if not os.path.exists(dir):
            os.makedirs(dir)
        if not os.path.isfile(r'C:\\Users\\' + user + '\\Notepad\\Logs.txt'):
            file = open(r'C:\\Users\\' + user + '\\Notepad\\Logs.txt', 'a')
            file.close()
        hide()
        decryptFile()
        db = path+'schedule.db'
        conn = sqlite3.connect(db)
        c = conn.cursor()
        create_table()
        account_pass()
        root = Tk()
        style = Style()
        w = root.winfo_screenwidth()
        h = root.winfo_screenheight()
        root.title("Vault")
        root.state('zoomed')
        root.iconbitmap('assets\\lock.ico')
        root.geometry("%dx%d+0+0" % (w,h))
        root.minsize(width=w,height=h)
        frame1 = tk.Frame(root, bd=5, highlightbackground="gray70", highlightthickness=1)
        frame1.pack(side=TOP, fill='x', expand=False)
        frame6 = Frame(root)
        frame6.pack(fill='x', side=BOTTOM, anchor=S)
        developer = Label(frame6, font=('aria', 10), text="-Made by Debjeet Das", foreground="gray1")
        developer.pack(fill=None, side=RIGHT, anchor=NE)
        hel = PhotoImage(file = "assets\\help.png")
        hel = hel.subsample(2,2)
        hel = hel.subsample(2,2)
        hel = hel.subsample(2,2)
        hel = hel.subsample(2,2)
        hel = hel.subsample(2,2)
        help_btn = tk.Button(frame6, image=hel, borderwidth=0, cursor="hand2", command=HELP)
        help_btn.image = hel
        help_btn.pack(fill=None, side=RIGHT, anchor=NE)
        total_etn = Label(frame6, font=('aria', 10), text="Total Entries: ", foreground="gray1")
        total_etn.pack(fill=None, side=LEFT, anchor=SW)
        frame4 = Frame(root)
        frame4.pack(side=BOTTOM,fill='x',expand=False)
        logs = Text(frame4, height=3)
        logs.pack(side=LEFT, fill = None, expand=False)
        with open(dir+'Logs.txt', 'r') as f:
            logs.insert(INSERT, f.read())
        logs.see(END)
        logs.configure(state="disabled")
        frame5 = Frame(root)
        frame5.pack(side=RIGHT,fill='y',expand=True,anchor=SE)
        frame2 = Frame(root,borderwidth=10)
        frame2.pack(side=RIGHT, fill=None, expand=True)
        frame7 = Frame(root)
        frame7.pack(side=TOP, fill='x',expand=False, anchor='s',pady=(10,0))
        filter_entry = Entry(frame7, width = 32, font=("Segoe UI", 12))
        filter_entry.grid(row = 0, column = 1, padx=10, sticky='sw')
        filter_entry.bind("<Return>", filter_out)
        filter_entry.bind("<Escape>", Show_All)
        filt = PhotoImage(file = "assets\\filter.png")
        filt = filt.subsample(2,2)
        filt = filt.subsample(2,2)
        filt = filt.subsample(2,2)
        filt = filt.subsample(2,2)
        filt = filt.subsample(2,2)
        filter_btn = tk.Button(frame7,  image = filt, borderwidth=0,  cursor="hand2", command=filter_out)
        filter_btn.grid(row=0,column=2, padx=(5,5), sticky='w')

        unfilt = PhotoImage(file = "assets\\unfilter.png")
        unfilt = unfilt.subsample(2,2)
        unfilt = unfilt.subsample(2,2)
        unfilt = unfilt.subsample(2,2)
        unfilt = unfilt.subsample(2,2)
        lis_btn = tk.Button(frame7,  image = unfilt, borderwidth=0,  cursor="hand2", command=Show_All)
        lis_btn.grid(row=0,column=0, padx=(22,15))
        CreateToolTip(lis_btn, 20, 30, "Refresh List")
        
        frame3 = Frame(root)
        frame3.pack(side=RIGHT, fill=BOTH, expand=False)
        store()
        canvas = Canvas(frame3)
        frame = Frame(canvas)
        myscrollbar = Scrollbar(frame3, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=myscrollbar.set)
        myscrollbar.pack(side=RIGHT, fill=Y)
        myhoriscrollbar = Scrollbar(frame3, orient="horizontal", command=canvas.xview)
        canvas.configure(xscrollcommand=myhoriscrollbar.set)
        myhoriscrollbar.pack(side=BOTTOM, fill=X)
        canvas.pack(side=RIGHT, fill=BOTH, expand=True)
        canvas.create_window((0,0), window=frame, anchor='nw')
        frame.bind("<Configure>", myfunction)

        Show_All()
        Label(frame2, text="Vault", font=("Times",200,"bold"), foreground="deep sky blue").grid(row=0,column=0)
        addition = PhotoImage(file = "assets\\add.png")
        add = addition.subsample(2,2)
        add = add.subsample(2,2)
        add = add.subsample(2,2)
        add = add.subsample(2,2)
        button_add = tk.Button(frame1, text="Add", image = add, compound = TOP, borderwidth=0, command=Add_Password, cursor="hand2")
        button_add.grid(row = 0,column=0, padx=15, sticky=N+S)
        CreateToolTip(button_add, 15, 50,"Store new Password")

        searching = PhotoImage(file = "assets\\search.png")
        search = searching.subsample(2,2)
        search = search.subsample(2,2)
        search = search.subsample(2,2)
        search = search.subsample(2,2)
        button_search = tk.Button(frame1, text="Search", image = search, compound = TOP, borderwidth=0, command=Search_Password, cursor="hand2")
        button_search.grid(row = 0,column=1, padx=15, sticky=N+S)
        CreateToolTip(button_search, 15, 50, "Search a Password")

        deletion = PhotoImage(file = "assets\\delete.png")
        delete = deletion.subsample(2,2)
        delete = delete.subsample(2,2)
        delete = delete.subsample(2,2)
        delete = delete.subsample(2,2)
        button_delete = tk.Button(frame1, text="Delete", image = delete, compound = TOP, borderwidth=0, command=Delete_Password, cursor="hand2")
        button_delete.grid(row =0,column=2, padx=15, sticky=N+S)
        CreateToolTip(button_delete, 15, 50, "Delete a Password")

        updation = PhotoImage(file = "assets\\edit.png")
        update = updation.subsample(2,2)
        update = update.subsample(2,2)
        update = update.subsample(2,2)
        update = update.subsample(2,2)
        button_update = tk.Button(frame1, text="Update",image = update, compound = TOP, borderwidth=0, command=Update_Password, cursor="hand2")
        button_update.grid(row =0,column=3, padx=15, sticky=N+S)
        CreateToolTip(button_update, 15, 50, "Update Username or Password")

        Separator(frame1,orient=VERTICAL).grid(row=0,column=4, sticky='ns')

        up_acc = PhotoImage(file = "assets\\update.png")
        acc = up_acc.subsample(2,2)
        acc = acc.subsample(2,2)
        acc = acc.subsample(2,2)
        acc = acc.subsample(2,2)
        button_show = tk.Button(frame1, text="Update", image = acc, compound = TOP, borderwidth=0, command = Restricted, cursor="hand2")
        button_show.grid(row =0,column=5, padx=15, sticky=N+S)
        CreateToolTip(button_show, 15, 50, "Update Your Account Username or Password")

        del_acc = PhotoImage(file = "assets\\del_acc.png")
        account = del_acc.subsample(2,2)
        account = account.subsample(2,2)
        account = account.subsample(2,2)
        account = account.subsample(2,2)
        button_export = tk.Button(frame1, text="Delete", image = account, compound = TOP, borderwidth=0, command=Delete_Account, cursor="hand2")
        button_export.grid(row =0,column=6, padx=15, sticky=N+S)
        CreateToolTip(button_export, 15, 50, "Delete Your Account")

        Separator(frame1,orient=VERTICAL).grid(row=0,column=7, sticky='ns')

        generate = PhotoImage(file = "assets\\generate.png")
        gen = generate.subsample(2,2)
        gen = gen.subsample(2,2)
        gen = gen.subsample(2,2)
        gen = gen.subsample(2,2)
        button_gen = tk.Button(frame1, text="Generate", image = gen, compound = TOP, borderwidth=0, command=Generate_Password, cursor="hand2")
        button_gen.grid(row =0,column=8, padx=15, sticky=N+S)
        CreateToolTip(button_gen, 15, 50, "Generate a Strong Password")

        checker = PhotoImage(file = "assets\\check.png")
        check = checker.subsample(2,2)
        check = check.subsample(2,2)
        check = check.subsample(2,2)
        check = check.subsample(2,2)
        button_verify = tk.Button(frame1, text="Verify", image = check, compound = TOP, borderwidth=0, command = verify, cursor="hand2")
        button_verify.grid(row =0,column=9, padx=15, sticky=N+S)
        CreateToolTip(button_verify, 15, 50, "Check Password Strength")

        Separator(frame1,orient=VERTICAL).grid(row=0,column=10, sticky='ns')

        security = PhotoImage(file = "assets\\security.png")
        secure = security.subsample(2,2)
        secure = secure.subsample(2,2)
        secure = secure.subsample(2,2)
        secure = secure.subsample(2,2)
        breach = tk.Button(frame1, text="Security",  image = secure, compound = TOP, borderwidth=0, command=vault, cursor="hand2")
        breach.grid(row=0,column=11, padx=15, sticky=N+S)
        CreateToolTip(breach, 15, 50, "See who last tried to acess the Vault")

        commo = PhotoImage(file = "assets\\common.png")
        comm = commo.subsample(2,2)
        comm = comm.subsample(2,2)
        comm = comm.subsample(2,2)
        comm = comm.subsample(2,2)
        repeat = tk.Button(frame1, text="Repeated",  image = comm, compound = TOP, borderwidth=0, command=common, cursor="hand2")
        repeat.grid(row=0,column=12, padx=15, sticky=N+S)
        CreateToolTip(repeat, 15, 50, "See the password you use most")

        Separator(frame1,orient=VERTICAL).grid(row=0,column=13, sticky='ns')

        export = PhotoImage(file = "assets\\export.png")
        export = export.subsample(2,2)
        export = export.subsample(2,2)
        export = export.subsample(2,2)
        export = export.subsample(2,2)
        export_btn = tk.Button(frame1, text="Export",  image = export, compound = TOP, borderwidth=0, command = Export, cursor="hand2")
        export_btn.grid(row=0,column=14, padx=15, sticky=N+S+W)
        CreateToolTip(export_btn, 15, 50, "Transfer your Passwords")

        Separator(frame1,orient=VERTICAL).grid(row=0,column=15, sticky='ns')

        note = PhotoImage(file = "assets\\notes.png")
        note = note.subsample(2,2)
        note = note.subsample(2,2)
        note = note.subsample(2,2)
        note = note.subsample(2,2)
        note_btn = tk.Button(frame1, text="Notes",  image = note, compound = TOP, borderwidth=0, command = Notepad, cursor="hand2")
        note_btn.grid(row=0,column=16, padx=15, sticky=N+S+W)
        CreateToolTip(note_btn, 15, 50, "Secure Notes")

        url_img = PhotoImage(file = "assets\\url.png")
        url_img = url_img.subsample(2,2)
        url_img = url_img.subsample(2,2)
        url_img = url_img.subsample(2,2)
        url_img = url_img.subsample(2,2)
        url_btn = tk.Button(frame1, text="Links",  image = url_img, compound = TOP, borderwidth=0, cursor="hand2", command=secure_url)
        url_btn.grid(row=0,column=17, padx=15, sticky=N+S+W)
        CreateToolTip(url_btn, 15, 50, "Secure Links")

        clip = Text(frame1,height=3,width=20,foreground="red")
        clip.grid(row=0,column=18,sticky='e')
        frame1.grid_rowconfigure(0,weight=1)
        frame1.grid_columnconfigure(18,weight=1)
        clip.configure(state="disabled")

        instagram = PhotoImage(file = "assets\\instagram.png")
        insta = instagram.subsample(2,2)
        insta = insta.subsample(2,2)
        insta = insta.subsample(2,2)
        insta = insta.subsample(2,2)
        insta_btn = tk.Button(frame5, image = insta, borderwidth=0, command=insta_link, cursor="hand2")
        insta_btn.grid(row=0,column=0, pady=10, padx=10, sticky=W+E)
        CreateToolTip(insta_btn, -70, 35, "Open Instagram")

        facebook = PhotoImage(file = "assets\\facebook.png")
        face = facebook.subsample(2,2)
        face = face.subsample(2,2)
        face = face.subsample(2,2)
        face = face.subsample(2,2)
        face_btn = tk.Button(frame5, image = face, borderwidth=0, command = face_link, cursor="hand2")
        face_btn.grid(row=1,column=0, pady=10, padx=10, sticky=W+E)
        CreateToolTip(face_btn, -40, 40, "Open Facebook")

        google = PhotoImage(file = "assets\\gmail.png")
        gmail = google.subsample(2,2)
        gmail = gmail.subsample(2,2)
        gmail = gmail.subsample(2,2)
        gmail = gmail.subsample(2,2)
        gmail_btn = tk.Button(frame5, image = gmail, borderwidth=0, command=gmail_link, cursor="hand2")
        gmail_btn.grid(row=2,column=0, pady=10, padx=10, sticky=W+E)
        CreateToolTip(gmail_btn, -40, 40, "Open GMAIL")

        snapchat = PhotoImage(file = "assets\\snapchat.png")
        snap = snapchat.subsample(2,2)
        snap = snap.subsample(2,2)
        snap = snap.subsample(2,2)
        snap = snap.subsample(2,2)
        snap_btn = tk.Button(frame5, image = snap, borderwidth=0, command=snap_link, cursor="hand2")
        snap_btn.grid(row=3,column=0, pady=10, padx=10, sticky=W+E)
        CreateToolTip(snap_btn, -70, 35, "Open Snapchat")

        paypal = PhotoImage(file = "assets\\paypal.png")
        pay = paypal.subsample(2,2)
        pay = pay.subsample(2,2)
        pay = pay.subsample(2,2)
        pay = pay.subsample(2,2)
        pay_btn = tk.Button(frame5, image = pay, borderwidth=0, command=paypal_link, cursor="hand2")
        pay_btn.grid(row=4,column=0, pady=10, padx=10, sticky=W+E)
        CreateToolTip(pay_btn, -70, 35, "Open Paypal")

        twitter = PhotoImage(file = "assets\\twitter.png")
        tweet = twitter.subsample(2,2)
        tweet = tweet.subsample(2,2)
        tweet = tweet.subsample(2,2)
        tweet = tweet.subsample(2,2)
        tweet_btn = tk.Button(frame5, image = tweet, borderwidth=0, command=tweet_link, cursor="hand2")
        tweet_btn.grid(row=5,column=0, pady=10, padx=10, sticky=W+E)
        CreateToolTip(tweet_btn, -70, 35, "Open Twitter")

        linkedin = PhotoImage(file = "assets\\linkedin.png")
        linked = linkedin.subsample(2,2)
        linked = linked.subsample(2,2)
        linked = linked.subsample(2,2)
        linked = linked.subsample(2,2)
        linked_btn = tk.Button(frame5, image = linked, borderwidth=0, command=linked_link, cursor="hand2")
        linked_btn.grid(row=6,column=0, pady=10, padx=10, sticky=W+E)
        CreateToolTip(linked_btn, -70, 35, "Open Linkedin")

        flipkart = PhotoImage(file = "assets\\flipkart.png")
        flip = flipkart.subsample(2,2)
        flip = flip.subsample(2,2)
        flip = flip.subsample(2,2)
        flip = flip.subsample(2,2)
        flip_btn = tk.Button(frame5, image = flip, borderwidth=0, command=flip_link, cursor="hand2")
        flip_btn.grid(row=7,column=0, pady=10, padx=10, sticky=W+E)
        CreateToolTip(flip_btn, -70, 35, "Open Flipkart")

        amazon = PhotoImage(file = "assets\\amazon.png")
        amaz = amazon.subsample(2,2)
        amaz = amaz.subsample(2,2)
        amaz = amaz.subsample(2,2)
        amaz = amaz.subsample(2,2)
        amaz_btn = tk.Button(frame5, image = amaz, borderwidth=0, command=amazon_link, cursor="hand2")
        amaz_btn.grid(row=8,column=0, pady=10, padx=10, sticky=W+E)
        CreateToolTip(amaz_btn, -70, 35, "Open Amazon")

                
        developer = PhotoImage(file = "assets\\dev.png")
        dev = developer.subsample(2,2)
        dev = dev.subsample(2,2)
        dev = dev.subsample(2,2)
        dev = dev.subsample(2,2)
        dev_btn = tk.Button(frame5, image = dev, borderwidth=0, command=dev_contact, cursor="hand2")
        dev_btn.grid(row=9,column=0, pady=10, padx=10, sticky=W+E)
        CreateToolTip(dev_btn, -70, 35, "Developer contact")

        root.bind_all("<Any-KeyPress>", reset_timer)
        root.bind_all("<Any-ButtonPress>", reset_timer)
        root.mainloop()
        c.close()
        conn.close()
        encryptFile()
except sqlite3.DatabaseError:
    pass
except PermissionError:
    elevate()
except SystemExit:
    sys.exit()
except Exception as e:
    print(e)
    MessageBox = ctypes.windll.user32.MessageBoxW
    MessageBox(None, 'Some Fatal Error Occured, please try Again.If problem persists, contact developer.', 'Error', 0)
