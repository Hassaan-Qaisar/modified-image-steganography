# receiver_gui.py

import socket
import sys
from PIL import Image
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import threading
import os

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')

def decode_image(image_path):
    img = Image.open(image_path)
    image_bytes = img.tobytes()

    # Extract n from the first 8 pixels
    n_bits = [str(image_bytes[i] & 1) for i in range(8)]
    n = int(''.join(n_bits), 2)

    # Extract the key and the cipher from the image
    key_bits = []
    cipher_bits = []

    #the 8th index will have the first cipher bit and 9th will have the first key bit
    #first we get the cipher
    index = 8
    cipher_bits.append(str(image_bytes[index] & 1))
    for i in range(8, len(image_bytes)):
        if image_bytes[index + n] == 204:
            break
        else:
            cipher_bits.append(str(image_bytes[index + n] & 1))
            index += n
    
    #now we get the key
    index = 9
    key_bits.append(str(image_bytes[index] & 1))
    for i in range(9, len(image_bytes)):
        if image_bytes[index + n] == 170:
            break
        else:
            key_bits.append(str(image_bytes[index + n] & 1))
            index += n

    key_bytes = bytes(int(''.join(key_bits[i:i+8]), 2) for i in range(0, len(key_bits), 8))
    cipher_bytes = bytes(int(''.join(cipher_bits[i:i+8]), 2) for i in range(0, len(cipher_bits), 8))

    # Decrypt the cipher using the key
    message = aes_decrypt(cipher_bytes, key_bytes)

    return message

def receive_encoded_image(output_image_path, listen_ip, listen_port, callback):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((listen_ip, listen_port))
            print("Waiting to receive encoded image...")
            data, addr = sock.recvfrom(65536)  # Use a larger buffer size (e.g., 65536)
            with open(output_image_path, "wb") as f:
                f.write(data)
            print("Encoded image received successfully.")

            # Decode the received image to extract the hidden message
            decoded_message = decode_image(output_image_path)
            callback(decoded_message)
    except Exception as e:
        callback(f"Error: {str(e)}")

class ReceiverGUI:
    def __init__(self, master):
        self.master = master
        master.title("📥 Image Receiver")
        master.geometry("600x400")
        master.resizable(False, False)

        # Styling
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 12))
        self.style.configure('TButton', font=('Arial', 12))
        self.style.configure('Header.TLabel', font=('Arial', 16, 'bold'))

        # Main Frame
        self.main_frame = ttk.Frame(master, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        self.header = ttk.Label(self.main_frame, text="🔒 Receive a Secret Message", style='Header.TLabel')
        self.header.pack(pady=10)

        # Listening Details Frame
        self.listen_frame = ttk.LabelFrame(self.main_frame, text="Listening Details", padding="15")
        self.listen_frame.pack(fill=tk.X, pady=10)

        # Listen IP
        self.listen_ip_label = ttk.Label(self.listen_frame, text="Listen IP:")
        self.listen_ip_label.grid(row=0, column=0, sticky='e', padx=5, pady=5)
        self.listen_ip_entry = ttk.Entry(self.listen_frame, width=30)
        self.listen_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        self.listen_ip_entry.insert(0, "0.0.0.0")

        # Listen Port
        self.listen_port_label = ttk.Label(self.listen_frame, text="Listen Port:")
        self.listen_port_label.grid(row=1, column=0, sticky='e', padx=5, pady=5)
        self.listen_port_entry = ttk.Entry(self.listen_frame, width=30)
        self.listen_port_entry.grid(row=1, column=1, padx=5, pady=5)
        self.listen_port_entry.insert(0, "12345")

        # Receive Button
        self.receive_button = ttk.Button(self.main_frame, text="📥 Start Receiving", command=self.start_receiving)
        self.receive_button.pack(pady=10)

        # Status Frame
        self.status_frame = ttk.Frame(self.main_frame, padding="10")
        self.status_frame.pack(fill=tk.X)

        self.status_label = ttk.Label(self.status_frame, text="", foreground="green", font=('Arial', 12, 'bold'))
        self.status_label.pack()

    def start_receiving(self):
        listen_ip = self.listen_ip_entry.get()
        try:
            listen_port = int(self.listen_port_entry.get())
        except ValueError:
            messagebox.showerror("Invalid Port", "Please enter a valid listening port number.")
            return
        output_image_path = "received_image.png"

        self.receive_button.config(state=tk.DISABLED)
        self.status_label.config(text="Listening for incoming images...", foreground="blue")
        self.master.update_idletasks()

        # Start a new thread to receive the image
        threading.Thread(target=receive_encoded_image, args=(output_image_path, listen_ip, listen_port, self.handle_message), daemon=True).start()

    def handle_message(self, message):
        if message.startswith("Error"):
            self.status_label.config(text=message, foreground="red")
            messagebox.showerror("Error", message)
        else:
            self.status_label.config(text="Message received and decoded successfully.", foreground="green")
            messagebox.showinfo("Received Message", f"Message: {message}")
            # Optionally, open the received image
            img = Image.open("received_image.png")
            img.show()

def main():
    root = tk.Tk()
    gui = ReceiverGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
