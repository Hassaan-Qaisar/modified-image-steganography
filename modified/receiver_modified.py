# receiver_gui.py

import socket
from PIL import Image
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import threading
import os
import hmac
import hashlib
import random

# Pre-shared key (16 bytes for AES-128)
PRE_SHARED_KEY = b''  # Replace with your secure key

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')

def decode_image(image_path, n=4, seed=42):
    img = Image.open(image_path)
    width, height = img.size
    image_bytes = img.tobytes()

    # Generate pixel indices using Spread Spectrum
    pixel_indices = generate_pixel_indices(width, height, n, seed=seed)

    # Calculate the number of ciphertext bits based on image capacity
    total_pixels = width * height
    available_pixels = len(pixel_indices)
    mac_bits_length = 256  # 256 bits for HMAC-SHA256
    ciphertext_bits_length = available_pixels - mac_bits_length

    if ciphertext_bits_length <= 0:
        raise ValueError("Image is too small to contain any message.")

    # Extract ciphertext bits
    ciphertext_bits = []
    for i in range(ciphertext_bits_length):
        idx = pixel_indices[i]
        ciphertext_bits.append(str(image_bytes[idx] & 1))
    ciphertext = bytes(int(''.join(ciphertext_bits[i:i+8]), 2) for i in range(0, len(ciphertext_bits), 8))

    # Extract MAC bits
    mac_bits = []
    for i in range(ciphertext_bits_length, ciphertext_bits_length + mac_bits_length):
        idx = pixel_indices[i]
        mac_bits.append(str(image_bytes[idx] & 1))
    mac = bytes(int(''.join(mac_bits[i:i+8]), 2) for i in range(0, len(mac_bits), 8))

    # Verify HMAC
    computed_mac = hmac.new(PRE_SHARED_KEY, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, computed_mac):
        raise ValueError("Integrity check failed. The message may have been tampered with.")

    # Decrypt the message
    message = aes_decrypt(ciphertext, PRE_SHARED_KEY)

    return message

def generate_pixel_indices(width, height, n, seed=42):
    random.seed(seed)
    total_pixels = width * height
    # Spread spectrum: distribute bits across the image randomly
    indices = random.sample(range(total_pixels), total_pixels)
    return indices

def receive_encoded_image(output_image_path, listen_ip, listen_port, callback, n=4, seed=42):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((listen_ip, listen_port))
            print("🔄 Listening for incoming encoded images...")
            data, addr = sock.recvfrom(65536)  # Use a larger buffer size (e.g., 65536)
            with open(output_image_path, "wb") as f:
                f.write(data)
            print("✅ Encoded image received successfully.")

            # Decode the received image to extract the hidden message
            decoded_message = decode_image(output_image_path, n=n, seed=seed)
            callback(decoded_message)
    except Exception as e:
        callback(f"❌ Error: {str(e)}")

class ReceiverGUI:
    def __init__(self, master):
        self.master = master
        master.title("📥 Image Receiver")
        master.geometry("800x700")
        master.resizable(False, False)

        # Styling
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 12))
        self.style.configure('TButton', font=('Arial', 12))
        self.style.configure('Header.TLabel', font=('Arial', 16, 'bold'))
        self.style.configure('TEntry', font=('Arial', 12))

        # Main Frame
        self.main_frame = ttk.Frame(master, padding="20")
        self.main_frame.grid(row=0, column=0, sticky='NSEW')

        # Configure grid weights
        master.grid_rowconfigure(0, weight=1)
        master.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(7, weight=1)  # Allow message frame to expand
        self.main_frame.grid_columnconfigure(1, weight=1)

        # Header
        self.header = ttk.Label(self.main_frame, text="🔒 Receive a Secret Message", style='Header.TLabel')
        self.header.grid(row=0, column=0, columnspan=3, pady=10)

        # Listen IP
        self.listen_ip_label = ttk.Label(self.main_frame, text="Listen IP:")
        self.listen_ip_label.grid(row=1, column=0, sticky='E', padx=5, pady=5)
        self.listen_ip_entry = ttk.Entry(self.main_frame, width=30)
        self.listen_ip_entry.grid(row=1, column=1, sticky='W', padx=5, pady=5)
        self.listen_ip_entry.insert(0, "0.0.0.0")

        # Listen Port
        self.listen_port_label = ttk.Label(self.main_frame, text="Listen Port:")
        self.listen_port_label.grid(row=2, column=0, sticky='E', padx=5, pady=5)
        self.listen_port_entry = ttk.Entry(self.main_frame, width=30)
        self.listen_port_entry.grid(row=2, column=1, sticky='W', padx=5, pady=5)
        self.listen_port_entry.insert(0, "12345")

        # Receive Button
        self.receive_button = ttk.Button(self.main_frame, text="📥 Start Receiving", command=self.start_receiving)
        self.receive_button.grid(row=3, column=1, pady=20, sticky='W')

        # Status Label
        self.status_label = ttk.Label(self.main_frame, text="", foreground="green", font=('Arial', 12, 'bold'))
        self.status_label.grid(row=4, column=0, columnspan=3, pady=10, sticky='W')

    def start_receiving(self):
        listen_ip = self.listen_ip_entry.get()
        try:
            listen_port = int(self.listen_port_entry.get())
        except ValueError:
            messagebox.showerror("Invalid Port", "Please enter a valid listening port number.")
            return

        # Fixed steganography parameters
        n = 4
        seed = 42

        output_image_path = "received_image.png"

        self.receive_button.config(state=tk.DISABLED)
        self.status_label.config(text="🔄 Listening for incoming images...", foreground="blue")
        self.master.update_idletasks()

        # Start a new thread to receive the image
        threading.Thread(target=self.receive_thread, args=(output_image_path, listen_ip, listen_port, n, seed), daemon=True).start()

    def receive_thread(self, output_image_path, listen_ip, listen_port, n, seed):
        status = receive_encoded_image(output_image_path, listen_ip, listen_port, self.handle_message, n=n, seed=seed)

    def handle_message(self, message):
        if message.startswith("❌ Error") or message.startswith("Error"):
            self.update_status(message, success=False)
            messagebox.showerror("Error", message)
        else:
            self.update_status("✅ Message received and decoded successfully.", success=True)
            messagebox.showinfo("Received Message", f"Message: {message}")
            # Optionally, open the received image
            try:
                img = Image.open("received_image.png")
                img.show()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open received image: {str(e)}")

        # Re-enable the receive button for the next message
        self.receive_button.config(state=tk.NORMAL)

    def update_status(self, message, success=True):
        color = "green" if success else "red"
        self.status_label.config(text=message, foreground=color)
        if success:
            pass  # Already handled via messagebox
        else:
            pass  # Already handled via messagebox

def main():
    root = tk.Tk()
    gui = ReceiverGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
