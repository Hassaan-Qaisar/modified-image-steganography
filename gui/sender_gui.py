# sender_gui.py

import socket
from PIL import Image, ImageTk, ImageDraw
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import os

def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return ciphertext

def encode_image(image_path, message):
    #open the image and convert to bytes
    img = Image.open(image_path)
    width, height = img.size
    image_bytes = img.tobytes()

    # Generate a random 128-bit key and an integer n
    key = get_random_bytes(16)
    n = random.randint(2, 9)

    #convert the message to cipher
    message = aes_encrypt(message, key)

    # Convert n, cipher and key to bits for steganography
    n_bits = format(n, "08b")
    key_bits = "".join(format(b, "08b") for b in key)
    message_bits = "".join(format(b, "08b") for b in message)

    #->CHECKS   
    if len(message_bits) > len(image_bytes) - 8:  # Reserve the first 8 pixels for n
        raise ValueError("Message is too large to be encoded in the image")

    encoded_pixels = bytearray(image_bytes)

    #->ENCODING n
    # Replace the least significant bits of the first 8 pixels with the bits of n
    for i in range(8):
        pixel = image_bytes[i]
        bit = n_bits[i]
        new_pixel = (pixel & 0xFE) | int(bit)
        encoded_pixels[i] = new_pixel

    #->ENCODING MESSAGE
    # after we have embedded the random integer n successfully, we now encode the image with the message we wish to send.
    index = 8
    used_bytes = []
    for m in message_bits:
        pixel = image_bytes[index]
        used_bytes.append(index) #noting down the bytes we have altered
        new_pixel = (pixel & 0xFE) | int(m)
        encoded_pixels[index] = new_pixel
        index += n
    
    #after we are done putting in our message we need to indicate an end to it. "index" is the last place where we put the message, now we put a 11001100 using the same formula
    pixel = image_bytes[index + n]
    used_bytes.append(index)
    new_pixel = 0b11001100
    encoded_pixels[index] = new_pixel
    
    #->ENCODING KEY
    # after we have embedded the random integer n successfully, we now encode the image with the key.
    index = 9
    for k in key_bits:
        if index in used_bytes: #check to ensure that the byte of the image we are about to alter has not already been altered
            index += n
        else:
            pixel = image_bytes[index]
            new_pixel = (pixel & 0xFE) | int(k)
            encoded_pixels[index] = new_pixel
            index += n

    #now we indicate the end of the key with 10101010
    pixel = image_bytes[index + n]
    used_bytes.append(index)
    new_pixel = 0b10101010
    encoded_pixels[index] = new_pixel

    # Create a new image with the encoded pixels
    encoded_image = Image.frombytes("RGB", (width, height), bytes(encoded_pixels))
    return encoded_image

def send_encoded_image(image_path, message, receiver_ip, receiver_port):
    try:
        encoded_image = encode_image(image_path, message)
        encoded_image_path = "encoded_image.png"
        encoded_image.save(encoded_image_path)
    
        # Send encoded image over UDP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            with open(encoded_image_path, "rb") as f:
                data = f.read()
                sock.sendto(data, (receiver_ip, receiver_port))
        os.remove(encoded_image_path)  # Clean up
        return "Encoded image sent successfully."
    except Exception as e:
        return f"Error: {str(e)}"

class SenderGUI:
    def __init__(self, master):
        self.master = master
        master.title("📤 Image Sender")
        master.geometry("700x600")
        master.resizable(False, False)

        # Styling
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 12))
        self.style.configure('TButton', font=('Arial', 12))
        self.style.configure('Header.TLabel', font=('Arial', 16, 'bold'))
        self.style.configure('TEntry', font=('Arial', 12))
        self.style.configure('TText', font=('Arial', 12))

        # Main Frame
        self.main_frame = ttk.Frame(master, padding="20")
        self.main_frame.grid(row=0, column=0, sticky='NSEW')

        # Configure grid weights
        master.grid_rowconfigure(0, weight=1)
        master.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(7, weight=1)  # Allow message frame to expand
        self.main_frame.grid_columnconfigure(1, weight=1)

        # Header
        self.header = ttk.Label(self.main_frame, text="🔒 Send a Secret Message", style='Header.TLabel')
        self.header.grid(row=0, column=0, columnspan=3, pady=10)

        # Receiver IP
        self.receiver_ip_label = ttk.Label(self.main_frame, text="Receiver IP:")
        self.receiver_ip_label.grid(row=1, column=0, sticky='E', padx=5, pady=5)
        self.receiver_ip_entry = ttk.Entry(self.main_frame, width=30)
        self.receiver_ip_entry.grid(row=1, column=1, sticky='W', padx=5, pady=5)
        self.receiver_ip_entry.insert(0, "127.0.0.1")

        # Receiver Port
        self.receiver_port_label = ttk.Label(self.main_frame, text="Receiver Port:")
        self.receiver_port_label.grid(row=2, column=0, sticky='E', padx=5, pady=5)
        self.receiver_port_entry = ttk.Entry(self.main_frame, width=30)
        self.receiver_port_entry.grid(row=2, column=1, sticky='W', padx=5, pady=5)
        self.receiver_port_entry.insert(0, "12345")

        # Image Path
        self.image_path_label = ttk.Label(self.main_frame, text="Image Path:")
        self.image_path_label.grid(row=3, column=0, sticky='E', padx=5, pady=5)
        self.image_path_entry = ttk.Entry(self.main_frame, width=40)
        self.image_path_entry.grid(row=3, column=1, sticky='W', padx=5, pady=5)
        self.browse_button = ttk.Button(self.main_frame, text="Browse", command=self.browse_image)
        self.browse_button.grid(row=3, column=2, sticky='W', padx=5, pady=5)

        # Create New Image Button
        self.create_image_button = ttk.Button(self.main_frame, text="Create New Image", command=self.create_new_image)
        self.create_image_button.grid(row=4, column=1, pady=10, sticky='W')

        # Secret Message Label
        self.message_label = ttk.Label(self.main_frame, text="Secret Message:")
        self.message_label.grid(row=5, column=0, sticky='NE', padx=5, pady=5)

        # Secret Message Text
        self.message_text = tk.Text(self.main_frame, height=10, width=50, font=('Arial', 12))
        self.message_text.grid(row=5, column=1, columnspan=2, sticky='W', padx=5, pady=5)

        # Send Button
        self.send_button = ttk.Button(self.main_frame, text="📤 Send Message", command=self.send_message)
        self.send_button.grid(row=6, column=1, pady=20, sticky='W')

        # Status Label
        self.status_label = ttk.Label(self.main_frame, text="", foreground="green", font=('Arial', 12, 'bold'))
        self.status_label.grid(row=7, column=0, columnspan=3, pady=10, sticky='W')

    def browse_image(self):
        file_path = filedialog.askopenfilename(
            title="Select Image",
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")]
        )
        if file_path:
            self.image_path_entry.delete(0, tk.END)
            self.image_path_entry.insert(0, file_path)

    def create_new_image(self):
        # Create a new white image
        new_image_path = "new_image.png"
        img = Image.new("RGB", (800, 600), color='white')
        img.save(new_image_path)
        self.image_path_entry.delete(0, tk.END)
        self.image_path_entry.insert(0, os.path.abspath(new_image_path))
        messagebox.showinfo("New Image Created", f"New image created and saved as:\n{os.path.abspath(new_image_path)}")

    def send_message(self):
        receiver_ip = self.receiver_ip_entry.get()
        try:
            receiver_port = int(self.receiver_port_entry.get())
        except ValueError:
            messagebox.showerror("Invalid Port", "Please enter a valid receiver port number.")
            return
        image_path = self.image_path_entry.get()
        message = self.message_text.get("1.0", tk.END).strip()

        if not image_path or not os.path.exists(image_path):
            messagebox.showerror("Invalid Image", "Please select a valid image.")
            return

        if not message:
            messagebox.showerror("Empty Message", "Please enter a message to send.")
            return

        self.status_label.config(text="🔄 Encoding and sending the image...", foreground="blue")
        self.master.update_idletasks()

        status = send_encoded_image(image_path, message, receiver_ip, receiver_port)
        if status.startswith("Error"):
            self.status_label.config(text=status, foreground="red")
            messagebox.showerror("Error", status)
        else:
            self.status_label.config(text=status, foreground="green")
            messagebox.showinfo("Success", status)

def main():
    root = tk.Tk()
    gui = SenderGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
