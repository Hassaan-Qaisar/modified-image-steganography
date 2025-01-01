# Information Security Project: Enhanced Image Steganography  

This project aims to improve the security of image steganography by incorporating advanced cryptographic techniques. Starting from a basic implementation sourced from GeeksforGeeks, we modified and enhanced it with AES encryption, SHA hashing, and a broad-spectrum steganographic approach.  

---

## 🚀 Features  

1. **Advanced Encryption**  
   - Integrated AES encryption (128-bit key) for secure data transmission.  
   - SHA hashing ensures message integrity and validity of the decryption key.  

2. **Broad Spectrum Technique**  
   - The hidden message is distributed across the entire image for increased robustness against detection.  

3. **Key Authentication**  
   - The receiver manually inputs the key to validate and decrypt the message.  

4. **Enhanced Security**  
   - Brute force attacks implemented to test vulnerabilities in both the original and modified implementations.  

---

## 📂 Project Structure  

The project is organized into four folders:  

1. **`original/`**  
   Contains the initial image steganography code taken from GeeksforGeeks for reference.  

2. **`modified/`**  
   - Sender and receiver modules with our modifications.  
   - Features AES encryption, SHA hashing, and broad-spectrum steganography.  

3. **`gui/`**  
   - A simple GUI using Tkinter for ease of use.  
   - Provides a user-friendly interface for sending and receiving encrypted messages.  

4. **`attack/`**  
   - Scripts to perform brute-force attacks on both the original and modified implementations.  
   - Compares the security strength of both approaches.  

---

## ⚙️ Technologies Used  

- **Cryptography**: AES (128-bit), SHA hashing  
- **Programming Language**: Python  
- **Libraries**:  
  - `tkinter` for GUI  
  - `Pillow` for image processing  
  - `cryptography` for encryption and hashing  
- **Image Steganography**: Broad-spectrum data embedding  

---

## 🛠️ How to Use  

1. Clone the repository:  
   ```bash
   git clone https://github.com/Hassaan-Qaisar/modified-image-steganography
   cd your-repository
