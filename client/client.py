# client.py
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk, ImageOps
import requests
import json
from dotenv import load_dotenv, set_key
from library.cryto_tools import (
    generate_rsa_key_pair,
    convert_private_key_to_pem,
    convert_public_key_to_pem,
    decrypt_server_public_key,
    prepare_crypto_package
)

# Load environment variables
load_dotenv()

# FastAPI 서버 URL
SERVER_URL = "http://127.0.0.1:8000/api/v1"

class WatermarkApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Watermark Application")

        # Add API key entry and exchange button at top
        self.api_frame = tk.Frame(root)
        self.api_frame.pack(pady=5)
        
        self.api_label = tk.Label(self.api_frame, text="API Key:")
        self.api_label.pack(side=tk.LEFT, padx=5)
        
        self.api_entry = tk.Entry(self.api_frame, width=40)
        self.api_entry.pack(side=tk.LEFT, padx=5)
        
        self.exchange_button = tk.Button(self.api_frame, text="서버와 Key 교환", command=self.exchange_keys)
        self.exchange_button.pack(side=tk.LEFT, padx=5)

        # Add a frame to contain the image
        self.image_frame = tk.Frame(root, width=600, height=400)
        self.image_frame.pack(pady=10)
        self.image_frame.pack_propagate(False)  # Prevent frame from shrinking

        # Change image label to fit in frame
        self.image_label = tk.Label(self.image_frame, text="No Image Uploaded", bg="gray")
        self.image_label.pack(expand=True, fill='both')

        # 버튼 영역
        self.upload_button = tk.Button(root, text="Upload Image", command=self.upload_image)
        self.upload_button.pack(pady=5)

        self.embed_button = tk.Button(root, text="Embed WM", command=self.embed_watermark, state=tk.DISABLED)
        self.embed_button.pack(pady=5)

        self.extract_button = tk.Button(root, text="Extract WM", command=self.extract_watermark, state=tk.DISABLED)
        self.extract_button.pack(pady=5)

        # 상태 표시 영역
        self.status_label = tk.Label(root, text="Status: Ready", fg="blue")
        self.status_label.pack(pady=10)

        # 이미지 경로
        self.image_path = None

        self.user_id = os.getenv("USER_ID")
        
        if not self.user_id:
            messagebox.showerror("Error", "USER_ID not found in .env")
            return

    def upload_image(self):
        """이미지 업로드 및 표시"""
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg;*.jpeg;*.png")])
        if file_path:
            self.image_path = file_path
            img = Image.open(file_path)
            # Resize image to fit 600x400 exactly
            img = ImageOps.fit(img, (600, 400), Image.LANCZOS)
            img_tk = ImageTk.PhotoImage(img)
            self.image_label.config(image=img_tk, text="")
            self.image_label.image = img_tk
            self.embed_button.config(state=tk.NORMAL)
            self.extract_button.config(state=tk.NORMAL)
            self.status_label.config(text="Status: Image Uploaded", fg="green")

    def embed_watermark(self):
        """워터마크 삽입 요청"""
        if not self.image_path:
            messagebox.showerror("Error", "No image uploaded!")
            return

        try:
            # Prepare crypto package
            user_priv_pem = os.getenv("USER_PRIVATE_KEY")
            server_pub_pem = os.getenv("SERVER_PUBLIC_KEY")
            if not all([user_priv_pem, server_pub_pem]):
                messagebox.showerror("Error", "Missing required keys in .env")
                return

            crypto_package = prepare_crypto_package(
                self.image_path,
                self.user_id,
                user_priv_pem,
                server_pub_pem
            )

            # Send request with crypto package
            files = {"image": open(self.image_path, "rb")}
            data = {
                "user_id": self.user_id,
                "crypto_package": json.dumps(crypto_package)
            }

            response = requests.post(f"{SERVER_URL}/watermark/", files=files, data=data)
            
            if response.status_code == 200:
                with open("watermarked_image.jpg", "wb") as f:
                    f.write(response.content)
                self.status_label.config(text="Status: Watermark Embedded Successfully", fg="green")
                messagebox.showinfo("Success", "Watermark embedded successfully! Saved as 'watermarked_image.jpg'.")
            else:
                self.status_label.config(text="Status: Failed to Embed Watermark", fg="red")
                messagebox.showerror("Error", f"Failed to embed watermark: {response.text}")

        except Exception as e:
            self.status_label.config(text="Status: Error Occurred", fg="red")
            messagebox.showerror("Error", f"An error occurred: {e}")

    def extract_watermark(self):
        """워터마크 추출 요청"""
        if not self.image_path:
            messagebox.showerror("Error", "No image uploaded!")
            return

        files = {"image": open(self.image_path, "rb")}
        data = {
            "user_id": self.user_id
        }

        try:
            response = requests.post(f"{SERVER_URL}/extract-watermark/", files=files, data=data)
            if response.status_code == 200:
                watermark_text = response.json().get("watermark_text", "No watermark found")
                self.status_label.config(text=f"Status: Watermark Extracted: {watermark_text}", fg="green")
                messagebox.showinfo("Extracted Watermark", f"Watermark: {watermark_text}")
            else:
                self.status_label.config(text="Status: Failed to Extract Watermark", fg="red")
                messagebox.showerror("Error", f"Failed to extract watermark: {response.text}")
        except Exception as e:
            self.status_label.config(text="Status: Error Occurred", fg="red")
            messagebox.showerror("Error", f"An error occurred: {e}")

    def exchange_keys(self):
        """Perform key exchange with server"""
        try:
            app_key = self.api_entry.get().strip()
            if not app_key:
                messagebox.showerror("Error", "Please enter API key")
                return

            # Generate client keys
            private_key, public_key = generate_rsa_key_pair()
            
            # Convert keys to PEM format and save to .env
            env_path = ".env"
            set_key(env_path, "USER_PRIVATE_KEY", convert_private_key_to_pem(private_key))
            public_key_pem = convert_public_key_to_pem(public_key)
            
            # Send to server using JSON body instead of query params
            response = requests.put(
                f"{SERVER_URL}/user/{self.user_id}",
                json={
                    "app_key": app_key,
                    "user_public_key": public_key_pem,
                    "password_img": 111111,
                    "password_wm": 222222
                }
            )
            
            if response.status_code == 200:
                # Decrypt and save server's public key
                sp_public_key_pem = response.json()["sp_public_key"]
                set_key(env_path, "SERVER_PUBLIC_KEY", sp_public_key_pem)
                
                self.status_label.config(text="Status: Key Exchange Successful", fg="green")
                messagebox.showinfo("Success", "Key exchange completed successfully")
            else:
                self.status_label.config(text="Status: Key Exchange Failed", fg="red")
                messagebox.showerror("Error", f"Key exchange failed: {response.text}")

        except Exception as e:
            self.status_label.config(text="Status: Key Exchange Error", fg="red")
            messagebox.showerror("Error", f"An error occurred: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    # Set window size and position it at the center of the screen
    window_width = 800
    window_height = 600
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    center_x = int(screen_width/2 - window_width/2)
    center_y = int(screen_height/2 - window_height/2)
    root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
    root.resizable(False, False)  # Prevent window resizing
    app = WatermarkApp(root)
    root.mainloop()