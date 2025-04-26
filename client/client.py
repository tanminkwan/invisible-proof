import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk, ImageOps
import requests
import json
import logging
from dotenv import load_dotenv, set_key
from library.cryto_tools import (
    generate_rsa_key_pair,
    convert_private_key_to_pem,
    convert_public_key_to_pem,
    decrypt_server_public_key,
    prepare_crypto_package
)
import base64

# Load environment variables
load_dotenv()

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout  # 파일 핸들러 제거하고 stdout으로만 출력
)
logger = logging.getLogger(__name__)

class WatermarkApp:
    def __init__(self, root, user_id=None, server_url=None):
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

        self.user_id = user_id
        self.server_url = server_url
        
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
            logger.info("Starting watermark embedding process")
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

            response = requests.post(f"{self.server_url}/watermark/", files=files, data=data)
            
            if response.status_code == 200:
                response_data = response.json()
                logger.info("Server Response Data:")
                logger.info(f"  Timestamp: {response_data['gen_time']}")
                logger.info(f"  Filename: {response_data['filename']}")
                logger.info(f"  TSQ Length: {len(response_data['tsq'])} bytes")
                logger.info(f"  TSR Length: {len(response_data['tsr'])} bytes")
                logger.info(f"  TSA Cert Available: {bool(response_data['tsa_cert'])}")
                logger.info(f"  TSA CA Available: {bool(response_data['tsa_ca'])}")
                
                # Save image from base64
                image_bytes = base64.b64decode(response_data["image"])
                with open(response_data['filename'], "wb") as f:
                    f.write(image_bytes)
                logger.info("Watermarked image saved successfully")
                    
                gen_time = response_data["gen_time"]
                status_text = f"Status: Watermark Embedded Successfully\nTimestamp: {gen_time}"
                self.status_label.config(text=status_text, fg="green")
                messagebox.showinfo("Success", 
                    f"Watermark embedded successfully!\n"
                    f"Timestamp: {gen_time}\n"
                    f"Saved as '{response_data['filename']}'")
            else:
                logger.error(f"Server returned error: {response.status_code}")
                logger.error(f"Error details: {response.text}")
                self.status_label.config(text="Status: Failed to Embed Watermark", fg="red")
                messagebox.showerror("Error", f"Failed to embed watermark: {response.text}")

        except Exception as e:
            logger.exception("Error during watermark embedding")
            self.status_label.config(text="Status: Error Occurred", fg="red")
            messagebox.showerror("Error", f"An error occurred: {e}")

    def extract_watermark(self):
        """워터마크 추출 요청"""
        if not self.image_path:
            messagebox.showerror("Error", "No image uploaded!")
            return

        logger.info("Starting watermark extraction process")
        files = {"image": open(self.image_path, "rb")}
        data = {
            "user_id": self.user_id
        }

        try:
            response = requests.post(f"{self.server_url}/extract-watermark/", files=files, data=data)
            if response.status_code == 200:
                watermark_text = response.json().get("watermark_text", "No watermark found")
                logger.info(f"Extracted watermark: {watermark_text}")
                self.status_label.config(text=f"Status: Watermark Extracted: {watermark_text}", fg="green")
                messagebox.showinfo("Extracted Watermark", f"Watermark: {watermark_text}")
            else:
                logger.error(f"Extraction failed with status code: {response.status_code}")
                self.status_label.config(text="Status: Failed to Extract Watermark", fg="red")
                messagebox.showerror("Error", f"Failed to extract watermark: {response.text}")
        except Exception as e:
            logger.exception("Error during watermark extraction")
            self.status_label.config(text="Status: Error Occurred", fg="red")
            messagebox.showerror("Error", f"An error occurred: {e}")

    def exchange_keys(self):
        """Perform key exchange with server"""
        try:
            logger.info("Starting key exchange process")
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
                f"{self.server_url}/user/{self.user_id}",
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
                
                logger.info("Key exchange successful")
                self.status_label.config(text="Status: Key Exchange Successful", fg="green")
                messagebox.showinfo("Success", "Key exchange completed successfully")
            else:
                logger.error(f"Key exchange failed with status code: {response.status_code}")
                self.status_label.config(text="Status: Key Exchange Failed", fg="red")
                messagebox.showerror("Error", f"Key exchange failed: {response.text}")

        except Exception as e:
            logger.exception("Error during key exchange")
            self.status_label.config(text="Status: Key Exchange Error", fg="red")
            messagebox.showerror("Error", f"An error occurred: {e}")


if __name__ == "__main__":

    user_id = os.getenv("USER_ID")
    server_url = os.getenv("SERVER_URL")

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
    app = WatermarkApp(root, user_id=user_id, server_url=server_url)
    root.mainloop()