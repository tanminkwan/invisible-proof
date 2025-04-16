# Invisible Proof - Watermark Library

## Overview
This project provides functionality to embed and extract watermarks in images using the `blind_watermark` package.

## Requirements
- Python 3.x
- OpenCV (`pip install opencv-python`)
- blind_watermark (`pip install blind-watermark`)
- FastAPI (`pip install fastapi`)
- Uvicorn (`pip install uvicorn`)

## How to Run

### Running the Server
1. Open a terminal in `c:\GitHub\invisible-proof`.
2. Run the server with:
   ```bash
   uvicorn server.server:app --reload
   ```
   This starts the FastAPI server at http://127.0.0.1:8000.

### Running the Client
1. Open a terminal in `c:\GitHub\invisible-proof\client`.
2. Run the client with:
   ```bash
   python client.py
   ```
   This opens the GUI where you can upload an image, embed a watermark, and extract it.

## Modifications
- Adjust input/output image names and watermark text directly in `library/watermark.py` as needed.
