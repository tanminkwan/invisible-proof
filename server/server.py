from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import FileResponse, JSONResponse
import shutil
import os
from library.watermark import embed_watermark, extract_watermark

app = FastAPI()

# Temporary directory for saving uploaded files
TEMP_DIR = "temp"
os.makedirs(TEMP_DIR, exist_ok=True)

@app.post("/embed-watermark/")
async def embed_watermark_api(
    image: UploadFile = File(...), 
    watermark_text: str = Form(...)
):
    """
    API to embed a watermark into an image.
    """
    input_path = os.path.join(TEMP_DIR, image.filename)
    output_path = os.path.join(TEMP_DIR, f"watermarked_{image.filename}")

    # Save the uploaded image to the temp directory
    with open(input_path, "wb") as buffer:
        shutil.copyfileobj(image.file, buffer)

    # Embed the watermark
    embed_watermark(input_path, watermark_text, output_path)

    # Return the watermarked image
    return FileResponse(output_path, media_type="image/jpeg", filename=f"watermarked_{image.filename}")


@app.post("/extract-watermark/")
async def extract_watermark_api(
    image: UploadFile = File(...)
):
    """
    API to extract a watermark from an image.
    """
    input_path = os.path.join(TEMP_DIR, image.filename)

    # Save the uploaded image to the temp directory
    with open(input_path, "wb") as buffer:
        shutil.copyfileobj(image.file, buffer)

    # Extract the watermark with a fixed length of 215
    len_wm = 215
    extracted_text = extract_watermark(input_path, len_wm)

    # Return the extracted watermark text
    return JSONResponse(content={"watermark_text": extracted_text})