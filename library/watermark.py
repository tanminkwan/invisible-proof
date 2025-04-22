import cv2
from blind_watermark  import WaterMark
import logging

def embed_watermark(input_image, watermark_text, output_image, password_img, password_wm):
    # Create watermark encoder with provided passwords
    encoder = WaterMark(password_img=password_img, password_wm=password_wm)
    encoder.read_img(input_image)
    encoder.read_wm(watermark_text, mode='str')
    encoder.embed(output_image)
    logging.debug(f'Put down the length of wm_bit {len(encoder.wm_bit)}')
    return len(encoder.wm_bit)

def extract_watermark(image_path, password_img, password_wm, len_wm=32):
    # Create watermark decoder with provided passwords
    decoder = WaterMark(password_img=password_img, password_wm=password_wm)
    wm_extract = decoder.extract(image_path, wm_shape=len_wm, mode='str')
    logging.debug(f'Extracted text : {wm_extract}')
    return wm_extract

if __name__ == "__main__":
    input_image = r"E:\faces_pjt\3races2.jpg"         # 원본 이미지 파일 (예: test.png)
    output_image = "test_wm.jpg"       # 워터마크 삽입 후 저장할 파일
    watermark_text = "Certified by Tanminkwan Foundation Owned by tiffanie"  # 워터마크 텍스트
    password_img = 123456
    password_wm = 654321
    
    len_wm = embed_watermark(input_image, watermark_text, output_image, password_img, password_wm)
    text = extract_watermark(output_image, password_img, password_wm, len_wm)
    print(f"Extracted watermark: {len_wm} {text}")