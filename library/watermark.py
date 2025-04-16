import cv2
from blind_watermark  import WaterMark
import logging

def embed_watermark(input_image, watermark_text, output_image):
    
    # 워터마크 인코더 생성 및 워터마크 설정 (문자열을 bytes로 인코딩)
    encoder = WaterMark(password_img=1, password_wm=1)
    encoder.read_img(input_image)


    encoder.read_wm(watermark_text, mode='str')
    encoder.embed(output_image)

    logging.debug(f'Put down the length of wm_bit {len(encoder.wm_bit)}')
    return len(encoder.wm_bit)


def extract_watermark(image_path, len_wm=32):

    # 워터마크가 삽입된 이미지를 읽어옵니다.
    decoder = WaterMark(password_img=1, password_wm=1)
    wm_extract = decoder.extract(image_path, wm_shape=len_wm, mode='str')
    logging.debug(f'Extracted text : {wm_extract}')
    return wm_extract

if __name__ == "__main__":
    input_image = "3races2.jpg"         # 원본 이미지 파일 (예: test.png)
    output_image = "test_wm.jpg"       # 워터마크 삽입 후 저장할 파일
    watermark_text = "Hellow Tanminkwan"            
    
    len_wm = embed_watermark(input_image, watermark_text, output_image)
    extract_watermark(output_image, len_wm)