# =============================================================
# FINAL STREAMLIT STEGANOGRAPHY APP
# Supports: Text, Image, File, Audio, Video hiding in Image
# B.Tech CSE Major Project – Production Ready
# =============================================================

import streamlit as st
import cv2
import numpy as np
from cryptography.fernet import Fernet
import base64
import io
import random
import hashlib
from PIL import Image
import zipfile
import mimetypes

# =============================================================
# CONSTANTS & LIMITS
# =============================================================

MAX_MEDIA_SIZE_MB = 5
CONTENT_TEXT = 0
CONTENT_IMAGE = 1
CONTENT_FILE = 2
CONTENT_MEDIA = 3  # Audio / Video

# =============================================================
# CRYPTOGRAPHY & UTILITIES
# =============================================================

def generate_key(passcode: str) -> Fernet:
    key = base64.urlsafe_b64encode(passcode.ljust(32).encode()[:32])
    return Fernet(key)


def content_to_binary(content: bytes) -> str:
    return ''.join(format(byte, '08b') for byte in content)


def binary_to_content(binary_str: str) -> bytes | None:
    try:
        return bytes(int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8))
    except Exception:
        return None

# =============================================================
# RANDOMIZED LSB LOGIC
# =============================================================

def _get_pixel_order(img_shape, passcode):
    rows, cols, channels = img_shape
    seed = int(hashlib.sha256(passcode.encode()).hexdigest()[:8], 16)
    coords = [(i, j, c) for i in range(rows) for j in range(cols) for c in range(channels)]
    random.Random(seed).shuffle(coords)
    return coords

# =============================================================
# MEDIA HANDLING (AUDIO / VIDEO)
# =============================================================

def detect_media_type(filename):
    mime, _ = mimetypes.guess_type(filename)
    if mime:
        if mime.startswith('audio'): return 'A'
        if mime.startswith('video'): return 'V'
    return 'B'


def prepare_media_bytes(file):
    file.seek(0)
    data = file.read()
    size_mb = len(data) / (1024 * 1024)
    if size_mb > MAX_MEDIA_SIZE_MB:
        raise ValueError(f"Media file exceeds {MAX_MEDIA_SIZE_MB} MB limit")

    filename = file.name
    filename_bytes = filename.encode()
    media_flag = detect_media_type(filename).encode()

    header = bytes([CONTENT_MEDIA]) + media_flag + bytes([len(filename_bytes)]) + filename_bytes
    return header + data


def unpack_media_bytes(data: bytes):
    media_flag = data[0:1].decode()
    fname_len = data[1]
    filename = data[2:2+fname_len].decode()
    media_data = data[2+fname_len:]
    label = {'A': 'audio', 'V': 'video', 'B': 'file'}[media_flag]
    return media_data, filename, label

# =============================================================
# CORE STEGANOGRAPHY (HIDE)
# =============================================================

def hide_message_in_image(uploaded_file, content, passcode, content_type, filename=None):
    uploaded_file.seek(0)
    img = cv2.imdecode(np.frombuffer(uploaded_file.read(), np.uint8), cv2.IMREAD_COLOR)
    original_img = img.copy()

    if content_type == CONTENT_TEXT:
        content_bytes = content.encode()
        payload = bytes([CONTENT_TEXT]) + content_bytes

    elif content_type == CONTENT_IMAGE:
        content.seek(0)
        payload = bytes([CONTENT_IMAGE]) + content.read()

    elif content_type == CONTENT_FILE:
        content.seek(0)
        fname_bytes = filename.encode()
        payload = bytes([CONTENT_FILE]) + bytes([len(fname_bytes)]) + fname_bytes + content.read()

    elif content_type == CONTENT_MEDIA:
        payload = prepare_media_bytes(content)

    else:
        return None, None, "Unsupported content type"

    cipher = generate_key(passcode)
    encrypted = cipher.encrypt(payload)
    binary_data = content_to_binary(encrypted) + '1111111111111110'

    capacity = img.size
    if len(binary_data) > capacity:
        return None, None, "Carrier image capacity exceeded"

    pixel_order = _get_pixel_order(img.shape, passcode)
    idx = 0

    for i, j, c in pixel_order:
        if idx >= len(binary_data): break
        img[i, j, c] = int(format(img[i, j, c], '08b')[:-1] + binary_data[idx], 2)
        idx += 1

    ok, buffer = cv2.imencode('.png', img)
    return buffer.tobytes(), original_img, None

# =============================================================
# CORE STEGANOGRAPHY (EXTRACT)
# =============================================================

def extract_message_from_image(uploaded_file, passcode):
    uploaded_file.seek(0)
    img = cv2.imdecode(np.frombuffer(uploaded_file.read(), np.uint8), cv2.IMREAD_COLOR)
    binary = ''
    delimiter = '1111111111111110'

    for i, j, c in _get_pixel_order(img.shape, passcode):
        binary += format(img[i, j, c], '08b')[-1]
        if binary.endswith(delimiter):
            binary = binary[:-len(delimiter)]
            break

    encrypted = binary_to_content(binary)
    cipher = generate_key(passcode)
    decrypted = cipher.decrypt(encrypted)

    ctype = decrypted[0]
    data = decrypted[1:]

    if ctype == CONTENT_TEXT:
        return data.decode(), CONTENT_TEXT, None, None

    if ctype == CONTENT_IMAGE:
        return data, CONTENT_IMAGE, "image.png", None

    if ctype == CONTENT_FILE:
        fname_len = data[0]
        filename = data[1:1+fname_len].decode()
        return data[1+fname_len:], CONTENT_FILE, filename, None

    if ctype == CONTENT_MEDIA:
        media, filename, label = unpack_media_bytes(data)
        return media, CONTENT_MEDIA, filename, label

    return None, None, None, None

# =============================================================
# STREAMLIT UI
# =============================================================

st.set_page_config(page_title="Advanced Steganography", layout="wide")
st.title("🛡️ Advanced Image Steganography System")
st.caption("Text | Image | File | Audio | Video → Image (Encrypted)")

hide_tab, extract_tab = st.tabs(["Hide Content", "Extract Content"])

with hide_tab:
    carrier = st.file_uploader("Upload Carrier Image (PNG)", type=['png'])
    choice = st.radio("Content Type", ["Text", "Image", "File", "Audio / Video"])

    secret = None
    ctype = CONTENT_TEXT
    fname = None

    if choice == "Text":
        secret = st.text_area("Secret Text")
        ctype = CONTENT_TEXT
    elif choice == "Image":
        secret = st.file_uploader("Secret Image", type=['png', 'jpg'])
        ctype = CONTENT_IMAGE
    elif choice == "File":
        secret = st.file_uploader("Any File")
        ctype = CONTENT_FILE
        if secret: fname = secret.name
    else:
        secret = st.file_uploader("Audio / Video", type=['mp3', 'wav', 'mp4', 'avi', 'mkv'])
        ctype = CONTENT_MEDIA

    passcode = st.text_input("Passcode", type="password")

    if st.button("Hide Content") and carrier and secret and passcode:
        stego, _, err = hide_message_in_image(carrier, secret, passcode, ctype, fname)
        if err:
            st.error(err)
        else:
            st.success("Content hidden successfully")
            st.download_button("Download Stego Image", stego, "stego.png")

with extract_tab:
    stego_img = st.file_uploader("Upload Stego Image", type=['png'])
    passcode = st.text_input("Passcode", type="password", key="dec")

    if st.button("Extract") and stego_img and passcode:
        data, ctype, fname, label = extract_message_from_image(stego_img, passcode)

        if ctype == CONTENT_TEXT:
            st.text_area("Decrypted Text", data)
        elif ctype == CONTENT_IMAGE:
            st.image(data)
        elif ctype == CONTENT_FILE:
            st.download_button("Download File", data, fname)
        elif ctype == CONTENT_MEDIA:
            if label == 'audio': st.audio(data)
            if label == 'video': st.video(data)
            st.download_button("Download Media", data, fname)
