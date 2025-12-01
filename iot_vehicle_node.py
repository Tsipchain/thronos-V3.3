import os
import time
import json
import random
import hashlib
import secrets
from PIL import Image, ImageDraw

# Configuration
VEHICLE_ID = "THR-CAR-" + secrets.token_hex(4).upper()
SECRET_KEY_FILE = "vehicle_key.json"
SOURCE_IMAGE = "PIC OF THE /images/Fire.jpg"
OUTPUT_IMAGE = "/images/Vehicle.jpg"

def load_or_create_key():
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, 'r') as f:
            return json.load(f)
    else:
        key_data = {
            "vehicle_id": VEHICLE_ID,
            "private_key": secrets.token_hex(32),
            "public_key": secrets.token_hex(32) # Simplified
        }
        with open(SECRET_KEY_FILE, 'w') as f:
            json.dump(key_data, f, indent=2)
        return key_data

def get_vehicle_data():
    # Simulate reading from OBD-II
    return {
        "timestamp": time.time(),
        "gps_lat": 37.9838 + random.uniform(-0.01, 0.01),
        "gps_lon": 23.7275 + random.uniform(-0.01, 0.01),
        "speed_kmh": random.randint(0, 120),
        "odometer": 12000 + random.randint(0, 100),
        "battery_level": random.randint(20, 100)
    }

def create_dummy_image(filename):
    img = Image.new('RGB', (800, 600), color = (73, 109, 137))
    d = ImageDraw.Draw(img)
    d.text((10,10), "Thronos IoT Vehicle Node", fill=(255,255,0))
    img.save(filename)

def encode_lsb(image_path, data_str, output_path):
    if not os.path.exists(image_path):
        print(f"Source image {image_path} not found. Creating dummy.")
        create_dummy_image(image_path)
        
    img = Image.open(image_path)
    encoded = img.copy()
    width, height = img.size
    pixels = encoded.load()
    
    # Convert data to binary
    binary_data = ''.join(format(ord(i), '08b') for i in data_str)
    data_len = len(binary_data)
    
    if data_len > width * height * 3:
        raise ValueError("Data too large for image")
        
    idx = 0
    for y in range(height):
        for x in range(width):
            if idx < data_len:
                r, g, b = pixels[x, y]
                
                # Modify LSB of Red channel
                if idx < data_len:
                    r = (r & ~1) | int(binary_data[idx])
                    idx += 1
                # Modify LSB of Green channel
                if idx < data_len:
                    g = (g & ~1) | int(binary_data[idx])
                    idx += 1
                # Modify LSB of Blue channel
                if idx < data_len:
                    b = (b & ~1) | int(binary_data[idx])
                    idx += 1
                    
                pixels[x, y] = (r, g, b)
            else:
                break
        if idx >= data_len:
            break
            
    encoded.save(output_path)
    return True

def main():
    keys = load_or_create_key()
    print(f"🚗 Vehicle Node Started: {keys['vehicle_id']}")
    
    # Run a single cycle for demonstration
    data = get_vehicle_data()
    data['vehicle_id'] = keys['vehicle_id']
    
    # Sign data (simplified hash)
    payload_str = json.dumps(data)
    signature = hashlib.sha256((payload_str + keys['private_key']).encode()).hexdigest()
    final_payload = json.dumps({"data": data, "sig": signature})
    
    print(f"📊 Telemetry: {data}")
    
    # Encode to Image
    try:
        encode_lsb(SOURCE_IMAGE, final_payload, OUTPUT_IMAGE)
        print(f"🖼️  Encoded data into {OUTPUT_IMAGE}")
    except Exception as e:
        print(f"❌ Encoding error: {e}")

if __name__ == "__main__":
    main()