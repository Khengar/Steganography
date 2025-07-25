from PIL import Image
import numpy as np

def hide_message_in_image(image_path: str, message: bytes, output_path: str):
    # Hides a byte message within an image using LSB steganography.
    img = Image.open(image_path, 'r')
    width, height = img.size
    img_arr = np.array(list(img.getdata()))

    if img.mode == 'P':
        print("Warning: Palette-based image, may not be ideal.")
        img = img.convert("RGBA")
        img_arr = np.array(list(img.getdata()))

    channels = 4 if img.mode == 'RGBA' else 3
    pixels = img_arr.size // channels

    # Add a delimiter to know when the message ends
    stop_indicator = b'--STOP--'
    message += stop_indicator

    byte_message = ''.join(f"{byte:08b}" for byte in message)
    data_len = len(byte_message)

    if data_len > pixels:
        raise ValueError("Data is too large to hide in this image.")

    data_index = 0
    for i in range(pixels):
        if data_index < data_len:
            pixel = img_arr[i]
            for j in range(channels):
                if data_index < data_len:
                    # Modify the least significant bit
                    pixel[j] = int(bin(pixel[j])[2:-1] + byte_message[data_index], 2)
                    data_index += 1
        else:
            break

    img_arr = img_arr.reshape((height, width, channels))
    result_img = Image.fromarray(img_arr.astype('uint8'), img.mode)
    result_img.save(output_path)

def extract_message_from_image(image_path: str):
    """Extracts a hidden byte message from an image."""
    img = Image.open(image_path, 'r')
    img_arr = np.array(list(img.getdata()))
    channels = 4 if img.mode == 'RGBA' else 3
    pixels = img_arr.size // channels

    binary_data = ""
    stop_indicator = b'--STOP--'
    stop_indicator_bin = ''.join(f"{byte:08b}" for byte in stop_indicator)

    for i in range(pixels):
        pixel = img_arr[i]
        for j in range(channels):
            binary_data += bin(pixel[j])[-1]
        # Check if the stop indicator is found
        if stop_indicator_bin in binary_data:
            # Remove the stop indicator and any extra bits
            message_bin = binary_data.split(stop_indicator_bin, 1)[0]
            # Convert binary string to bytes
            message_bytes = int(message_bin, 2).to_bytes((len(message_bin) + 7) // 8, byteorder='big')
            return message_bytes

    raise ValueError("Could not find a hidden message.")