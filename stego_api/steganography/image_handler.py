# steganography/image_handler.py

from PIL import Image
import numpy as np
import struct # Import for packing/unpacking length

# No need for STOP_INDICATOR anymore with length-based embedding

def hide_message_in_image(image_path: str, message: bytes, output_path: str):
    print(f"DEBUG: HIDE - Input image path: {image_path}, raw message length (bytes): {len(message)}, output path: {output_path}")

    # 1. Prepend message with its length (e.g., 4 bytes for length)
    message_length = len(message)
    # Use struct.pack to convert integer length to 4 bytes
    # '>I' means Big-endian, unsigned int. Adjust if your message length can exceed 4 billion bytes.
    length_prefix = struct.pack('>I', message_length) 

    data_to_hide_with_length = length_prefix + message

    print(f"DEBUG: HIDE - Length prefix: {length_prefix.hex()}, total data to hide (bytes): {len(data_to_hide_with_length)}")

    img = Image.open(image_path, 'r')
    print(f"DEBUG: HIDE - Original image mode: {img.mode}, size: {img.size}")

    if img.mode == 'P':
        print("DEBUG: HIDE - Converting palette image to RGBA.")
        img = img.convert("RGBA")

    img_arr = np.array(list(img.getdata()), dtype=np.uint8) 

    if len(img_arr.shape) == 1: channels = 1
    else: channels = img_arr.shape[1]
    pixels_count = img_arr.shape[0]

    byte_message_bin = ''.join(f"{byte:08b}" for byte in data_to_hide_with_length) # Now contains length prefix + message
    data_len_bits = len(byte_message_bin)

    total_bits_available = pixels_count * channels 

    print(f"DEBUG: HIDE - Image array shape: {img_arr.shape}, dtype: {img_arr.dtype}, channels: {channels}, pixels_count: {pixels_count}")
    print(f"DEBUG: HIDE - Binary string length (bits): {data_len_bits}")
    print(f"DEBUG: HIDE - Image capacity (bits): {total_bits_available}")

    if data_len_bits > total_bits_available:
        raise ValueError(f"Data is too large to hide in this image. Needed {data_len_bits} bits, but only {total_bits_available} available.")

    data_index = 0
    for i in range(pixels_count): 
        if data_index >= data_len_bits: 
            break

        pixel = img_arr[i] 

        for j in range(channels): 
            if data_index < data_len_bits:
                original_channel_val = pixel[j]
                lsb_bit = byte_message_bin[data_index] 

                modified_channel_val = (original_channel_val & 0xFE) | int(lsb_bit, 2)
                pixel[j] = modified_channel_val

                data_index += 1
            else:
                break 

    print(f"DEBUG: HIDE - Total bits embedded: {data_index}")

    output_mode = img.mode 
    if len(img_arr.shape) == 1 and channels == 1: 
        final_img_arr = img_arr.reshape((img.size[1], img.size[0])) 
        output_mode = 'L'
    elif len(img_arr.shape) == 2: 
         final_img_arr = img_arr.reshape((img.size[1], img.size[0], channels))
         output_mode = img.mode 
    else:
         final_img_arr = img_arr
         output_mode = img.mode


    result_img = Image.fromarray(final_img_arr.astype('uint8'), output_mode)
    result_img.save(output_path)
    print(f"DEBUG: HIDE - Image saved to {output_path}")


def extract_message_from_image(image_path: str):
    print(f"DEBUG: EXTRACT - Input image path: {image_path}")
    img = Image.open(image_path, 'r')
    print(f"DEBUG: EXTRACT - Image mode: {img.mode}, size: {img.size}")

    if img.mode == 'P':
        img = img.convert("RGBA") 

    img_arr = np.array(list(img.getdata()), dtype=np.uint8) 
    print(f"DEBUG: EXTRACT - Image array shape: {img_arr.shape}, dtype: {img_arr.dtype}")

    if len(img_arr.shape) == 1: channels = 1 
    else: channels = img_arr.shape[1]
    pixels_count = img_arr.shape[0]

    binary_data = ""
    # Need to extract length first (e.g., 4 bytes = 32 bits)
    length_prefix_bits_count = 32 # 4 bytes * 8 bits/byte

    max_extract_bits = pixels_count * channels
    extracted_bits_count = 0

    # Extract the length prefix first
    for i in range(pixels_count):
        if extracted_bits_count >= length_prefix_bits_count:
            break # Stop once we have enough bits for the length prefix
        pixel = img_arr[i]
        for j in range(channels):
            if extracted_bits_count < length_prefix_bits_count:
                binary_data += bin(pixel[j])[-1]
                extracted_bits_count += 1
            else:
                break

    if len(binary_data) < length_prefix_bits_count:
        raise ValueError(f"Not enough hidden bits to read message length. Expected {length_prefix_bits_count}, got {len(binary_data)}.")

    # Convert binary length prefix to integer
    message_length = struct.unpack('>I', int(binary_data[:length_prefix_bits_count], 2).to_bytes(4, byteorder='big'))[0]

    print(f"DEBUG: EXTRACT - Extracted message length from header: {message_length} bytes.")

    # Now extract the actual message data
    # Continue from where we left off, for the remaining message_length bytes
    remaining_bits_to_extract = message_length * 8 # Message length in bits

    # Reset binary_data to continue appending, only with remaining useful bits
    binary_data = "" 
    # Continue loop from where length extraction stopped
    current_pixel_index = extracted_bits_count // channels
    current_channel_index = extracted_bits_count % channels

    total_actual_bits_extracted = 0

    for i in range(current_pixel_index, pixels_count):
        if total_actual_bits_extracted >= remaining_bits_to_extract:
            break
        pixel = img_arr[i]

        # Start from current_channel_index for the first pixel, then from 0 for subsequent
        start_j = current_channel_index if i == current_pixel_index else 0

        for j in range(start_j, channels):
            if total_actual_bits_extracted < remaining_bits_to_extract:
                binary_data += bin(pixel[j])[-1]
                total_actual_bits_extracted += 1
            else:
                break

        if total_actual_bits_extracted > 0 and total_actual_bits_extracted % 100000 == 0:
            print(f"DEBUG: EXTRACT - Processed {total_actual_bits_extracted} message bits.")

    if total_actual_bits_extracted < remaining_bits_to_extract:
        raise ValueError(f"Incomplete message extracted. Expected {remaining_bits_to_extract} bits, got {total_actual_bits_extracted}.")

    # Convert binary message string to bytes
    message_bytes = int(binary_data, 2).to_bytes(message_length, byteorder='big')
    print(f"DEBUG: EXTRACT - Extracted message length (bytes): {len(message_bytes)}")
    return message_bytes