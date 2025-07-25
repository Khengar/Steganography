from pydub import AudioSegment

AudioSegment.converter = "C:\\Users\\WINN\\AppData\\Local\\Microsoft\\WinGet\\Packages\\Gyan.FFmpeg.Essentials_Microsoft.Winget.Source_8wekyb3d8bbwe\\ffmpeg-7.1.1-essentials_build\\bin\\ffmpeg.exe"

def hide_message_in_audio(audio_path: str, message: bytes, output_path: str):
    """Hides a byte message within an audio file (e.g., MP3, WAV) and saves as WAV."""
    # from_file can handle multiple formats like mp3, wav, etc.
    audio = AudioSegment.from_file(audio_path)
    
    # Work with the raw audio data
    audio_bytes = bytearray(audio.raw_data)
    
    stop_indicator = b'--STOP--'
    message += stop_indicator
    byte_message = ''.join(f"{byte:08b}" for byte in message)
    data_len = len(byte_message)

    if data_len > len(audio_bytes) * 8:
        raise ValueError("Data is too large to hide in this audio file.")

    data_index = 0
    for i in range(len(audio_bytes)):
        if data_index < data_len:
            audio_bytes[i] = (audio_bytes[i] & 0b11111110) | int(byte_message[data_index], 2)
            data_index += 1
        else:
            break
            
    # Create a new AudioSegment from the modified bytes
    modified_audio = audio._spawn(audio_bytes)
    # Export as WAV to ensure data integrity
    modified_audio.export(output_path, format="wav")


def extract_message_from_audio(audio_path: str):
    """Extracts a hidden byte message from a WAV audio file."""
    audio = AudioSegment.from_wav(audio_path)
    audio_bytes = audio.raw_data
    
    stop_indicator = b'--STOP--'
    stop_indicator_len = len(stop_indicator) * 8

    # Use a list to collect message bits for efficiency
    message_bits = []
    
    # Iterate through the audio bytes to extract LSBs
    for byte in audio_bytes:
        message_bits.append(bin(byte)[-1])
        
        # Check if the last collected bits match the stop indicator
        if len(message_bits) >= stop_indicator_len:
            # Join only the relevant tail of the list for checking
            last_bits = "".join(message_bits[-stop_indicator_len:])
            if last_bits == ''.join(f"{b:08b}" for b in stop_indicator):
                # Found the indicator, now assemble the final message
                final_bits = "".join(message_bits[:-stop_indicator_len])
                message_bytes = int(final_bits, 2).to_bytes((len(final_bits) + 7) // 8, byteorder='big')
                return message_bytes

    raise ValueError("Could not find a hidden message or stop indicator.")