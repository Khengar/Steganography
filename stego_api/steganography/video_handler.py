import os
import subprocess
from .audio_handler import hide_message_in_audio, extract_message_from_audio

TEMP_AUDIO_FILENAME = "temp_audio.wav"
MODIFIED_AUDIO_FILENAME = "modified_audio.wav"


def hide_message_in_video(video_path: str, message: bytes, output_path: str):
    """
    Hides a message in a video's audio track using direct ffmpeg commands.
    """
    # 1. Extract the audio track using ffmpeg
    extract_command = [
        'ffmpeg',
        '-i', video_path,
        '-vn', # No video
        '-acodec', 'pcm_s16le', # Use WAV format
        '-y', # Overwrite output file if it exists
        TEMP_AUDIO_FILENAME
    ]
    subprocess.run(extract_command, check=True, capture_output=True)

    # 2. Use our audio handler to hide the message in the extracted audio
    hide_message_in_audio(TEMP_AUDIO_FILENAME, message, MODIFIED_AUDIO_FILENAME)

    # 3. Replace the original audio with our modified audio
    replace_command = [
        'ffmpeg',
        '-i', video_path,       # Original video input
        '-i', MODIFIED_AUDIO_FILENAME, # Modified audio input
        '-c:v', 'copy',         # Copy the video stream without re-encoding
        '-c:a', 'copy',         # <-- THIS IS THE FIX: Copy the audio stream too
        '-map', '0:v:0',        # Map the video stream from the first input
        '-map', '1:a:0',        # Map the audio stream from the second input
        '-y',                   # Overwrite output file if it exists
        output_path
    ]
    subprocess.run(replace_command, check=True, capture_output=True)

    # 4. Clean up temporary files
    os.remove(TEMP_AUDIO_FILENAME)
    os.remove(MODIFIED_AUDIO_FILENAME)


def extract_message_from_video(video_path: str):
    """
    Extracts a hidden message from a video's audio track using ffmpeg.
    """
    # 1. Extract the audio track to a temporary file
    extract_command = [
        'ffmpeg',
        '-i', video_path,
        '-vn',
        '-acodec', 'pcm_s16le',
        '-y',
        TEMP_AUDIO_FILENAME
    ]
    subprocess.run(extract_command, check=True, capture_output=True)

    # 2. Use our audio handler to extract the message
    try:
        message = extract_message_from_audio(TEMP_AUDIO_FILENAME)
    finally:
        # 3. Ensure the temporary file is always cleaned up
        os.remove(TEMP_AUDIO_FILENAME)

    return message