import shutil
import os

def hide_message_in_video(video_path: str, message: bytes, output_path: str):
    """
    Hides a message by appending it to the end of the video file.
    This robust method avoids re-encoding.
    """
    # 1. Define a stop indicator to know where the message ends
    data_to_hide = message + b'--STOP--'
    data_len = len(data_to_hide)
    
    # 2. First, copy the original video to the output path
    shutil.copyfile(video_path, output_path)
    
    # 3. Now, append the actual data and its length to the end of the new file
    with open(output_path, 'ab') as f:
        f.write(data_to_hide)
        # We also write the length of the data (as 8 bytes) to make extraction easy
        f.write(data_len.to_bytes(8, 'big'))

def extract_message_from_video(video_path: str):
    """
    Extracts a message that was appended to the end of a video file.
    """
    with open(video_path, 'rb') as f:
        # 1. Seek to the end of the file minus 8 bytes to read the length
        f.seek(-8, os.SEEK_END)
        data_len_bytes = f.read(8)
        data_len = int.from_bytes(data_len_bytes, 'big')
        
        # 2. Seek back to the start of our hidden data block
        f.seek(-8 - data_len, os.SEEK_END)
        
        # 3. Read the exact length of our hidden data
        hidden_data = f.read(data_len)

        # 4. Verify and strip the stop indicator to get the original message
        stop_indicator = b'--STOP--'
        if hidden_data.endswith(stop_indicator):
            return hidden_data[:-len(stop_indicator)]
        else:
            raise ValueError("Could not find a valid message. Stop indicator missing.")