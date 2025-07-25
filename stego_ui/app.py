import streamlit as st
import requests
import os

# --- Configuration ---
API_URL = "http://127.0.0.1:5000" # URL of our Flask API server

# --- UI Setup ---
st.set_page_config(page_title="StegoSleuth", layout="centered")
st.title("🕵️ StegoSleuth: The Secret Messenger")

# --- Helper Functions ---
def handle_response(response, mode):
    """Helper to display API responses."""
    if response.status_code == 200:
        res_json = response.json()
        if mode == 'embed':
            st.success(res_json.get("message", "Success!"))
            st.code(res_json.get("encryption_key_hex"), language="text")
            st.info(res_json.get("note", "Save this key to extract the message later!"))
        elif mode == 'extract':
            st.success("Message extracted successfully!")
            st.text_area("Recovered Message", value=res_json.get("secret_message"), height=200)
    else:
        try:
            error_data = response.json()
            st.error(f"Error: {error_data.get('error', 'An unknown error occurred.')}")
        except requests.exceptions.JSONDecodeError:
            st.error(f"An unexpected error occurred (Status code: {response.status_code}).")
            st.text(response.text)

# --- Main Application ---
with st.sidebar:
    st.header("Controls")
    operation_mode = st.radio("Choose Operation", ("Embed", "Extract"))
    media_type = st.selectbox("Select Media Type", ("Image", "Audio", "Video"))

st.header(f"{operation_mode} a Message in an {media_type}")

# --- Embed Logic ---
if operation_mode == "Embed":
    with st.form("embed_form"):
        secret_message = st.text_area("Enter your secret message:", height=150)
        uploaded_file = st.file_uploader(f"Upload your cover {media_type}", type=None)
        
        # This button is now inside the form
        submitted = st.form_submit_button(f"Embed in {media_type}")

        if submitted:
            if uploaded_file and secret_message:
                with st.spinner("Processing... This might take a moment."):
                    endpoint = f"/embed{'_' + media_type.lower() if media_type != 'Image' else ''}"
                    files = {media_type.lower(): (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)}
                    data = {'message': secret_message}
                    
                    try:
                        response = requests.post(f"{API_URL}{endpoint}", files=files, data=data)
                        handle_response(response, 'embed')
                    except requests.exceptions.RequestException as e:
                        st.error(f"API connection error: {e}")
            else:
                st.warning("Please provide both a file and a secret message.")

# --- Extract Logic ---
elif operation_mode == "Extract":
    with st.form("extract_form"):
        encryption_key = st.text_input("Enter your encryption key:")
        uploaded_file = st.file_uploader(f"Upload your stego {media_type}", type=None)
        
        # This button is now inside the form
        submitted = st.form_submit_button(f"Extract from {media_type}")

        if submitted:
            if uploaded_file and encryption_key:
                with st.spinner("Processing... This might take a moment."):
                    endpoint = f"/extract{'_' + media_type.lower() if media_type != 'Image' else ''}"
                    files = {media_type.lower(): (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)}
                    data = {'key': encryption_key}

                    try:
                        response = requests.post(f"{API_URL}{endpoint}", files=files, data=data)
                        handle_response(response, 'extract')
                    except requests.exceptions.RequestException as e:
                        st.error(f"API connection error: {e}")
            else:
                st.warning("Please provide both a file and the encryption key.")