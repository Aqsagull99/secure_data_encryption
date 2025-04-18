import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import time
from datetime import datetime, timedelta
import json
import os
import base64

# Configuration
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds
DATA_FILE = "encrypted_data.json"
MASTER_PASSWORD = "admin123"  # In production, use environment variables or proper auth

# Generate or load encryption key
def get_fernet_key():
    if os.path.exists("secret.key"):
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        return key

KEY = get_fernet_key()
cipher = Fernet(KEY)

# Load or initialize data storage
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

stored_data = load_data()

# Session state management
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'locked_until' not in st.session_state:
    st.session_state.locked_until = 0
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"

# Security functions
# Simple fixed salt for learning (not secure for production)
FIXED_SALT = b'mysalt1234567890'  # 16 bytes

def hash_passkey(passkey):
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), FIXED_SALT, 100000).hex()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# UI Functions
def set_bg_hack(main_bg):
    main_bg_ext = "png"
    st.markdown(
        f"""
        <style>
        .stApp {{
            background: url(data:image/{main_bg_ext};base64,{base64.b64encode(open(main_bg, "rb").read()).decode()});
            background-size: cover;
        }}
        </style>
        """,
        unsafe_allow_html=True
    )

def styled_button(label, key=None):
    st.markdown(
        f"""
        <style>
        div.stButton > button:first-child {{
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 10px 24px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            margin: 4px 2px;
            cursor: pointer;
            border-radius: 12px;
            transition: all 0.3s ease;
        }}
        div.stButton > button:first-child:hover {{
            background-color: #45a049;
            box-shadow: 0 4px 8px 0 rgba(0,0,0,0.2);
        }}
        </style>
        """,
        unsafe_allow_html=True
    )
    return st.button(label, key=key)

# Pages
def home_page():
    st.title("🔒 Secure Data Vault")
    st.markdown("""
    <style>
    .big-font {
        font-size:18px !important;
    }
    </style>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns([1, 1])
    with col1:
        st.image("https://cdn-icons-png.flaticon.com/512/295/295128.png", width=150)
        if styled_button("Store New Data", key="store_btn"):
            st.session_state.current_page = "Store Data"
            st.rerun()
    
    with col2:
        st.image("https://cdn-icons-png.flaticon.com/512/295/295129.png", width=150)
        if styled_button("Retrieve Data", key="retrieve_btn"):
            st.session_state.current_page = "Retrieve Data"
            st.rerun()
    
    st.markdown("""
    ### How it works:
    1. **Store Data**: Encrypt your sensitive information with a strong passkey
    2. **Retrieve Data**: Decrypt your data using the same passkey
    3. **Security**: After 3 failed attempts, the system will lock for 5 minutes
    """)

def store_data_page():
    st.title("📦 Store Data Securely")
    st.markdown('<div class="big-font">Enter your sensitive data and a strong passkey to encrypt and store it.</div>', unsafe_allow_html=True)
    
    data_id = st.text_input("Data Identifier (e.g., 'my_secret_note')", help="A unique name to identify your data")
    user_data = st.text_area("Data to Encrypt", height=150)
    passkey = st.text_input("Passkey", type="password", help="Choose a strong passkey you'll remember")
    passkey_confirm = st.text_input("Confirm Passkey", type="password")
    
    col1, col2 = st.columns([1, 3])
    with col1:
        if styled_button("Encrypt & Store"):
            if not data_id or not user_data or not passkey:
                st.error("All fields are required!")
            elif passkey != passkey_confirm:
                st.error("Passkeys don't match!")
            elif len(passkey) < 8:
                st.error("Passkey must be at least 8 characters long!")
            else:
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data)
                
                stored_data[data_id] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey,
                    "created_at": str(datetime.now())
                }
                save_data(stored_data)
                
                st.success("✅ Data stored securely!")
                st.markdown(f"""
                **Your Data ID**: `{data_id}`  
                **Created At**: {stored_data[data_id]['created_at']}  
                
                ⚠️ **Important**: You'll need both the Data ID and Passkey to retrieve this data.  
                Store them in a safe place!
                """)
    
    with col2:
        if styled_button("Back to Home"):
            st.session_state.current_page = "Home"
            st.rerun()

def retrieve_data_page():
    st.title("🔍 Retrieve Your Data")
    
    if st.session_state.locked_until > time.time():
        remaining_time = int(st.session_state.locked_until - time.time())
        st.error(f"🔒 System locked due to too many failed attempts. Please try again in {remaining_time} seconds.")
        if styled_button("Back to Home"):
            st.session_state.current_page = "Home"
            st.rerun()
        return
    
    st.markdown('<div class="big-font">Enter your Data ID and passkey to decrypt your data.</div>', unsafe_allow_html=True)
    
    data_id = st.text_input("Data Identifier")
    passkey = st.text_input("Passkey", type="password")
    
    col1, col2 = st.columns([1, 3])
    with col1:
        if styled_button("Decrypt Data"):
            if not data_id or not passkey:
                st.error("Both fields are required!")
            elif data_id not in stored_data:
                st.error("Data ID not found!")
            else:
                data_entry = stored_data[data_id]
                hashed_passkey = hash_passkey(passkey)
                
                if hashed_passkey == data_entry["passkey"]:
                    decrypted_text = decrypt_data(data_entry["encrypted_text"])
                    if decrypted_text:
                        st.session_state.failed_attempts = 0
                        st.success("✅ Successfully decrypted!")
                        
                        st.markdown(f"""
                        **Data ID**: `{data_id}`  
                        **Created At**: {data_entry['created_at']}  
                        **Your Data**:  
                        """)
                        st.text_area("Decrypted Data", value=decrypted_text, height=200, disabled=True)
                    else:
                        st.error("Decryption failed!")
                else:
                    st.session_state.failed_attempts += 1
                    remaining_attempts = MAX_ATTEMPTS - st.session_state.failed_attempts
                    
                    if remaining_attempts > 0:
                        st.error(f"❌ Incorrect passkey! {remaining_attempts} attempts remaining.")
                    else:
                        st.session_state.locked_until = time.time() + LOCKOUT_TIME
                        st.error("🔒 Too many failed attempts! System locked for 5 minutes.")
    
    with col2:
        if styled_button("Back to Home"):
            st.session_state.current_page = "Home"
            st.rerun()

def login_page():
    st.title("🔑 Reauthorization Required")
    st.warning("Too many failed attempts. Please authenticate to continue.")
    
    password = st.text_input("Master Password", type="password")
    
    if styled_button("Authenticate"):
        if password == MASTER_PASSWORD:
            st.session_state.failed_attempts = 0
            st.session_state.locked_until = 0
            st.session_state.authenticated = True
            st.success("✅ Authentication successful! Redirecting...")
            time.sleep(1)
            st.session_state.current_page = "Retrieve Data"
            st.rerun()
        else:
            st.error("❌ Incorrect password!")

# Main App
def main():
    # Custom CSS for better UI
    st.set_page_config(
        page_title="Secure Data Vault",
        page_icon="🔒",
        layout="centered",
        initial_sidebar_state="collapsed"
    )
    
    # Hide the sidebar
    st.markdown("""
    <style>
        section[data-testid="stSidebar"] {
            display: none !important;
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Navigation
    if st.session_state.current_page == "Home":
        home_page()
    elif st.session_state.current_page == "Store Data":
        store_data_page()
    elif st.session_state.current_page == "Retrieve Data":
        if st.session_state.failed_attempts >= MAX_ATTEMPTS and not st.session_state.authenticated:
            login_page()
        else:
            retrieve_data_page()
    elif st.session_state.current_page == "Login":
        login_page()

if __name__ == "__main__":
    main()








