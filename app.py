import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import json
import os

# Define the scope for accessing YouTube Data API
SCOPES = ['https://www.googleapis.com/auth/youtube.readonly']

def authenticate_and_get_token(client_secrets_file):
    """Authenticate the user and get the access token."""
    # OAuth 2.0 flow configuration
    flow = InstalledAppFlow.from_client_secrets_file(client_secrets_file, SCOPES)
    
    # Run the OAuth 2.0 flow
    creds = flow.run_local_server(port=0)
    
    # Save the credentials
    credentials = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }
    
    return credentials

def main():
    st.title("YouTube Data API Access Token Generator")

    st.write("Upload your `client_secrets.json` file to obtain an access token.")

    uploaded_file = st.file_uploader("Choose a file", type="json")

    if uploaded_file is not None:
        # Save the uploaded file to a temporary location
        with open("client_secrets.json", "wb") as f:
            f.write(uploaded_file.getvalue())

        st.write("File uploaded successfully! Starting authentication...")

        # Authenticate and get the token
        try:
            credentials = authenticate_and_get_token("client_secrets.json")
            st.success("Authentication successful!")
            
            st.write("Your access token is:")
            st.text_area("Access Token", value=credentials['token'], height=150)

            # Optionally, save credentials to a file
            with open('credentials.json', 'w') as token_file:
                json.dump(credentials, token_file)
            st.write("Credentials saved to `credentials.json`.")
            
        except Exception as e:
            st.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
