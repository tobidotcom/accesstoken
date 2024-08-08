import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
import json

# Define the scope for accessing YouTube Data API
SCOPES = ['https://www.googleapis.com/auth/youtube.readonly']

def authenticate_and_get_token(client_secrets_file):
    """Authenticate the user and get the access token."""
    flow = InstalledAppFlow.from_client_secrets_file(client_secrets_file, SCOPES)

    creds = None
    try:
        creds = flow.run_local_server(port=0)
    except Exception as e:
        st.error(f"Automatic authentication failed: {e}")
        # Provide manual authentication URL and code input
        auth_url, _ = flow.authorization_url(access_type='offline')
        st.write("Please go to this URL to authorize the application:")
        st.write(f"[Authorize Here]({auth_url})")
        auth_code = st.text_input("Enter the authorization code:")
        if auth_code:
            try:
                creds = flow.fetch_token(code=auth_code)
            except Exception as e:
                st.error(f"Failed to fetch token: {e}")

    if creds:
        credentials = {
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': creds.scopes
        }
        return credentials
    else:
        st.error("Failed to obtain credentials.")
        return None

def main():
    st.title("YouTube Data API Access Token Generator")

    st.write("Upload your `client_secrets.json` file to obtain an access token.")

    uploaded_file = st.file_uploader("Choose a file", type="json")

    if uploaded_file is not None:
        with open("client_secrets.json", "wb") as f:
            f.write(uploaded_file.getvalue())

        st.write("File uploaded successfully! Starting authentication...")

        credentials = authenticate_and_get_token("client_secrets.json")
        
        if credentials:
            st.success("Authentication successful!")
            st.write("Your access token is:")
            st.text_area("Access Token", value=credentials['token'], height=150)

            with open('credentials.json', 'w') as token_file:
                json.dump(credentials, token_file)
            st.write("Credentials saved to `credentials.json`.")

if __name__ == "__main__":
    main()

