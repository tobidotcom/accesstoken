import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
import json

# Define the scopes for accessing YouTube Data API
SCOPES = [
    'https://www.googleapis.com/auth/youtube',
    'https://www.googleapis.com/auth/youtube.force-ssl',
    'https://www.googleapis.com/auth/youtube.readonly',
    'https://www.googleapis.com/auth/youtubepartner',
    'https://www.googleapis.com/auth/youtubepartner-channel-audit',
    'https://www.googleapis.com/auth/yt-analytics.readonly',
    'https://www.googleapis.com/auth/yt-analytics-monetary.readonly'
]

def authenticate_and_get_token(client_secrets_file):
    """Authenticate the user and get the access token."""
    try:
        flow = InstalledAppFlow.from_client_secrets_file(
            client_secrets_file, SCOPES, redirect_uri="https://accesstoken-zo9us8njw6cs8u7qz9n7at.streamlit.app/"
        )
        
        # Generate authorization URL
        auth_url, _ = flow.authorization_url(access_type='offline', prompt='consent')
        st.write("Please go to this URL to authorize the application:")
        st.write(f"[Authorize Here]({auth_url})")

        # Input field for authorization code
        auth_code = st.text_input("Enter the authorization code:")
        if auth_code:
            try:
                flow.fetch_token(code=auth_code)
                creds = flow.credentials

                credentials = {
                    'token': creds.token,
                    'refresh_token': creds.refresh_token,
                    'token_uri': creds.token_uri,
                    'client_id': creds.client_id,
                    'client_secret': creds.client_secret,
                    'scopes': creds.scopes
                }
                return credentials
            except Exception as e:
                st.error(f"Failed to fetch token: {e}")
                return None
    except Exception as e:
        st.error(f"Authentication failed: {e}")
        return None

def main():
    st.title("YouTube Data API Access Token Generator")

    st.write("Upload your `client_secrets.json` file to obtain an access token.")

    uploaded_file = st.file_uploader("Choose a file", type="json")

    if uploaded_file is not None:
        with open("client_secrets.json", "wb") as f:
            f.write(uploaded_file.getvalue())

        st.write("File uploaded successfully! Starting authentication...")

        # Authenticate and get the token
        credentials = authenticate_and_get_token("client_secrets.json")
        
        if credentials:
            st.success("Authentication successful!")
            st.write("Your access token is:")
            st.text_area("Access Token", value=credentials['token'], height=150)

            # Save credentials to a file
            with open('credentials.json', 'w') as token_file:
                json.dump(credentials, token_file)
            st.write("Credentials saved to `credentials.json`.")
        else:
            st.error("Failed to obtain credentials. Please try again.")

if __name__ == "__main__":
    main()

