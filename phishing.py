import streamlit as st
import pandas as pd
import re
import joblib

# Load model
model = joblib.load("decision_tree_model.joblib")

# Feature names used during training (ensure these match exactly)
feature_names = ["Have_IP", "Have_At", "URL_Length", "URL_Depth", "Redirection",
                 "https_Domain","Tiny_URL", "Prefix/Suffix", "DNS_Record", "Web_Traffic", 
                 "Domain_Age", "Domain_End", "iFrame", "Mouse_Over", "Right_Click", "Web_Forwards"]

# Feature extraction function
def extract_features(domain_name):
    features = {
        "Have_IP": 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain_name) else 0,
        "Have_At": 1 if "@" in domain_name else 0,
        "URL_Length": len(domain_name),
        "URL_Depth": domain_name.count('/'),
        "Redirection": 1 if "//" in domain_name[7:] else 0,  # after http:// or https://
        "https_Domain": 1 if domain_name.startswith("https") else 0,
        "Tiny_URL": 1 if len(domain_name) < 20 else 0,
        "Prefix/Suffix": 1 if '-' in domain_name else 0,
        "DNS_Record": 1,  # placeholder, can be filled based on actual DNS queries if needed
        "Web_Traffic": 0,  # placeholder, could be determined by web analytics
        "Domain_Age": 0,  # placeholder, could be filled using whois data
        "Domain_End": 1 if domain_name.endswith('.com') else 0,
        "iFrame": 0,  # placeholder, relates to website behavior
        "Mouse_Over": 0,  # placeholder, could be based on JavaScript behavior
        "Right_Click": 0,  # placeholder, could be set based on site restrictions
        "Web_Forwards": 0  # placeholder, can be filled based on redirection count
    }
    return features
# Initialize session state for scan history if not already initialized
if 'phishing_history' not in st.session_state:
    st.session_state['phishing_history'] = []

if 'prediction_result' not in st.session_state:
    st.session_state['prediction_result'] = None  # Track result to avoid re-clicking


# Prediction function
def predict_url(url):
    # Extract features from the input URL
    features = extract_features(url)

    # Convert features to DataFrame with proper column names
    feature_df = pd.DataFrame([features], columns=feature_names)
    feature_df = feature_df.drop(['Tiny_URL'], axis=1)  # Drop 'Tiny_URL' if not used

    # Get prediction from the model
    prediction = model.predict(feature_df)
    prediction_label = "Phishing" if prediction[0] == 1 else "Safe"
    
    return prediction_label, features

# Phishing detection page
def phishing_detection():
    st.header("Phishing Detection System")

    # Input text box to enter a URL
    url_input = st.text_input("Enter a URL to check for phishing:")

    # Check if URL is valid
    if url_input and not re.match(r'^(http|https)://', url_input):
        st.warning("Please enter a valid URL (must start with http:// or https://).")

    # Initialize a key to prevent double-clicking and force re-rendering
    if 'predict_clicked' not in st.session_state:
        st.session_state.predict_clicked = False

    # Check if URL has been entered and "Predict" button is clicked
    if st.button("Predict") or st.session_state.predict_clicked:
        st.session_state.predict_clicked = True

        if url_input:
            # Make prediction on the input URL
            result, features = predict_url(url_input)
            st.session_state['phishing_history'].append({"URL": url_input, "Result": result})

            # Display the result
            st.write(f"Prediction for {url_input}: **{result}**")

            # Display extracted features for transparency
            st.write("Extracted Features:")
            st.json(features)

        else:
            st.warning("Please enter a valid URL.")
        
        st.session_state.predict_clicked = False

    # Show scan history
    if st.session_state.phishing_history:
        st.subheader("Phishing Scan History")
        history_df = pd.DataFrame(st.session_state['phishing_history'])
        st.dataframe(history_df)

# Add a "Go Back" button
def go_back_button():
    if st.button("Go Back to Main Menu"):
        st.session_state.page = "main"