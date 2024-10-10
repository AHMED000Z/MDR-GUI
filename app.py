import streamlit as st
from phishing import phishing_detection
from malware import malware_scan

# Main menu page
def main():
    st.header("Managed Detection and Response (MDR)")

    # Navigation buttons
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Phishing Link Detection"):
            st.session_state.page = 'phishing'
    with col2:
        if st.button("Malware File Scan"):
            st.session_state.page = 'malware'

    # Add toggle for Dark Mode
    dark_mode = st.checkbox("Enable Dark Mode")
    if dark_mode:
        st.markdown('<style>body {background-color: #333333; color: #ffffff;}</style>', unsafe_allow_html=True)
    else:
        st.markdown('<style>body {background-color: #ffffff; color: #000000;}</style>', unsafe_allow_html=True)

# Initialize session state
if 'page' not in st.session_state:
    st.session_state.page = 'main'

# Navigate based on session state
if st.session_state.page == 'main':
    main()
elif st.session_state.page == 'phishing':
    phishing_detection()
elif st.session_state.page == 'malware':
    malware_scan()

# Add "Go back to main menu" button
if st.session_state.page != 'main':
    if st.button("Go back to Main Menu"):
        st.session_state.page = 'main'
