import requests
import streamlit as st


st.set_page_config(page_title="AI Firewall", layout="wide")

st.title("AI Prompt Injection Firewall")

user_instruction = st.text_area("Trusted User Instruction", height=100)
untrusted_content = st.text_area("Untrusted Content (email, website, doc)", height=200)

if st.button("Run Firewall"):
    response = requests.post(
        "http://127.0.0.1:8000/firewall",
        json={
            "user_instruction": user_instruction,
            "untrusted_content": untrusted_content,
            "generate_report": True,
            "client_name": "Live Demo",
        },
        timeout=30,
    )

    response.raise_for_status()
    data = response.json()

    st.subheader("Safe Output")
    st.write(data["safe_output"])

    st.subheader("Security Analysis")
    st.json(data["security_analysis"])

    st.subheader("Sibling Council Review")
    st.json(data["council_review"])

    if data["report_path"]:
        st.success(f"Report saved: {data['report_path']}")
