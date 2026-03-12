from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from detector import PhishingDetector

st.set_page_config(page_title="Phishing Email Detector", page_icon="🛡️", layout="wide")

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_PATH = BASE_DIR / "data" / "sample_emails.csv"

@st.cache_resource
def load_detector() -> PhishingDetector:
    return PhishingDetector()

detector = load_detector()

st.title("🛡️ Phishing Email Detector")
st.caption("Hybrid scoring using NLP classification plus transparent phishing indicators.")

tab_one, tab_two, tab_three = st.tabs(["Single Email Analysis", "Batch CSV Scan", "About the Model"])

with tab_one:
    st.subheader("Analyze one email")
    col_left, col_right = st.columns([1, 1])

    with col_left:
        sender = st.text_input("Sender address", value="security@micr0soft-alerts.com")
        subject = st.text_input("Subject line", value="Urgent: Verify your account now")
        body = st.text_area(
            "Email body",
            height=260,
            value=(
                "Dear user,\n"
                "We detected suspicious activity on your account. "
                "To avoid permanent suspension, verify your credentials within twenty four hours.\n"
                "Click here now: http://secure-login-check.com/verify\n"
                "Failure to respond will result in account deactivation.\n"
                "Security Team"
            ),
        )

        if st.button("Analyze Email", type="primary"):
            result = detector.assess(subject=subject, sender=sender, body=body)
            st.session_state["latest_result"] = result

    with col_right:
        result = st.session_state.get("latest_result")
        if result:
            st.metric("Risk Score", f"{result.risk_score}/100")
            st.metric("Model Probability", f"{result.model_probability:.1%}")
            st.metric("Keyword Score", f"{result.keyword_score:.0f}/100")

            if result.risk_score >= 70:
                st.error(result.label)
            elif result.risk_score >= 45:
                st.warning(result.label)
            else:
                st.success(result.label)

            st.markdown("**Top indicators**")
            if result.indicators:
                for item in result.indicators:
                    st.write(f"- {item}")
            else:
                st.write("- No major warning indicators found.")

            st.markdown("**Suspicious terms**")
            if result.suspicious_terms:
                st.write(", ".join(result.suspicious_terms))
            else:
                st.write("No suspicious keywords matched the rules.")

            st.markdown("**Quick stats**")
            st.write(f"URLs found: {result.url_count}")
            st.write(f"Exclamation marks: {result.exclamation_count}")
        else:
            st.info("Run an analysis to see the result panel.")

with tab_two:
    st.subheader("Upload a CSV for batch scanning")
    st.write("Required columns: `sender`, `subject`, `body`")

    sample_df = pd.read_csv(SAMPLE_PATH)
    st.download_button(
        "Download sample CSV",
        data=sample_df.to_csv(index=False).encode("utf-8"),
        file_name="sample_emails.csv",
        mime="text/csv",
    )

    uploaded = st.file_uploader("Upload CSV", type=["csv"])
    if uploaded is not None:
        frame = pd.read_csv(uploaded)
        results = detector.batch_assess(frame)
        st.dataframe(results, use_container_width=True)
        st.download_button(
            "Download results",
            data=results.to_csv(index=False).encode("utf-8"),
            file_name="phishing_scan_results.csv",
            mime="text/csv",
        )

with tab_three:
    st.subheader("How this project works")
    st.markdown(
        """
        - **Text model:** TF-IDF vectorization plus logistic regression.
        - **Rule-based scoring:** suspicious keywords, urgency phrases, link checks, and sender-domain checks.
        - **Final score:** weighted blend of the learned model and transparent rule signals.
        - **Use case:** educational phishing triage, resume project, or dashboard demo.

        This project is not a replacement for a production secure email gateway. It is meant for learning,
        prototyping, and portfolio use.
        """
    )
