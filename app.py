import streamlit as st
import pandas as pd
import os
import time

from ml_pipeline import analyze_traffic
from explainer import get_shap_explanation
from llm_agent import generate_threat_report

# Configure basic page settings
st.set_page_config(page_title="AI SOC Dashboard", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# --- CUSTOM CSS FOR DARK/PREMIUM LOOK ---
st.markdown("""
<style>
    /* Sleek gradient top bar */
    .stApp header {
        background-color: transparent !important;
    }
    
    /* Premium Metric boxes */
    div[data-testid="stMetricValue"] {
        font-size: 1.8rem;
        color: #00FF41; /* Hacker terminal green */
    }
    
    .stAlert {
        border-radius: 10px;
    }
    
    /* Ensure a clear font */
    body {
        font-family: 'Inter', sans-serif;
    }
</style>
""", unsafe_allow_html=True)
# ----------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@st.cache_data
def load_data():
    csv_path = os.path.join(BASE_DIR, 'sample_network_traffic.csv')
    if os.path.exists(csv_path):
        return pd.read_csv(csv_path)
    return None

def main():
    st.title("🛡️ AI-Powered Security Operations Center")
    st.markdown("Real-time Network Anomaly Detection via Hybrid Isolation Forest + Semi-Supervised Random Forest")
    
    df = load_data()
    
    if df is None:
        st.error("No sample data found. Please ensure 'sample_network_traffic.csv' is in your cybersec project directory.")
        return
        
    st.sidebar.header("Control Panel")
    
    # We use Streamlit Session State to keep track of what packet we are analyzing
    if "packet_idx" not in st.session_state:
        st.session_state.packet_idx = 0
        
    packet_index = st.sidebar.slider("Select Network Sequence # (Simulating Live Feed)", 0, len(df)-1, st.session_state.packet_idx)
    st.session_state.packet_idx = packet_index
    
    # Grab the selected packet
    packet = df.iloc[[packet_index]]
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("📡 Live Packet Inspection")
        st.dataframe(packet, use_container_width=True)
        
    with col2:
        st.subheader("⚡ Actions")
        if st.button("Initiate ML Scan", use_container_width=True, type="primary"):
            with st.spinner("Running ML Pipeline (Isolation Forest -> Random Forest)..."):
                time.sleep(0.3) # Simulate a tiny latency for feel
                
                # --- EXECUTE THE ML PIPELINE ---
                results, X_scaled = analyze_traffic(packet)
                res = results[0]  
                
                # STORE IN STATE so it doesn't disappear if we click another button
                st.session_state.current_result = res
                st.session_state.current_packet_scaled = X_scaled[0]
                
    st.divider()
    
    # If an analysis has been performed, show the Threat Assessment Panel
    if "current_result" in st.session_state:
        res = st.session_state.current_result
        
        st.header("🚨 Threat Assessment")
        
        # Display the metrics calculated in ml_pipeline.py
        m1, m2, m3 = st.columns(3)
        m1.metric(label="Threat Status", value=res['status'])
        m2.metric(label="Severity Index", value=f"{res['severity']*100:.1f}%")
        
        if res.get('is_anomaly', False):
            m3.metric(label="Model Confidence", value=f"{res.get('confidence', 0)*100:.1f}%")
            
            st.error(f"**Action Required**: The model identified this traffic as an anomaly (Cluster Origin: {res.get('cluster_predicted', 'N/A')}).")
            
            # --- SHAP EXPLAINABILITY COMPONENT ---
            st.subheader("🧠 Model Explainability (SHAP)")
            with st.spinner("Extracting contributing features..."):
                top_features = get_shap_explanation(st.session_state.current_packet_scaled, res.get('cluster_predicted'))
                
                # Display the SHAP output dynamically
                st.markdown("The Explainable AI engine determined these network features triggered the alert:")
                for f in top_features:
                    color = "red" if f['direction'] == 'increase' else "green"
                    st.markdown(f"- **{f['feature']}**: <span style='color:{color}'>{f['direction']}</span> the alert signature.", unsafe_allow_html=True)
                     
            # --- LANGCHAIN LLM AGENT COMPONENT ---
            st.divider()
            st.subheader("🤖 LangChain AI Threat Analyst")
            if st.button("Generate Tactical Threat Report"):
                with st.spinner("Querying LLM SOC Analyst..."):
                    report = generate_threat_report(res, top_features)
                    st.info(report)
        else:
            m3.metric(label="Anomaly Score", value=f"{res.get('score', 0):.2f}")
            st.success("**All Clear**: No anomalies detected in current packet flow.")

if __name__ == "__main__":
    main()
