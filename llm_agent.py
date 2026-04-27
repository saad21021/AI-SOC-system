import os
from dotenv import load_dotenv
from langchain_core.prompts import PromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI

# Automatically load the GOOGLE_API_KEY from the .env file
load_dotenv()

def init_llm():
    """
    Initializes the Large Language Model using Google Gemini.
    Requires GOOGLE_API_KEY to be set in your environment variables.
    """
    # Explicitly load from the exact path because Streamlit cwd can sometimes get messed up
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    env_path = os.path.join(BASE_DIR, '.env')
    load_dotenv(dotenv_path=env_path, override=True)
    
    # --- SECURE CONFIGURATION ---
    # The API key should be stored in the .env file as GOOGLE_API_KEY
    api_key = os.getenv("GOOGLE_API_KEY", "").strip("\"' \t\n\r")
    
    if not api_key:
        raise ValueError(f"Could not find GOOGLE_API_KEY in .env file at {env_path}! Is it empty?")
    if "PASTE_YOUR_API" in api_key:
        raise ValueError("API Key is still the placeholder. Did you save the .env file?")
        
    if len(api_key) < 35:
         raise ValueError(f"API Key looks too short (Length {len(api_key)}). Make sure you copied the whole thing!")
         
    if "..." in api_key:
         raise ValueError("It looks like you copied the truncated key ('...')! Make sure you click the copy button next to the key, not highlight the text on the screen.")
         
    # gemini-1.5-flash is extremely fast and generous on the free tier!
    return ChatGoogleGenerativeAI(
        model="gemini-1.5-flash-latest", 
        temperature=0.2,
        google_api_key=api_key
    )

def generate_threat_report(packet_info, shap_features):
    """
    Takes the structured packet metadata and the SHAP feature impacts
    and generates an automated SOC threat analysis and mitigation plan.
    """
    try:
        llm = init_llm()
    except Exception as e:
        return f"⚠️ LLM Initialization Error: Ensure your GOOGLE_API_KEY is set properly. ({str(e)})"
    
    prompt = PromptTemplate(
        input_variables=["status", "severity", "confidence", "shap_data", "predicted_cluster"],
        template="""
        You are an expert Level 3 SOC Analyst. Our AI Anomaly Detection system has flagged a network packet.
        
        ### Intelligence Feed:
        - **Alert Status**: {status} (Predicted Cluster ID: {predicted_cluster})
        - **Severity Score (0.0 to 1.0)**: {severity}
        - **Model Confidence**: {confidence}
        
        ### Explainable AI (SHAP) Metrics:
        The machine learning model determined the following network features were the root cause of this alert:
        {shap_data}
        
        Based on this data, write a brief, punchy threat intelligence summary (max 3 sentences) explaining what this network traffic likely represents. Then, provide 2 actionable mitigation steps for a network engineer. Format the output in clean Markdown.
        """
    )
    
    # Format the SHAP data cleanly for the LLM to read
    shap_text = ""
    if not shap_features:
        shap_text = "No specific features identified.\n"
    else:
        for f in shap_features:
            shap_text += f"- **{f['feature']}**: {f['direction']} the anomaly score (absolute impact: {f['impact']:.3f}). {f['explanation']}\n"
        
    chain = prompt | llm
    
    try:
        response = chain.invoke({
            "status": packet_info.get("status", "Unknown"),
            "severity": packet_info.get("severity", 0),
            "confidence": packet_info.get("confidence", 0),
            "predicted_cluster": packet_info.get("cluster_predicted", -1),
            "shap_data": shap_text
        })
        return response.content
    except Exception as e:
        return f"⚠️ LLM Execution Error: {str(e)}"
