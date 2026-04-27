# 🛡️ AI-Powered Security Operations Center (SOC)

An advanced network anomaly detection system that leverages **Hybrid Machine Learning**, **Explainable AI (XAI)**, and **Large Language Models (LLMs)** to identify, explain, and mitigate cyber threats in real-time.

---

## 🚀 Overview

Traditional Intrusion Detection Systems (IDS) often act as "black boxes," flagging threats without explaining *why* they were flagged. This project solves that by providing:
1.  **Dual-Stage ML Pipeline**: Combines unsupervised outlier detection with supervised threat classification.
2.  **Explainable AI (SHAP)**: Visualizes the specific network features (packet size, flags, duration) that triggered an alert.
3.  **LLM Threat Analyst**: Uses Google Gemini to generate tactical mitigation reports for security engineers.

## ✨ Key Features

- **Anomaly Detection**: Uses **Isolation Forest** to detect zero-day attacks and unknown traffic patterns.
- **Threat Classification**: Uses **Random Forest** to categorize detected anomalies (DDoS, Port Scans, Botnets, etc.).
- **Interactive Dashboard**: Built with **Streamlit** for real-time visualization and simulation.
- **Root Cause Analysis**: Integrated **SHAP (SHapley Additive exPlanations)** to provide transparency for every alert.
- **Automated Reporting**: Generates SOC-ready threat intelligence reports via **LangChain + Gemini 1.5 Flash**.

## 🛠️ Tech Stack

- **Languages**: Python 3.10+
- **Machine Learning**: Scikit-Learn, NumPy, Pandas
- **Explainability**: SHAP
- **AI/LLM**: LangChain, Google Generative AI (Gemini)
- **Frontend**: Streamlit
- **DevOps**: Git, Python-Dotenv

## 📥 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/saad21021/AI-SOC-system.git
   cd AI-SOC-system
   ```

2. **Set up a Virtual Environment**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configuration**:
   Create a `.env` file in the root directory and add your Google API Key:
   ```env
   GOOGLE_API_KEY=your_api_key_here
   ```

## 🖥️ Usage

Run the Streamlit dashboard:
```bash
streamlit run app.py
```

## 🧠 How It Works

1.  **Data Ingestion**: The system reads network packet metadata (simulated or live).
2.  **Feature Scaling**: Data is normalized using a pre-trained `StandardScaler`.
3.  **Anomaly Scoring**: Isolation Forest assigns an anomaly score.
4.  **Classification**: If anomalous, Random Forest predicts the specific attack type.
5.  **Explanation**: SHAP calculates feature importance for that specific packet.
6.  **Reporting**: The LLM synthesizes all data into a professional security report.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

## 🤝 Contact

Saad Ahmed - [saadkamal21021@gmail.com](mailto:saadkamal21021@gmail.com)
Project Link: [https://github.com/saad21021/AI-SOC-system](https://github.com/saad21021/AI-SOC-system)
