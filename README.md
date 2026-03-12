# Phishing Email Detector

A GitHub-ready Python project that analyzes email text and flags phishing risk using a **hybrid approach**:

- **NLP model**: TF-IDF + Logistic Regression
- **Rule-based scoring**: suspicious keywords, urgency language, sender checks, and link analysis
- **Web dashboard**: Streamlit app for single-email and batch CSV analysis
- **Evaluation extras**: confusion matrix, sample dataset, and basic tests

This project is ideal for showing **cybersecurity**, **Python**, and **data analysis** skills in one repository.

## Screenshots

### Single email analysis
![Single email dashboard](assets/dashboard_home.png)

### Batch CSV scan
![Batch scan dashboard](assets/dashboard_batch.png)

### Confusion matrix
![Confusion matrix](assets/confusion_matrix.png)

## Why this project is good for GitHub

It shows that you can:

- build a practical cybersecurity tool
- combine machine learning with explainable rules
- create a dashboard instead of just a notebook
- test and package a project like a real repo
- document your work clearly for recruiters

## Features

- Paste an email subject, sender, and body into the dashboard
- Get a phishing **risk score** from zero to one hundred
- See a clear label:
  - **Likely Phishing**
  - **Suspicious / Needs Review**
  - **Likely Legitimate**
- View suspicious indicators such as:
  - unknown sender domains
  - HTTP links
  - urgency wording
  - credential requests
  - suspicious keywords
- Upload a CSV to scan multiple emails at once
- Download batch results as a CSV

## Project structure

```text
phishing_email_detector/
├── app.py
├── detector.py
├── train_model.py
├── evaluate.py
├── requirements.txt
├── LICENSE
├── README.md
├── data/
│   ├── training_data.csv
│   └── sample_emails.csv
├── models/
│   └── phishing_model.joblib
├── assets/
│   ├── confusion_matrix.png
│   ├── dashboard_batch.png
│   └── dashboard_home.png
└── tests/
    └── test_detector.py
```

## How it works

The detector blends two signals:

### One. Text classification
The machine learning model uses:

- **TF-IDF vectorization**
- **Logistic Regression**

The model is trained on labeled email text from the included dataset.

### Two. Explainable phishing indicators
The rules add signals for things like:

- suspicious words such as *verify*, *urgent*, *password*, *suspend*
- unknown or odd sender domains
- alphanumeric obfuscation in domains
- links in the message
- unsecured `http://` links
- time pressure phrases
- requests for credentials

### Final score
The final phishing score is a weighted blend of:

- model probability
- keyword score
- structural risk signals

This makes the output more useful in a portfolio project because it is not just a black-box prediction.

## Installation

Clone the repo and install dependencies:

```bash
pip install -r requirements.txt
```

## Run the app

```bash
streamlit run app.py
```

## Retrain the model

```bash
python train_model.py
```

## Generate the confusion matrix again

```bash
python evaluate.py
```

## Run tests

```bash
pytest -q
```

## CSV format for batch scanning

Use a CSV with these columns:

- `sender`
- `subject`
- `body`

Example:

```csv
sender,subject,body
security@micr0soft-alerts.com,Urgent: Verify your account now,"Dear user, verify your account now..."
alex@vt.edu,Project update,"Hi team, here is the latest project update..."
```

## Notes about the dataset

The included training data is **synthetic and portfolio-friendly**. It is meant for learning, demos, and GitHub presentation.

Because the dataset is synthetic and intentionally separated into clear phishing vs legitimate patterns, the evaluation results can look very strong. For a more realistic version, you can later improve this project by:

- adding a larger real-world public phishing dataset
- tuning the rules and model thresholds
- adding sender reputation APIs
- highlighting suspicious spans in the email body
- deploying the app online

## Resume-ready description

You can use this on your resume or LinkedIn:

**Built a Python phishing email detector that combines NLP classification with explainable keyword and link-based risk scoring; developed a Streamlit dashboard for single-email and batch CSV analysis and evaluated performance with a confusion matrix.**

## Suggested GitHub repo description

**Python phishing email detector with NLP, keyword scoring, sender/link analysis, and a Streamlit dashboard.**

## Suggested future upgrades

- add SHAP or feature importance explanations
- highlight suspicious phrases directly in the body
- add URL reputation checks
- create a REST API with FastAPI
- deploy with Streamlit Community Cloud or Render

## Disclaimer

This project is for education, demos, and portfolio use. It is not a production email security system.
