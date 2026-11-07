# 🛡️ SecureLog AI
**AI-Powered Security Log Analysis and Threat Detection System** (Python + Streamlit)

SecureLog AI reads security logs (live Windows Security log or a CSV file), uses
machine learning to find suspicious / malicious activity, and shows everything on a
dark dashboard. It can also e-mail an alert for high-risk events.

## Folder structure
```
securelog_ai/
├── app.py                  <- main program (run this)
├── requirements.txt        <- list of libraries to install
├── .env.example            <- copy to ".env" and add your settings
├── README.md
├── .streamlit/config.toml  <- dark theme
├── modules/
│   ├── __init__.py
│   ├── config.py           <- reads .env settings
│   ├── auth.py             <- admin login check
│   ├── windows_logs.py     <- reads Windows Security log (pywin32)
│   ├── data_loader.py      <- loads/cleans live, CSV and sample data
│   ├── sample_data.py      <- makes fake log data
│   ├── ai_engine.py        <- Isolation Forest + Random Forest
│   ├── charts.py           <- Plotly charts
│   ├── email_alert.py      <- Gmail alert (smtplib)
│   └── styles.py           <- dark CSS
├── dataset/
│   ├── generate_dataset.py <- makes the 50,000-row CSV
│   └── sample_logs.csv     <- ready-made sample (already generated)
└── docs/VIVA_AND_REPORT.md <- AI explanation, 10 viva Q&A, project report
```

## Step-by-step: install and run
1. Install **Python 3.10 or newer** from python.org (tick "Add Python to PATH").
2. Open the project folder in Command Prompt (or VS Code terminal):
   ```
   cd securelog_ai
   ```
3. (Recommended) create a virtual environment:
   ```
   python -m venv venv
   venv\Scripts\activate          (Windows)
   source venv/bin/activate       (Linux / Mac)
   ```
4. Install the libraries:
   ```
   pip install -r requirements.txt
   ```
5. Create your settings file:
   ```
   copy .env.example .env         (Windows)
   cp .env.example .env           (Linux / Mac)
   ```
   Open `.env` in Notepad and change the password (and add Gmail details if you
   want e-mail alerts).
6. (Optional) make a fresh 50,000-row dataset:
   ```
   python dataset/generate_dataset.py
   ```
7. Start the app:
   ```
   streamlit run app.py
   ```
   The browser opens at http://localhost:8501
8. Login with **admin / admin123** (or what you wrote in `.env`).

## Using live Windows Event Logs
* Works only on **Windows** with `pywin32` (installed automatically by step 4).
* Reading the Security log needs **Administrator** rights: right-click Command
  Prompt → *Run as administrator*, then run `streamlit run app.py`.
* If it is not Windows, or access is denied, the app shows a warning and uses
  sample data automatically.

## Using your own CSV
Dashboard → choose **Upload CSV file**. Needed columns:
`username, ip_address, failed_attempts, threat_level` (threat_level 0-10).
Optional: `event, login_hour, time`.

## Setting up e-mail alerts (Gmail)
1. Google Account → Security → turn on **2-Step Verification**.
2. Search "App passwords" in your Google Account and create one (16 letters).
3. Put it in `.env` as `EMAIL_APP_PASSWORD`, plus `EMAIL_SENDER` and `EMAIL_RECEIVER`.
4. Click **Send Email Alerts** on the Dashboard or High Risk Users page.

Never share or upload your `.env` file.

## Common problems
| Problem | Fix |
|---|---|
| `streamlit` is not recognised | Run `python -m streamlit run app.py` |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` again (inside the venv) |
| Live logs show sample data | Run the terminal as Administrator, on Windows only |
| Gmail login failed | Use an App Password, not your normal password |

## Important notes (be honest in your viva)
* The risk labels used to train the Random Forest come from a transparent
  rule-based threat score, so its accuracy is very high. The Isolation Forest
  (unsupervised) is the part that finds unusual events without labels.
* The sample dataset is fake (made by a script). Real logs need more tuning.
