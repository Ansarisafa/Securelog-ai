"""
SecureLog AI - AI-Powered Security Log Analysis and Threat Detection System
Run with:   streamlit run app.py
"""
import platform
from datetime import datetime

import pandas as pd
import streamlit as st

from modules import charts
from modules.ai_engine import (analyze, live_threat_status, security_score,
                               top_risk_users)
from modules.auth import check_login
from modules.data_loader import (load_csv, load_live_logs, load_sample_dataset)
from modules.email_alert import send_alert_email
from modules.styles import CSS

# ---------------------------------------------------------------- page setup
st.set_page_config(page_title="SecureLog AI", page_icon="🛡️", layout="wide")
st.markdown(CSS, unsafe_allow_html=True)

LIVE = "Live Windows Event Logs"
UPLOAD = "Upload CSV file"
PAGES = ["Dashboard", "AI Analysis", "Charts", "High Risk Users", "Reports"]
COLOR_WORDS = {"High": "#ff4b4b", "Malicious": "#ff4b4b", "Critical": "#ff4b4b",
               "Threat Detected": "#ff4b4b", "Medium": "#ffa500",
               "Suspicious": "#ffa500", "Low": "#21c354", "Normal": "#21c354",
               "Safe": "#21c354"}


# ------------------------------------------------------------ small helpers
def show_table(data, height=400):
    """Show a table that fills the page width (works on old and new Streamlit)."""
    try:
        st.dataframe(data, width="stretch", height=height, hide_index=True)
    except Exception:
        st.dataframe(data, use_container_width=True, height=height, hide_index=True)


def show_chart(fig):
    """Show a Plotly chart that fills the width (works on old and new Streamlit)."""
    try:
        st.plotly_chart(fig, width="stretch")
    except Exception:
        st.plotly_chart(fig, use_container_width=True)


def color_cell(value):
    """Return CSS to colour words like High / Medium / Low."""
    colour = COLOR_WORDS.get(value)
    return f"color: {colour}; font-weight: bold" if colour else ""


def style_table(df, colour_columns):
    """Colour the chosen columns of a table."""
    styler = df.style
    apply_func = getattr(styler, "map", None) or styler.applymap  # new / old pandas
    cols = [c for c in colour_columns if c in df.columns]
    return apply_func(color_cell, subset=cols) if cols else styler


def time_as_text(df):
    """Return a copy where the time column is plain text (nicer in tables)."""
    out = df.copy()
    out["time"] = out["time"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return out


def info_card(label, value):
    st.markdown(f'<div class="info-card"><div class="label">{label}</div>'
                f'<div class="value">{value}</div></div>', unsafe_allow_html=True)


# ------------------------------------------------------------------- login
def login_page():
    st.markdown('<div class="login-title">🛡️ SecureLog AI</div>', unsafe_allow_html=True)
    st.markdown('<div class="login-sub">AI-Powered Security Log Analysis and '
                'Threat Detection System</div>', unsafe_allow_html=True)
    _, middle, _ = st.columns([1, 1.2, 1])
    with middle:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
        if submitted:
            if check_login(username, password):
                st.session_state["logged_in"] = True
                st.session_state["user"] = username.strip()
                st.rerun()
            else:
                st.error("Wrong username or password.")
        st.caption("Default login: admin / admin123 (change it in the .env file)")


# ------------------------------------------------------------------ sidebar
def sidebar():
    """Draw the sidebar and return the page the admin selected."""
    with st.sidebar:
        st.markdown("## 🛡️ SecureLog AI")
        st.success("Logged in as Administrator")
        page = st.radio("Navigation", PAGES)
        st.markdown('<div class="online-box">● System Online</div>', unsafe_allow_html=True)
        st.write("")
        if st.button("Logout"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
    return page


# -------------------------------------------------------------- data access
def data_source_selector():
    """Dashboard widget: choose Live Windows logs or an uploaded CSV."""
    st.subheader("Data Source")
    options = [LIVE, UPLOAD]
    current = st.session_state.get("source_choice", LIVE)
    choice = st.radio("Choose data source", options,
                      index=options.index(current), horizontal=True)
    st.session_state["source_choice"] = choice

    if choice == LIVE:
        if st.button("🔄 Refresh live logs"):
            st.session_state.pop("live_data", None)   # forces a new read
    else:
        file = st.file_uploader("Upload a security log CSV file", type=["csv"])
        st.caption("Required columns: username, ip_address, failed_attempts, "
                   "threat_level  (optional: event, login_hour, time)")
        if file is not None:
            file_id = f"{file.name}-{file.size}"
            if st.session_state.get("uploaded_id") != file_id:   # new file
                try:
                    st.session_state["uploaded_df"] = load_csv(file)
                    st.session_state["uploaded_id"] = file_id
                    st.session_state["uploaded_name"] = file.name
                except Exception as error:
                    st.error(f"Could not read this file: {error}")


def get_data():
    """Return (raw_dataframe, text describing the source)."""
    choice = st.session_state.get("source_choice", LIVE)
    if choice == UPLOAD:
        if st.session_state.get("uploaded_df") is not None:
            return (st.session_state["uploaded_df"],
                    f"Uploaded file: {st.session_state['uploaded_name']}")
        if "sample_df" not in st.session_state:
            st.session_state["sample_df"] = load_sample_dataset()
        return st.session_state["sample_df"], "Sample dataset (no file uploaded yet)"

    # Live Windows logs (read once, then kept until you press Refresh)
    if "live_data" not in st.session_state:
        with st.spinner("Reading Windows Security log..."):
            st.session_state["live_data"] = load_live_logs()
    df, message, is_live = st.session_state["live_data"]
    return df, ("Live Windows Security log" if is_live else "Sample data (live logs unavailable)")


@st.cache_data(show_spinner="AI is analysing the logs...")
def run_analysis(df):
    """Run the AI models. cache_data remembers the result so it is not repeated."""
    return analyze(df)


def get_results():
    """Load data + run AI. Returns (result_df, model_info, source_text)."""
    raw, source_text = get_data()
    try:
        result, info = run_analysis(raw)
    except Exception as error:
        st.error(f"AI analysis failed: {error}")
        st.stop()
    return result, info, source_text


# ------------------------------------------------------------ shared widgets
def email_button(result, key):
    """The 'Send Email Alerts' button."""
    if st.button("📧 Send Email Alerts", key=key):
        with st.spinner("Sending e-mail..."):
            ok, message = send_alert_email(result[result["risk_level"] == "High"])
        if ok:
            st.success(message)
        else:
            st.error(message)


def live_monitoring_box(result):
    """The 'Live Threat Monitoring' box."""
    m = live_threat_status(result)
    colour = {"Low": "#21c354", "Medium": "#ffa500", "High": "#ff4b4b"}[m["level"]]
    st.markdown(f"""
    <div class="monitor-box" style="border-left:6px solid {colour};">
      <b>📡 Live Threat Monitoring</b>
      <div class="monitor-grid">
        <div class="monitor-item"><div class="label">Threat Level</div>
             <div class="value" style="color:{colour}">{m['level']}</div></div>
        <div class="monitor-item"><div class="label">Failed Logins</div>
             <div class="value">{m['failed_logins']}</div></div>
        <div class="monitor-item"><div class="label">Blocked Users</div>
             <div class="value">{m['blocked_users']}</div></div>
        <div class="monitor-item"><div class="label">Current Threat Score</div>
             <div class="value">{m['threat_pct']}%</div></div>
        <div class="monitor-item"><div class="label">System Status</div>
             <div class="value" style="color:{colour}">{m['status']}</div></div>
      </div>
    </div>""", unsafe_allow_html=True)


# --------------------------------------------------------------------- pages
def dashboard_page():
    st.title("📊 Dashboard")

    # header cards
    c1, c2, c3 = st.columns(3)
    with c1:
        info_card("Logged User", st.session_state.get("user", "admin"))
    with c2:
        info_card("System", f"{platform.system()} ({platform.node()})")
    with c3:
        info_card("Date", datetime.now().strftime("%d %B %Y"))

    data_source_selector()
    result, info, source_text = get_results()
    st.caption(f"Data source in use: **{source_text}**")
    if source_text.startswith("Sample data (live"):
        st.warning("Live Windows logs could not be read (not Windows, pywin32 missing, "
                   "or not running as Administrator). Showing sample data instead.")

    # metric cards
    risk = result["risk_level"].value_counts()
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Events", f"{len(result):,}")
    m2.metric("Low Risk", f"{risk.get('Low', 0):,}")
    m3.metric("Medium Risk", f"{risk.get('Medium', 0):,}")
    m4.metric("High Risk", f"{risk.get('High', 0):,}")

    live_monitoring_box(result)
    email_button(result, key="email_dashboard")

    st.subheader("Live Security Events")
    cols = ["username", "event", "behavior", "risk_level", "threat_score",
            "ai_status", "ai_reason", "time"]
    latest = time_as_text(result.sort_values("time", ascending=False).head(500))[cols]
    show_table(style_table(latest, ["risk_level", "ai_status"]), height=450)
    st.caption("Showing the latest 500 events (newest first).")


def ai_analysis_page():
    st.title("🤖 AI Analysis")
    result, info, source_text = get_results()
    st.caption(f"Data source in use: **{source_text}**")

    acc = f"{info['accuracy'] * 100:.1f}%" if info["accuracy"] is not None else "n/a"
    st.info(f"Models: Isolation Forest (anomaly detection) + Random Forest "
            f"(risk classification). Random Forest test accuracy: **{acc}**")

    # AI Threat Analysis metrics
    pred = result["ai_prediction"].value_counts()
    st.subheader("AI Threat Analysis")
    a1, a2, a3, a4, a5 = st.columns(5)
    a1.metric("Events Analysed", f"{len(result):,}")
    a2.metric("Malicious", f"{pred.get('Malicious', 0):,}")
    a3.metric("Suspicious", f"{pred.get('Suspicious', 0):,}")
    a4.metric("Normal", f"{pred.get('Normal', 0):,}")
    a5.metric("Anomalies Found", f"{info['anomalies']:,}")

    # donut + bar chart
    left, right = st.columns(2)
    with left:
        show_chart(charts.prediction_donut(result))
    with right:
        show_chart(charts.threat_score_bar(result))

    # prediction table
    st.subheader("AI Threat Prediction Results")
    table = result.sort_values("threat_score", ascending=False).head(500)[
        ["username", "ip_address", "failed_attempts", "threat_level",
         "ai_prediction", "confidence", "severity"]]
    table = table.rename(columns={"ai_prediction": "AI prediction"})
    show_table(style_table(table, ["AI prediction", "severity"]), height=380)
    st.caption("Showing the 500 events with the highest threat score. "
               "Confidence is in %.")

    # top 10 users
    st.subheader("Top 10 High Risk Users")
    top = top_risk_users(result, 10)
    t1, t2 = st.columns([1.2, 1])
    with t1:
        show_table(top, height=390)
    with t2:
        show_chart(charts.top_users_bar(top))

    # security insights
    st.subheader("Security Insights")
    score = security_score(result)
    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Unique Users", f"{result['username'].nunique():,}")
    s2.metric("Unique IPs", f"{result['ip_address'].nunique():,}")
    s3.metric("Average Failed Attempts", f"{result['failed_attempts'].mean():.2f}")
    s4.metric("Security Score", f"{score} / 100")
    st.progress(int(score))

    with st.expander("Which features did the Random Forest use most?"):
        show_chart(charts.feature_importance_bar(info["feature_importance"]))


def charts_page():
    st.title("📈 Charts")
    result, info, source_text = get_results()
    st.caption(f"Data source in use: **{source_text}**")
    left, right = st.columns(2)
    with left:
        show_chart(charts.hourly_activity(result))
    with right:
        show_chart(charts.risk_comparison(result))
    show_chart(charts.events_over_time(result))


def high_risk_page():
    st.title("🚨 High Risk Users")
    result, info, source_text = get_results()
    st.caption(f"Data source in use: **{source_text}**")

    high = result[result["risk_level"] == "High"]
    search = st.text_input("🔍 Search by username")
    if search.strip():
        high = high[high["username"].str.contains(search.strip(), case=False, na=False)]

    h1, h2, h3 = st.columns(3)
    h1.metric("High Risk Events", f"{len(high):,}")
    h2.metric("Users", f"{high['username'].nunique():,}")
    h3.metric("Max Threat Score", f"{high['threat_score'].max() if len(high) else 0}")

    cols = ["username", "ip_address", "event", "failed_attempts", "threat_level",
            "threat_score", "ai_prediction", "severity", "time"]
    table = time_as_text(high.sort_values("threat_score", ascending=False).head(1000))[cols]
    if table.empty:
        st.info("No high-risk events match your search.")
    else:
        show_table(style_table(table, ["ai_prediction", "severity"]), height=450)
        st.caption("Showing up to 1,000 rows (highest threat score first).")
    email_button(result, key="email_high_risk")


def reports_page():
    st.title("📝 Reports")
    result, info, source_text = get_results()
    st.caption(f"Data source in use: **{source_text}**")

    high = result[result["risk_level"] == "High"]
    r1, r2, r3, r4 = st.columns(4)
    r1.metric("Total Events", f"{len(result):,}")
    r2.metric("High Risk Events", f"{len(high):,}")
    r3.metric("Unique Users", f"{result['username'].nunique():,}")
    r4.metric("Unique IPs", f"{result['ip_address'].nunique():,}")
    r5, r6, r7, r8 = st.columns(4)
    r5.metric("Average Threat Score", f"{result['threat_score'].mean():.1f}")
    r6.metric("Malicious (AI)", f"{(result['ai_prediction'] == 'Malicious').sum():,}")
    r7.metric("Suspicious (AI)", f"{(result['ai_prediction'] == 'Suspicious').sum():,}")
    r8.metric("Security Score", f"{security_score(result)} / 100")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    full_csv = time_as_text(result).to_csv(index=False).encode("utf-8")
    high_csv = time_as_text(high).to_csv(index=False).encode("utf-8")
    d1, d2 = st.columns(2)
    with d1:
        st.download_button("⬇️ Download Full Report (CSV)", full_csv,
                           file_name=f"securelog_report_{stamp}.csv", mime="text/csv")
    with d2:
        st.download_button("⬇️ Download High-Risk Events Only (CSV)", high_csv,
                           file_name=f"securelog_high_risk_{stamp}.csv", mime="text/csv")

    st.subheader("Report Preview")
    preview = time_as_text(result.head(200))
    show_table(preview, height=350)
    st.caption("Preview of the first 200 rows. The download contains all rows.")


# --------------------------------------------------------------------- main
def main():
    if not st.session_state.get("logged_in", False):
        login_page()
        return
    page = sidebar()
    if page == "Dashboard":
        dashboard_page()
    elif page == "AI Analysis":
        ai_analysis_page()
    elif page == "Charts":
        charts_page()
    elif page == "High Risk Users":
        high_risk_page()
    else:
        reports_page()


main()
