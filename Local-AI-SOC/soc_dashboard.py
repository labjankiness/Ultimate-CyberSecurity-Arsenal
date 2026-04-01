"""
AI-SOC Threat Dashboard — Streamlit visualization for triage results.

Reads alert data from soc_alerts.db (SQLite) and displays metrics,
charts, and a filterable alert feed in a dark SOC-style interface.

Usage:
    streamlit run soc_dashboard.py
"""

import time
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from database import init_db, get_alerts, get_alert_stats, get_incidents, get_incident, get_responses
from response_engine import generate_response

st.set_page_config(
    page_title="AI-SOC Dashboard",
    page_icon="\U0001f6e1\ufe0f",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Dark theme CSS
st.markdown("""
<style>
    .stApp { background-color: #0a0a0a; }
    .metric-card {
        background: #111827; border: 1px solid #1f2937; border-radius: 8px;
        padding: 16px; text-align: center;
    }
    .metric-value { font-size: 32px; font-weight: bold; }
    .metric-label { font-size: 12px; color: #6b7280; text-transform: uppercase; }
    .severity-critical { color: #ef4444; }
    .severity-medium { color: #f59e0b; }
    .severity-low { color: #4ade80; }
    .incident-card {
        background: #111827; border: 1px solid #1f2937; border-radius: 8px;
        padding: 16px; margin-bottom: 12px;
    }
    .chain-badge {
        display: inline-block; padding: 2px 8px; border-radius: 4px;
        font-size: 11px; font-weight: bold; margin-right: 4px;
    }
    .chain-kill { background: #7f1d1d; color: #fca5a5; }
    .chain-brute { background: #78350f; color: #fde68a; }
    .chain-freq { background: #1e3a5f; color: #93c5fd; }
    .chain-same { background: #1f2937; color: #9ca3af; }
</style>
""", unsafe_allow_html=True)

init_db()


# --- Sidebar Filters ---
st.sidebar.title("Filters")
auto_refresh = st.sidebar.toggle("Auto-refresh (5s)", value=False)
min_threat = st.sidebar.slider("Minimum Threat Level", 1, 10, 1)
verdict_filter = st.sidebar.selectbox("Verdict", ["All", "True Positive", "False Positive"])
categories = [
    "SSH Brute Force", "Privilege Escalation", "SQL Injection",
    "Port Scan", "Rogue USB", "Reconnaissance", "Other"
]
category_filter = st.sidebar.multiselect("Categories", categories, default=categories)
ip_search = st.sidebar.text_input("Source IP Search")


# --- Load Data ---
all_alerts = get_alerts(limit=500, min_severity=min_threat)
stats = get_alert_stats()

# Apply filters
df = pd.DataFrame(all_alerts) if all_alerts else pd.DataFrame()

if not df.empty:
    if verdict_filter != "All":
        df = df[df["verdict"] == verdict_filter]
    if category_filter:
        df = df[df["category"].isin(category_filter)]
    if ip_search:
        df = df[df["source_ip"].fillna("").str.contains(ip_search, case=False)]


# --- Header ---
st.title("\U0001f6e1\ufe0f AI-SOC Threat Dashboard")

# --- Metric Cards ---
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total Alerts", stats["total"])
with col2:
    st.metric("True Positives", stats["true_positives"])
with col3:
    st.metric("False Positives", stats["false_positives"])
with col4:
    st.metric("Avg Threat Level", f"{stats['avg_threat_level']:.1f}/10")


tab_alerts, tab_incidents = st.tabs(["Alerts", "Incidents"])

with tab_incidents:
    incidents = get_incidents()
    if not incidents:
        st.info("No correlated incidents yet. Run attack chains to generate multi-step incidents.")
    else:
        st.subheader(f"Correlated Incidents ({len(incidents)})")
        for inc in incidents:
            max_sev = inc.get("max_severity", 0) or 0
            if max_sev >= 8:
                border = "#ef4444"
                sev_badge = ":red[CRITICAL]"
            elif max_sev >= 5:
                border = "#f59e0b"
                sev_badge = ":orange[MEDIUM]"
            else:
                border = "#4ade80"
                sev_badge = ":green[LOW]"

            corr_id = inc.get("correlation_id", "N/A")
            cats = inc.get("categories", "N/A")
            with st.expander(
                f"{sev_badge} **Incident {corr_id}** — "
                f"{inc.get('alert_count', 0)} alerts | "
                f"Max severity: {max_sev}/10 | "
                f"{inc.get('source_ip', 'N/A')}"
            ):
                col_i1, col_i2, col_i3 = st.columns(3)
                with col_i1:
                    st.markdown(f"**Source IP:** `{inc.get('source_ip', 'N/A')}`")
                with col_i2:
                    st.markdown(f"**First seen:** {inc.get('first_seen', 'N/A')}")
                with col_i3:
                    st.markdown(f"**Last seen:** {inc.get('last_seen', 'N/A')}")

                st.markdown(f"**Categories:** {cats}")

                # Show individual alerts in this incident
                inc_alerts = get_incident(corr_id)
                if inc_alerts:
                    st.markdown("**Attack Timeline:**")
                    for idx, ia in enumerate(inc_alerts, 1):
                        tl_i = ia.get("threat_level", 0)
                        stage = ia.get("chain_stage", "")
                        stage_str = f" [{stage}]" if stage else ""
                        st.markdown(
                            f"{idx}. `{ia.get('timestamp', '')}` — "
                            f"**{ia.get('category', 'N/A')}**{stage_str} "
                            f"(severity {tl_i}/10)"
                        )
                        st.caption(ia.get("summary", ""))

with tab_alerts:
    if df.empty:
        st.info("No alerts yet. Run `python simulate_attack.py` and `python log_watcher.py` to generate alerts.")
    else:
        # --- Charts Row ---
        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            st.subheader("Threat Level Distribution")
            threat_counts = df["threat_level"].value_counts().sort_index()
            colors = []
            for level in threat_counts.index:
                if level >= 8:
                    colors.append("#ef4444")
                elif level >= 5:
                    colors.append("#f59e0b")
                else:
                    colors.append("#4ade80")
            fig_threat = go.Figure(go.Bar(
                x=threat_counts.index, y=threat_counts.values,
                marker_color=colors,
            ))
            fig_threat.update_layout(
                paper_bgcolor="#0a0a0a", plot_bgcolor="#111827",
                font_color="#e0e0e0", xaxis_title="Threat Level", yaxis_title="Count",
                margin=dict(t=10, b=40, l=40, r=10), height=300,
            )
            st.plotly_chart(fig_threat, use_container_width=True)

        with chart_col2:
            st.subheader("Category Breakdown")
            if stats["by_category"]:
                cat_df = pd.DataFrame(
                    list(stats["by_category"].items()), columns=["Category", "Count"]
                )
                fig_cat = px.pie(
                    cat_df, names="Category", values="Count", hole=0.4,
                    color_discrete_sequence=px.colors.qualitative.Set2,
                )
                fig_cat.update_layout(
                    paper_bgcolor="#0a0a0a", font_color="#e0e0e0",
                    margin=dict(t=10, b=10, l=10, r=10), height=300,
                    legend=dict(font=dict(size=11)),
                )
                st.plotly_chart(fig_cat, use_container_width=True)

        # --- Timeline ---
        st.subheader("Alerts Over Time")
        if "timestamp" in df.columns:
            df_time = df.copy()
            df_time["timestamp"] = pd.to_datetime(df_time["timestamp"], errors="coerce")
            df_time = df_time.dropna(subset=["timestamp"])
            if not df_time.empty:
                df_time["hour"] = df_time["timestamp"].dt.floor("h")
                hourly = df_time.groupby("hour").size().reset_index(name="count")
                fig_timeline = px.area(
                    hourly, x="hour", y="count",
                    color_discrete_sequence=["#00d4ff"],
                )
                fig_timeline.update_layout(
                    paper_bgcolor="#0a0a0a", plot_bgcolor="#111827",
                    font_color="#e0e0e0", xaxis_title="Time", yaxis_title="Alerts",
                    margin=dict(t=10, b=40, l=40, r=10), height=250,
                )
                st.plotly_chart(fig_timeline, use_container_width=True)

        # --- MITRE ATT&CK Heatmap ---
        if "mitre_tactic" in df.columns and "mitre_technique_id" in df.columns:
            mitre_df = df[df["mitre_technique_id"].fillna("").str.startswith("T")].copy()
            if not mitre_df.empty:
                st.subheader("MITRE ATT&CK Technique Heatmap")
                pivot = mitre_df.groupby(["mitre_tactic", "mitre_technique_id"]).size().reset_index(name="count")
                fig_mitre = px.treemap(
                    pivot, path=["mitre_tactic", "mitre_technique_id"], values="count",
                    color="count", color_continuous_scale="Reds",
                )
                fig_mitre.update_layout(
                    paper_bgcolor="#0a0a0a", font_color="#e0e0e0",
                    margin=dict(t=10, b=10, l=10, r=10), height=350,
                )
                st.plotly_chart(fig_mitre, use_container_width=True)

        # --- Alert Feed ---
        st.subheader(f"Alert Feed ({len(df)} alerts)")

        for _, row in df.iterrows():
            tl = row.get("threat_level", 0)
            if tl >= 8:
                border_color = "#ef4444"
                badge = ":red[CRITICAL]"
            elif tl >= 5:
                border_color = "#f59e0b"
                badge = ":orange[MEDIUM]"
            else:
                border_color = "#4ade80"
                badge = ":green[LOW]"

            corr_label = ""
            if row.get("is_correlated"):
                corr_label = f" | Incident: {row.get('correlation_id', '')}"

            with st.expander(
                f"{badge} **{row.get('category', 'N/A')}** — {row.get('verdict', '')} "
                f"(Threat: {tl}/10) | {row.get('timestamp', '')}"
                f" | {row.get('source_ip', 'N/A')}{corr_label}"
            ):
                st.markdown(f"**Summary:** {row.get('summary', 'N/A')}")
                st.markdown(f"**Remediation:** {row.get('remediation', 'N/A')}")
                st.code(row.get("raw_log", ""), language="text")
                col_a, col_b, col_c = st.columns(3)
                with col_a:
                    st.markdown(f"**Source IP:** `{row.get('source_ip', 'N/A')}`")
                with col_b:
                    st.markdown(f"**Username:** `{row.get('username', 'N/A')}`")
                with col_c:
                    st.markdown(f"**Command:** `{row.get('command', 'N/A')}`")
                mitre_id = row.get("mitre_technique_id", "")
                if mitre_id and mitre_id != "N/A":
                    mitre_url = row.get("mitre_url", "")
                    link = f"[{mitre_id}]({mitre_url})" if mitre_url else mitre_id
                    st.markdown(
                        f"**MITRE ATT&CK:** {link} — "
                        f"{row.get('mitre_technique_name', '')} ({row.get('mitre_tactic', '')})"
                    )
                if row.get("is_correlated"):
                    st.markdown(
                        f"**Correlation:** Incident `{row.get('correlation_id', '')}` "
                        f"| Stage: {row.get('chain_stage', 'N/A')}"
                    )

                # Response suggestions for True Positives
                if row.get("verdict") == "True Positive":
                    st.divider()
                    st.markdown("**Suggested Responses**")
                    st.caption("These are automated suggestions. Review before executing.")
                    suggestions = generate_response(dict(row))
                    for s in suggestions:
                        risk = s["risk_level"]
                        if risk == "aggressive":
                            risk_badge = ":red[AGGRESSIVE]"
                        elif risk == "moderate":
                            risk_badge = ":orange[MODERATE]"
                        else:
                            risk_badge = ":green[SAFE]"
                        approval = " | Requires approval" if s["requires_approval"] else ""
                        st.markdown(f"{risk_badge} **{s['action_name']}**{approval}")
                        st.code(s["command"], language="bash")
                        st.caption(s["explanation"])


# Auto-refresh
if auto_refresh:
    time.sleep(5)
    st.rerun()
