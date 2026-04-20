"""
Honeypot Analytics Dashboard — Streamlit visualization.

Displays real-time metrics, attack origin maps, credential analysis,
and attacker behavior patterns from the honeypot database.

Usage:
    streamlit run dashboard.py
"""

import time
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from database import (
    init_db, get_summary_stats, get_top_attackers, get_credential_stats,
    get_hourly_activity, get_country_stats, get_connections,
    get_attacker_history, get_connection_commands,
)
from log_processor import detect_credential_reuse, detect_rapid_attacks

st.set_page_config(
    page_title="Honeypot Analytics",
    page_icon="\U0001f36f",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .stApp { background-color: #0a0a0a; }
    .metric-card {
        background: #111827; border: 1px solid #1f2937; border-radius: 8px;
        padding: 16px; text-align: center;
    }
</style>
""", unsafe_allow_html=True)

init_db()

# --- Sidebar ---
st.sidebar.title("Honeypot Dashboard")
auto_refresh = st.sidebar.toggle("Auto-refresh (10s)", value=False)
ip_drill = st.sidebar.text_input("Drill down: Attacker IP")

# --- Header ---
st.title("\U0001f36f SSH Honeypot Analytics")

# --- Metrics ---
stats = get_summary_stats()
col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.metric("Total Connections", stats["total_connections"])
with col2:
    st.metric("Unique IPs", stats["unique_ips"])
with col3:
    st.metric("Usernames Tried", stats["unique_usernames"])
with col4:
    st.metric("Passwords Tried", stats["unique_passwords"])
with col5:
    st.metric("Countries", stats["unique_countries"])

if stats["total_connections"] == 0:
    st.info("No data yet. Run `python simulate_attacker.py` to generate demo data.")
else:
    tab_overview, tab_creds, tab_attackers, tab_feed = st.tabs([
        "Overview", "Credentials", "Attackers", "Live Feed"
    ])

    with tab_overview:
        chart1, chart2 = st.columns(2)

        with chart1:
            st.subheader("Attack Origins")
            countries = get_country_stats()
            if countries:
                country_df = pd.DataFrame(
                    list(countries.items()), columns=["Country", "Connections"]
                )
                fig_country = px.bar(
                    country_df, x="Country", y="Connections",
                    color="Connections", color_continuous_scale="Reds",
                )
                fig_country.update_layout(
                    paper_bgcolor="#0a0a0a", plot_bgcolor="#111827",
                    font_color="#e0e0e0", margin=dict(t=10, b=40, l=40, r=10),
                    height=350,
                )
                st.plotly_chart(fig_country, use_container_width=True)

        with chart2:
            st.subheader("Hourly Activity")
            hourly = get_hourly_activity()
            if hourly:
                hours = [f"{h}:00" for h in sorted(hourly.keys())]
                counts = [hourly[h] for h in sorted(hourly.keys())]
                fig_hourly = go.Figure(go.Bar(
                    x=hours, y=counts,
                    marker_color="#ef4444",
                ))
                fig_hourly.update_layout(
                    paper_bgcolor="#0a0a0a", plot_bgcolor="#111827",
                    font_color="#e0e0e0", xaxis_title="Hour (UTC)",
                    yaxis_title="Connections",
                    margin=dict(t=10, b=40, l=40, r=10), height=350,
                )
                st.plotly_chart(fig_hourly, use_container_width=True)

        # Heatmap: day of week x hour
        connections = get_connections(limit=1000)
        if connections:
            df_conn = pd.DataFrame(connections)
            df_conn["timestamp"] = pd.to_datetime(df_conn["timestamp"], errors="coerce")
            df_conn = df_conn.dropna(subset=["timestamp"])
            if not df_conn.empty:
                df_conn["hour"] = df_conn["timestamp"].dt.hour
                df_conn["day"] = df_conn["timestamp"].dt.day_name()
                heatmap = df_conn.groupby(["day", "hour"]).size().reset_index(name="count")
                day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
                heatmap["day"] = pd.Categorical(heatmap["day"], categories=day_order, ordered=True)
                heatmap = heatmap.sort_values("day")

                st.subheader("Attack Heatmap (Day x Hour)")
                pivot = heatmap.pivot_table(index="day", columns="hour", values="count", fill_value=0)
                fig_heat = px.imshow(
                    pivot, color_continuous_scale="Reds",
                    labels=dict(x="Hour", y="Day", color="Attacks"),
                )
                fig_heat.update_layout(
                    paper_bgcolor="#0a0a0a", font_color="#e0e0e0",
                    margin=dict(t=10, b=10, l=10, r=10), height=300,
                )
                st.plotly_chart(fig_heat, use_container_width=True)

        # Pattern detection
        rapid = detect_rapid_attacks()
        reuse = detect_credential_reuse()
        if rapid or reuse:
            st.subheader("Attack Patterns")
            pat1, pat2 = st.columns(2)
            with pat1:
                if rapid:
                    st.markdown("**Automated Attack Sources**")
                    for r in rapid[:5]:
                        st.markdown(
                            f"- `{r['source_ip']}`: {r['rapid_attempts']} rapid attempts "
                            f"(avg {r['avg_interval']}s)"
                        )
            with pat2:
                if reuse:
                    st.markdown("**Shared Credential Lists**")
                    for c in reuse[:5]:
                        st.markdown(
                            f"- Password `{c['password']}` used by "
                            f"{c['ip_count']} different IPs"
                        )

    with tab_creds:
        st.subheader("Credential Analysis")
        creds = get_credential_stats()

        cred1, cred2 = st.columns(2)
        with cred1:
            st.markdown("**Top Usernames**")
            if creds["top_usernames"]:
                user_df = pd.DataFrame(
                    list(creds["top_usernames"].items()),
                    columns=["Username", "Attempts"]
                )
                fig_users = px.bar(
                    user_df, x="Username", y="Attempts",
                    color="Attempts", color_continuous_scale="Blues",
                )
                fig_users.update_layout(
                    paper_bgcolor="#0a0a0a", plot_bgcolor="#111827",
                    font_color="#e0e0e0", margin=dict(t=10, b=40, l=40, r=10),
                    height=350,
                )
                st.plotly_chart(fig_users, use_container_width=True)

        with cred2:
            st.markdown("**Top Passwords**")
            if creds["top_passwords"]:
                pass_df = pd.DataFrame(
                    list(creds["top_passwords"].items()),
                    columns=["Password", "Attempts"]
                )
                fig_pass = px.bar(
                    pass_df, x="Password", y="Attempts",
                    color="Attempts", color_continuous_scale="Oranges",
                )
                fig_pass.update_layout(
                    paper_bgcolor="#0a0a0a", plot_bgcolor="#111827",
                    font_color="#e0e0e0", margin=dict(t=10, b=40, l=40, r=10),
                    height=350,
                )
                st.plotly_chart(fig_pass, use_container_width=True)

    with tab_attackers:
        st.subheader("Top Attackers")
        attackers = get_top_attackers(15)
        if attackers:
            att_df = pd.DataFrame(attackers)
            st.dataframe(att_df, use_container_width=True, hide_index=True)

        # Attacker drill-down
        drill_ip = ip_drill
        if drill_ip:
            st.subheader(f"Attacker Detail: {drill_ip}")
            history = get_attacker_history(drill_ip)
            if history:
                st.markdown(f"**Total attempts:** {len(history)}")
                hist_df = pd.DataFrame(history)
                st.dataframe(
                    hist_df[["timestamp", "username", "password", "client_banner", "geo_country"]],
                    use_container_width=True, hide_index=True,
                )
                # Check for commands
                for h in history:
                    cmds = get_connection_commands(h["id"])
                    if cmds:
                        st.markdown(f"**Commands captured (session #{h['id']}):**")
                        for cmd in cmds:
                            st.code(cmd["command_text"], language="bash")
            else:
                st.info(f"No connections found from {drill_ip}")

    with tab_feed:
        st.subheader("Recent Connections")
        recent = get_connections(limit=50)
        if recent:
            feed_df = pd.DataFrame(recent)
            cols = ["timestamp", "source_ip", "username", "password",
                    "geo_country", "client_banner", "session_duration"]
            display_cols = [c for c in cols if c in feed_df.columns]
            st.dataframe(feed_df[display_cols], use_container_width=True, hide_index=True)

# Auto-refresh
if auto_refresh:
    time.sleep(10)
    st.rerun()
