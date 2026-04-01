"""
Network Anomaly Detector Dashboard — Streamlit visualization.

Displays network flow metrics, anomaly feed, baseline profiles,
and detection accuracy from simulated or captured traffic.

Usage:
    streamlit run dashboard.py
"""

import json
import time
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from database import init_db, get_flows, get_anomalies, get_flow_stats, get_baselines

st.set_page_config(
    page_title="Network Anomaly Detector",
    page_icon="\U0001f50d",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .stApp { background-color: #0a0a0a; }
</style>
""", unsafe_allow_html=True)

init_db()

# --- Sidebar ---
st.sidebar.title("Anomaly Detector")
auto_refresh = st.sidebar.toggle("Auto-refresh (10s)", value=False)
host_filter = st.sidebar.text_input("Filter by Host IP")
severity_filter = st.sidebar.multiselect("Severity", ["critical", "high", "medium", "low"], default=["critical", "high", "medium", "low"])

# --- Header ---
st.title("\U0001f50d Network Traffic Anomaly Detector")

# --- Metrics ---
stats = get_flow_stats()
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total Flows", stats["total_flows"])
with col2:
    st.metric("Unique Sources", stats["unique_sources"])
with col3:
    st.metric("Unique Destinations", stats["unique_destinations"])
with col4:
    st.metric("Anomalies Detected", stats["anomalies_detected"])

if stats["total_flows"] == 0:
    st.info("No data yet. Run: `python simulate_traffic.py` then `python detector.py`")
else:
    tab_overview, tab_anomalies, tab_baseline, tab_hosts = st.tabs([
        "Overview", "Anomalies", "Baselines", "Host Detail"
    ])

    with tab_overview:
        flows = get_flows(limit=2000)
        df = pd.DataFrame(flows)

        if not df.empty:
            chart1, chart2 = st.columns(2)

            with chart1:
                st.subheader("Protocol Distribution")
                proto_counts = df["protocol"].value_counts()
                fig_proto = px.pie(
                    names=proto_counts.index, values=proto_counts.values,
                    hole=0.4, color_discrete_sequence=px.colors.qualitative.Set2,
                )
                fig_proto.update_layout(
                    paper_bgcolor="#0a0a0a", font_color="#e0e0e0",
                    margin=dict(t=10, b=10, l=10, r=10), height=300,
                )
                st.plotly_chart(fig_proto, use_container_width=True)

            with chart2:
                st.subheader("Top Destination Ports")
                port_counts = df["dst_port"].value_counts().head(10)
                fig_ports = go.Figure(go.Bar(
                    x=[str(p) for p in port_counts.index],
                    y=port_counts.values,
                    marker_color="#00d4ff",
                ))
                fig_ports.update_layout(
                    paper_bgcolor="#0a0a0a", plot_bgcolor="#111827",
                    font_color="#e0e0e0", margin=dict(t=10, b=40, l=40, r=10),
                    height=300,
                )
                st.plotly_chart(fig_ports, use_container_width=True)

            # Timeline
            st.subheader("Traffic Over Time")
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df_time = df.dropna(subset=["timestamp"])
            if not df_time.empty:
                df_time["hour"] = df_time["timestamp"].dt.floor("h")
                hourly = df_time.groupby("hour").size().reset_index(name="count")
                fig_tl = px.area(hourly, x="hour", y="count", color_discrete_sequence=["#00d4ff"])
                fig_tl.update_layout(
                    paper_bgcolor="#0a0a0a", plot_bgcolor="#111827",
                    font_color="#e0e0e0", margin=dict(t=10, b=40, l=40, r=10),
                    height=250,
                )
                st.plotly_chart(fig_tl, use_container_width=True)

    with tab_anomalies:
        st.subheader("Detected Anomalies")
        anomalies = get_anomalies(limit=200)

        if not anomalies:
            st.info("No anomalies detected yet. Run the detector: `python detector.py`")
        else:
            anom_df = pd.DataFrame(anomalies)
            if severity_filter:
                anom_df = anom_df[anom_df["severity"].isin(severity_filter)]
            if host_filter:
                anom_df = anom_df[anom_df["src_ip"].str.contains(host_filter, na=False)]

            # Anomaly type breakdown
            if not anom_df.empty:
                type_counts = anom_df["anomaly_type"].value_counts()
                fig_types = px.bar(
                    x=type_counts.index, y=type_counts.values,
                    color=type_counts.values, color_continuous_scale="Reds",
                    labels={"x": "Anomaly Type", "y": "Count"},
                )
                fig_types.update_layout(
                    paper_bgcolor="#0a0a0a", plot_bgcolor="#111827",
                    font_color="#e0e0e0", margin=dict(t=10, b=40, l=40, r=10),
                    height=300,
                )
                st.plotly_chart(fig_types, use_container_width=True)

            # Anomaly feed
            for _, row in anom_df.iterrows():
                sev = row.get("severity", "low")
                if sev == "critical":
                    badge = ":red[CRITICAL]"
                elif sev == "high":
                    badge = ":orange[HIGH]"
                elif sev == "medium":
                    badge = ":blue[MEDIUM]"
                else:
                    badge = ":green[LOW]"

                with st.expander(
                    f"{badge} **{row.get('anomaly_type', 'N/A')}** — "
                    f"{row.get('src_ip', 'N/A')} -> {row.get('dst_ip', 'N/A')} "
                    f"| Confidence: {row.get('confidence', 0)}%"
                ):
                    st.markdown(f"**Detected at:** {row.get('detected_at', 'N/A')}")
                    st.markdown(f"**Flows involved:** {row.get('flow_count', 0)}")
                    evidence = row.get("evidence", "{}")
                    if isinstance(evidence, str):
                        evidence = json.loads(evidence)
                    st.json(evidence)

    with tab_baseline:
        st.subheader("Baseline Profiles")
        baselines = get_baselines()
        if not baselines:
            st.info("No baselines stored. Run the full pipeline to generate baselines.")
        else:
            selected_ip = st.selectbox("Select host", sorted(baselines.keys()))
            if selected_ip:
                prof = baselines[selected_ip]
                st.markdown(f"**Total flows profiled:** {prof.get('total_flows', 0)}")
                st.markdown(f"**Active hours:** {prof.get('active_hours', [])}")

                m1, m2 = st.columns(2)
                with m1:
                    bs = prof.get("bytes_sent", {})
                    st.markdown("**Bytes Sent Stats**")
                    st.markdown(f"Mean: {bs.get('mean', 0)} | Std: {bs.get('std', 0)} | P95: {bs.get('p95', 0)}")
                with m2:
                    br = prof.get("bytes_received", {})
                    st.markdown("**Bytes Received Stats**")
                    st.markdown(f"Mean: {br.get('mean', 0)} | Std: {br.get('std', 0)} | P95: {br.get('p95', 0)}")

                # Top destinations
                dsts = prof.get("common_destinations", {})
                if dsts:
                    st.markdown("**Common Destinations**")
                    dst_df = pd.DataFrame(list(dsts.items()), columns=["Destination", "Count"])
                    dst_df = dst_df.sort_values("Count", ascending=False).head(10)
                    st.dataframe(dst_df, use_container_width=True, hide_index=True)

    with tab_hosts:
        st.subheader("Host Detail")
        host_ip = host_filter or st.text_input("Enter host IP")
        if host_ip:
            host_flows = get_flows(limit=500, src_ip=host_ip)
            if host_flows:
                st.markdown(f"**{len(host_flows)} flows from {host_ip}**")
                hf_df = pd.DataFrame(host_flows)
                display_cols = ["timestamp", "dst_ip", "dst_port", "protocol", "bytes_sent", "bytes_received", "label"]
                st.dataframe(hf_df[[c for c in display_cols if c in hf_df.columns]], use_container_width=True, hide_index=True)
            else:
                st.info(f"No flows found for {host_ip}")

# Auto-refresh
if auto_refresh:
    time.sleep(10)
    st.rerun()
