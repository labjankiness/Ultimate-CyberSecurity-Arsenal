import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="IoT Honeypot Dashboard", layout="wide")

st.title("🛡️ IoT Honeypot Threat Intelligence")
st.markdown("Real-time monitoring of malicious connection attempts on your network.")

def get_data():
    conn = sqlite3.connect('logs/honeypot.db')
    df = pd.read_sql_query("SELECT * FROM connections ORDER BY timestamp DESC", conn)
    conn.close()
    return df

try:
    df = get_data()

    if not df.empty:
        # Metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Attacks", len(df))
        col2.metric("Unique IPs", df['ip_address'].nunique())
        col3.metric("Most Targeted Port", df['port'].mode()[0] if not df['port'].empty else "N/A")

        # Layout
        c1, c2 = st.columns([2, 1])

        with c1:
            st.subheader("Attack Timeline")
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            timeline = df.resample('H', on='timestamp').count().reset_index()
            fig = px.line(timeline, x='timestamp', y='id', labels={'id': 'Attacks'}, template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)

        with c2:
            st.subheader("Port Distribution")
            port_counts = df['port'].value_counts().reset_index()
            fig_pie = px.pie(port_counts, names='port', values='count', template="plotly_dark")
            st.plotly_chart(fig_pie, use_container_width=True)

        st.subheader("Recent Incidents")
        st.dataframe(df[['timestamp', 'ip_address', 'port', 'payload']].head(50), use_container_width=True)
    else:
        st.info("No data captured yet. Waiting for incoming connections...")

except Exception as e:
    st.error(f"Error loading dashboard: {e}")
    st.info("Make sure the honeypot has been run at least once to initialize the database.")

if st.button('Refresh Data'):
    st.rerun()
