# app.py

import streamlit as st
import plotly.express as px
from loglyzer_core import LogLyzer

# --- Page Configuration ---
st.set_page_config(
    page_title="LogLyzer Web Security Dashboard",
    page_icon="🔎",
    layout="wide",
)
st.title("🔎 LogLyzer Web Security Dashboard")
st.write("Upload your server access log file below for security analysis and visualization.")

# --- File Uploader ---
uploaded_file = st.file_uploader(
    "Choose a Log File (.log or .txt)",
    type=["log", "txt"],
    help="Limit 200MB per file",
)

# --- Sidebar Configuration for V1.0.1 ---
with st.sidebar:
    st.header("Security Settings")
    # V1.0.1 ADDITION: Configurable Threshold
    unauthorized_threshold = st.slider(
        "401 Attempt Threshold (per IP)",
        min_value=1,
        max_value=20,
        value=5,  # Default threshold
        help="Number of 401 errors from a single IP before it's flagged as suspicious."
    )
    st.header("Filter Results")

if uploaded_file is not None:
    # Read the file content
    log_data = uploaded_file.getvalue().decode("utf-8").splitlines()

    # --- Run Analysis ---
    with st.spinner("Starting Log Analysis..."):
        # This check is vital for performance in Streamlit. Reruns only if file or threshold changes.
        if 'loglyzer_results' not in st.session_state or st.session_state.get(
                'last_threshold') != unauthorized_threshold:
            # --- V1.0.1 INTEGRATION: Pass the configurable threshold to the core class ---
            analyzer = LogLyzer(log_data, unauthorized_threshold=unauthorized_threshold)

            results = analyzer.analyze()
            st.session_state['loglyzer_results'] = results
            st.session_state['full_df'] = analyzer.df  # Store the full DataFrame for filtering
            st.session_state['last_threshold'] = unauthorized_threshold  # Store for change detection

        results = st.session_state['loglyzer_results']
        full_df = st.session_state['full_df']
        # V1.0.2 ADDITION: Extract hourly data
        hourly_requests = results['hourly_requests']

    st.success(f"Analysis complete! Processed {results['total_logs']} log entries.")

    # --- Analysis Summary ---
    st.header("Analysis Summary")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Log Entries", results['total_logs'])
    col2.metric("Total Unauthorized (401) Attempts", results['suspicious_ips']['401 Count'].sum())
    col3.metric("Unique 401 Offender IPs", len(results['suspicious_ips']))

    # --- Sidebar Filtering (User-defined filters) ---

    # 1. IP Address Filter
    all_ips = ['All'] + full_df['ip_address'].unique().tolist()
    selected_ip = st.sidebar.selectbox("Filter by IP Address:", all_ips)

    # 2. Status Code Filter
    all_statuses = ['All'] + full_df['status_code'].dropna().unique().astype(int).tolist()
    selected_status = st.sidebar.selectbox("Filter by Status Code:", all_statuses)

    # --- Dynamic Filtering ---
    filtered_df = full_df.copy()

    if selected_ip != 'All':
        filtered_df = filtered_df[filtered_df['ip_address'] == selected_ip]

    if selected_status != 'All':
        filtered_df = filtered_df[filtered_df['status_code'] == selected_status]

    # Recalculate Aggregations based on filtered_df
    filtered_suspicious_df = filtered_df[filtered_df['status_code'] == 401].groupby('ip_address').size().reset_index(
        name='401 Count')
    filtered_suspicious_df.columns = ['IP Address', '401 Count']

    # We must re-apply the threshold filter to this filtered dataframe
    filtered_suspicious_df = filtered_suspicious_df[
        filtered_suspicious_df['401 Count'] >= unauthorized_threshold
        ]

    filtered_geo_counts = filtered_df['country'].value_counts().reset_index()
    filtered_geo_counts.columns = ['Country', 'Requests']

    # --- Detailed Findings Tab View ---
    st.header("Detailed Findings")
    # V1.0.2 CHANGE: Added a fourth tab variable (tab_time)
    tab_suspicious, tab_status, tab_geo, tab_time = st.tabs(
        ["Suspicious IPs (401s)", "Request Status Codes", "Geographic Activity", "Request Volume Over Time"]
    )

    # --- Tab 1: Suspicious IPs (401s) ---
    with tab_suspicious:
        # V1.0.1 Display change
        st.subheader(f"IP Addresses Exceeding {unauthorized_threshold} Unauthorized Attempts")

        if not filtered_suspicious_df.empty:
            st.dataframe(filtered_suspicious_df, hide_index=True, width='stretch')

            fig_suspicious = px.bar(
                filtered_suspicious_df,
                x="IP Address",
                y="401 Count",
                title="401 Error Count per IP",
            )
            st.plotly_chart(fig_suspicious, width='stretch')
        else:
            st.info("No suspicious (401) activity found based on the current filters.")

    # --- Tab 2: Status Code Distribution (NOT Filtered by IP/Status code for general overview) ---
    with tab_status:
        st.subheader("HTTP Status Code Distribution (Overall)")
        # Note: We use the *original* results for the distribution chart as it's a general metric
        st.dataframe(results['status_distribution'], hide_index=True, width='stretch')

        fig_status = px.bar(
            results['status_distribution'],
            x="Status Code",
            y="Count",
            title="Distribution of all HTTP Status Codes",
        )
        st.plotly_chart(fig_status, width='stretch')

    # --- Tab 3: Geographic Activity ---
    with tab_geo:
        st.subheader("Geographic Distribution of Requests (Filtered)")

        if not filtered_geo_counts.empty:
            st.dataframe(filtered_geo_counts, hide_index=True, width='stretch')

            st.subheader("Requests by Country")
            fig_geo = px.pie(
                filtered_geo_counts,
                values="Requests",
                names="Country",
                title="Geographic Request Distribution (Filtered)",
            )
            st.plotly_chart(fig_geo, width='stretch')
        else:
            st.info("No geographic data found based on the current filters.")

    # --- Tab 4: Request Volume Over Time (V1.0.2) ---
    with tab_time:
        st.subheader("Request Volume Over Time (Hourly)")

        if not hourly_requests.empty:
            fig_time = px.line(
                hourly_requests,
                x="Time",
                y="Requests",
                title="Total Requests per Hour",
            )
            fig_time.update_xaxes(type='category')
            st.plotly_chart(fig_time, width='stretch')
        else:
            st.info("Insufficient data to show hourly request volume.")

# THIS IS THE FINAL 'else' BLOCK THAT ALIGNS WITH 'if uploaded_file is not None'
else:
    # Clear the session state when no file is loaded
    if 'loglyzer_results' in st.session_state:
        del st.session_state['loglyzer_results']
    if 'last_threshold' in st.session_state:
        del st.session_state['last_threshold']

    st.info("Awaiting log file upload to begin analysis. Please upload your log file to see the security dashboard.")