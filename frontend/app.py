import json
import os
import tempfile

import streamlit as st

import ulpf


# =========================================================
# PROJECT PATHS
# =========================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

MODEL_PATH = os.path.join(
    PROJECT_ROOT,
    "models",
    "log_type_clf.joblib"
)

PLUGINS_PATH = os.path.join(
    PROJECT_ROOT,
    "plugins"
)


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="ULPF",
    page_icon="🔐",
    layout="wide"
)


# =========================================================
# CUSTOM CSS
# =========================================================

st.html(
    """
    <style>

    /* ================================================
       HEADER
       ================================================ */

    .ulpf-header {
        padding: 1.5rem 0 1rem 0;
    }

    .ulpf-title {
        font-size: 2.5rem;
        font-weight: 700;
        margin-bottom: 0.2rem;
    }

    .ulpf-subtitle {
        font-size: 1.1rem;
        opacity: 0.7;
        margin-bottom: 1rem;
    }


    /* ================================================
       SECTION TITLES
       ================================================ */

    .section-title {
        font-size: 1.4rem;
        font-weight: 600;
        margin-top: 1rem;
        margin-bottom: 0.8rem;
    }


    /* ================================================
       FILE INFORMATION
       ================================================ */

    .file-info {
        padding: 1rem;
        border-radius: 10px;
        border: 1px solid rgba(128, 128, 128, 0.3);
        margin-top: 1rem;
        margin-bottom: 1rem;
    }


    /* ================================================
       LOG TYPE TABLE
       ================================================ */

    .log-table {
        width: 100%;
        border: 1px solid rgba(128, 128, 128, 0.25);
        border-radius: 12px;
        overflow: hidden;
        margin-top: 0.5rem;
    }

    .log-table-header {
        display: grid;
        grid-template-columns: 1.3fr 0.8fr 2fr;
        padding: 14px;
        background: rgba(128, 128, 128, 0.08);
        border-bottom: 1px solid rgba(128, 128, 128, 0.25);
        font-weight: 600;
        color: rgba(255, 255, 255, 0.65);
    }

    .log-table-row {
        display: grid;
        grid-template-columns: 1.3fr 0.8fr 2fr;
        align-items: center;
        padding: 14px;
        border-bottom: 1px solid rgba(128, 128, 128, 0.18);
    }

    .log-table-row:last-child {
        border-bottom: none;
    }

    .log-type-name {
        font-weight: 500;
    }

    .log-events {
        font-weight: 500;
    }

    .share-container {
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .share-bar-background {
        flex: 1;
        height: 10px;
        background: rgba(128, 128, 128, 0.18);
        border-radius: 10px;
        overflow: hidden;
    }

    .share-bar {
        height: 100%;
        background: #ef5b5b;
        border-radius: 10px;
    }

    .share-value {
        min-width: 55px;
        text-align: right;
    }


    /* ================================================
       MOBILE
       ================================================ */

    @media (max-width: 700px) {

        .log-table-header,
        .log-table-row {
            grid-template-columns: 1.2fr 0.6fr 1.5fr;
            font-size: 0.85rem;
        }

        .share-container {
            gap: 6px;
        }

        .share-value {
            min-width: 42px;
        }

    }

    </style>
    """
)


# =========================================================
# HEADER
# =========================================================

st.html(
    """
    <div class="ulpf-header">

        <div class="ulpf-title">
            🔐 ULPF
        </div>

        <div class="ulpf-subtitle">
            Universal Log Pre-processing Framework
        </div>

    </div>
    """
)

st.divider()


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.title("🔐 ULPF")

st.sidebar.markdown("### ⚙️ Settings")

threshold = st.sidebar.slider(
    "Classification Confidence",
    min_value=0.0,
    max_value=1.0,
    value=0.60,
    step=0.05
)

st.sidebar.caption(
    "Logs below the confidence threshold "
    "are sent to quarantine."
)


# =========================================================
# FILE UPLOAD
# =========================================================

st.markdown(
    '<div class="section-title">📂 Upload Log File</div>',
    unsafe_allow_html=True
)

uploaded_file = st.file_uploader(
    "Choose a log file to analyze",
    type=["log", "txt"],
    help="Upload a .log or .txt file containing log events."
)


# =========================================================
# AFTER FILE IS UPLOADED
# =========================================================

if uploaded_file is not None:

    file_size_kb = len(
        uploaded_file.getvalue()
    ) / 1024


    # ---------------------------------------------------------
    # FILE INFORMATION
    # ---------------------------------------------------------

    st.html(
        f"""
        <div class="file-info">

            <b>📄 File:</b> {uploaded_file.name}

            <br>

            <b>📦 Size:</b> {file_size_kb:.2f} KB

        </div>
        """
    )


    # =========================================================
    # ANALYZE BUTTON
    # =========================================================

    analyze = st.button(
        "🚀 Analyze Logs",
        type="primary",
        use_container_width=True
    )


    # =========================================================
    # PROCESS LOG FILE
    # =========================================================

    if analyze:

        with st.spinner("Processing logs..."):

            try:

                # =================================================
                # TEMPORARY DIRECTORY
                # =================================================

                with tempfile.TemporaryDirectory() as temp_dir:

                    input_path = os.path.join(
                        temp_dir,
                        uploaded_file.name
                    )

                    output_path = os.path.join(
                        temp_dir,
                        "normalized.jsonl"
                    )

                    quarantine_path = os.path.join(
                        temp_dir,
                        "quarantine.jsonl"
                    )


                    # =================================================
                    # SAVE UPLOADED FILE
                    # =================================================

                    with open(
                        input_path,
                        "wb"
                    ) as f:

                        f.write(
                            uploaded_file.getvalue()
                        )


                    # =================================================
                    # CREATE BACKEND COMPONENTS
                    # =================================================

                    classifier = ulpf.LogTypeClassifier(
                        MODEL_PATH,
                        threshold
                    )

                    registry = ulpf.Registry(
                        PLUGINS_PATH,
                        self_test=True,
                        strict=False
                    )

                    sink = ulpf.JsonlSink(
                        output_path
                    )


                    # =================================================
                    # CREATE QUARANTINE + PIPELINE
                    # =================================================

                    with open(
                        quarantine_path,
                        "w",
                        encoding="utf-8"
                    ) as qfh:

                        quarantine = ulpf.Quarantine(
                            qfh
                        )

                        pipeline = ulpf.Pipeline(
                            classifier,
                            registry,
                            sink,
                            quarantine
                        )


                        # =============================================
                        # PROCESS FILE
                        # =============================================

                        pipeline.process_file(
                            input_path
                        )


                        # =============================================
                        # GET SUMMARY
                        # =============================================

                        summary = pipeline.summary()


                    # =================================================
                    # CLOSE SINK
                    # =================================================

                    sink.close()


                    # =================================================
                    # READ NORMALIZED EVENTS
                    # =================================================

                    normalized_events = []

                    if os.path.exists(
                        output_path
                    ):

                        with open(
                            output_path,
                            encoding="utf-8"
                        ) as f:

                            for line in f:

                                if line.strip():

                                    normalized_events.append(
                                        json.loads(line)
                                    )


                    # =================================================
                    # READ QUARANTINED EVENTS
                    # =================================================

                    quarantined_events = []

                    if os.path.exists(
                        quarantine_path
                    ):

                        with open(
                            quarantine_path,
                            encoding="utf-8"
                        ) as f:

                            for line in f:

                                if line.strip():

                                    quarantined_events.append(
                                        json.loads(line)
                                    )


                    # =================================================
                    # READ DOWNLOAD DATA
                    # =================================================

                    normalized_data = b""

                    if os.path.exists(
                        output_path
                    ):

                        with open(
                            output_path,
                            "rb"
                        ) as f:

                            normalized_data = f.read()


                    quarantine_data = b""

                    if os.path.exists(
                        quarantine_path
                    ):

                        with open(
                            quarantine_path,
                            "rb"
                        ) as f:

                            quarantine_data = f.read()


                # =====================================================
                # SUCCESS
                # =====================================================

                st.success(
                    "Analysis completed successfully!"
                )

                st.divider()


                # =====================================================
                # RESULTS TITLE
                # =====================================================

                st.markdown(
                    '<div class="section-title">'
                    '📊 Analysis Results'
                    '</div>',
                    unsafe_allow_html=True
                )


                # =====================================================
                # TABS
                # =====================================================

                (
                    tab_overview,
                    tab_normalized,
                    tab_quarantine,
                    tab_raw
                ) = st.tabs(
                    [
                        "📊 Overview",
                        f"✅ Normalized ({len(normalized_events)})",
                        f"⚠️ Quarantined ({len(quarantined_events)})",
                        "📄 Raw Input"
                    ]
                )


                # =====================================================
                # OVERVIEW TAB
                # =====================================================

                with tab_overview:

                    st.markdown(
                        "### 📊 Analysis Summary"
                    )


                    # =================================================
                    # MAIN METRICS
                    # =================================================

                    col1, col2, col3, col4 = st.columns(
                        4
                    )


                    with col1:

                        st.metric(
                            "Total Events",
                            summary["events_total"]
                        )


                    with col2:

                        st.metric(
                            "Normalized",
                            summary["normalized"]
                        )


                    with col3:

                        st.metric(
                            "Quarantined",
                            summary["quarantined"]
                        )


                    with col4:

                        success_rate = summary[
                            "success_rate"
                        ]

                        if success_rate is not None:

                            success_rate = (
                                f"{success_rate * 100:.1f}%"
                            )

                        else:

                            success_rate = "N/A"


                        st.metric(
                            "Success Rate",
                            success_rate
                        )


                    # =================================================
                    # PROCESSING STATISTICS
                    # =================================================

                    st.markdown(
                        "### ⚡ Processing Statistics"
                    )


                    col1, col2, col3 = st.columns(
                        3
                    )


                    with col1:

                        st.metric(
                            "Processing Time",
                            f'{summary["seconds"]} sec'
                        )


                    with col2:

                        st.metric(
                            "Events / Second",
                            summary["eps"]
                        )


                    with col3:

                        st.metric(
                            "Log Types",
                            len(
                                summary["per_type_ok"]
                            )
                        )


                    # =================================================
                    # LOG TYPE BREAKDOWN
                    # =================================================

                    if summary["per_type_ok"]:

                        st.markdown(
                            "### 🔍 Log Type Breakdown"
                        )


                        st.bar_chart(
                            summary["per_type_ok"]
                        )


                        # =============================================
                        # LOG TYPE DETAILS
                        # =============================================

                        st.markdown(
                            "### 📋 Log Type Details"
                        )


                        total_events = (
                            summary["events_total"]
                        )


                        # =============================================
                        # TABLE HEADER
                        # =============================================

                        table_html = """
                        <div class="log-table">

                            <div class="log-table-header">

                                <div>
                                    Log Type
                                </div>

                                <div>
                                    Events
                                </div>

                                <div>
                                    Share
                                </div>

                            </div>
                        """


                        # =============================================
                        # TABLE ROWS
                        # =============================================

                        for (
                            log_type,
                            count
                        ) in sorted(
                            summary["per_type_ok"].items(),
                            key=lambda x: x[1],
                            reverse=True
                        ):

                            if total_events > 0:

                                share = (
                                    count /
                                    total_events
                                ) * 100

                            else:

                                share = 0


                            bar_width = min(
                                share,
                                100
                            )


                            table_html += f"""
                            <div class="log-table-row">

                                <div class="log-type-name">
                                    {log_type}
                                </div>

                                <div class="log-events">
                                    {count}
                                </div>

                                <div class="share-container">

                                    <div class="share-bar-background">

                                        <div
                                            class="share-bar"
                                            style="width: {bar_width}%;">
                                        </div>

                                    </div>

                                    <div class="share-value">
                                        {share:.1f}%
                                    </div>

                                </div>

                            </div>
                            """


                        # =============================================
                        # CLOSE TABLE
                        # =============================================

                        table_html += """
                        </div>
                        """


                        # =============================================
                        # RENDER TABLE
                        # =============================================

                        st.html(
                            table_html
                        )


                # =====================================================
                # NORMALIZED EVENTS TAB
                # =====================================================

                with tab_normalized:

                    # =================================================
                    # HEADING + DOWNLOAD BUTTON
                    # =================================================

                    col1, col2 = st.columns(
                        [3, 1]
                    )


                    with col1:

                        st.markdown(
                            "### ✅ Normalized Events"
                        )


                    with col2:

                        if normalized_events:

                            st.download_button(
                                label="⬇️ Download JSONL",
                                data=normalized_data,
                                file_name="normalized.jsonl",
                                mime="application/json",
                                use_container_width=True
                            )


                    # =================================================
                    # JSON
                    # =================================================

                    if normalized_events:

                        st.caption(
                            f"{len(normalized_events)} "
                            "events successfully normalized"
                        )


                        st.code(
                            json.dumps(
                                normalized_events,
                                indent=2
                            ),
                            language="json"
                        )


                    else:

                        st.info(
                            "No events were successfully "
                            "normalized."
                        )


                # =====================================================
                # QUARANTINED EVENTS TAB
                # =====================================================

                with tab_quarantine:

                    # =================================================
                    # HEADING + DOWNLOAD BUTTON
                    # =================================================

                    col1, col2 = st.columns(
                        [3, 1]
                    )


                    with col1:

                        st.markdown(
                            "### ⚠️ Quarantined Events"
                        )


                    with col2:

                        if quarantined_events:

                            st.download_button(
                                label="⬇️ Download JSONL",
                                data=quarantine_data,
                                file_name="quarantine.jsonl",
                                mime="application/json",
                                use_container_width=True
                            )


                    # =================================================
                    # JSON
                    # =================================================

                    if quarantined_events:

                        st.warning(
                            f"{len(quarantined_events)} "
                            "events were quarantined."
                        )


                        st.code(
                            json.dumps(
                                quarantined_events,
                                indent=2
                            ),
                            language="json"
                        )


                    else:

                        st.success(
                            "No events were quarantined."
                        )


                # =====================================================
                # RAW INPUT TAB
                # =====================================================

                with tab_raw:

                    st.markdown(
                        "### 📄 Raw Input"
                    )


                    st.caption(
                        f"Original file: {uploaded_file.name}"
                    )


                    content = (
                        uploaded_file
                        .getvalue()
                        .decode(
                            "utf-8",
                            errors="replace"
                        )
                    )


                    st.code(
                        content,
                        language="text"
                    )


            # =========================================================
            # ERROR HANDLING
            # =========================================================

            except Exception as e:

                st.error(
                    f"Error while processing logs: {e}"
                )