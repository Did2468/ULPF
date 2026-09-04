import json
import os
import tempfile

import streamlit as st

import ulpf


# --------------------------------------------------
# Project paths
# --------------------------------------------------

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH = os.path.join(
    PROJECT_ROOT,
    "models",
    "log_type_clf.joblib"
)

PLUGINS_PATH = os.path.join(
    PROJECT_ROOT,
    "plugins"
)


# --------------------------------------------------
# Streamlit configuration
# --------------------------------------------------

st.set_page_config(
    page_title="ULPF",
    page_icon="🔐",
    layout="wide"
)


# --------------------------------------------------
# Header
# --------------------------------------------------

st.title("🔐 Universal Log Pre-processing Framework")
st.write(
    "Upload a log file to classify, parse and normalize events."
)

st.divider()


# --------------------------------------------------
# Sidebar
# --------------------------------------------------

st.sidebar.title("ULPF")

threshold = st.sidebar.slider(
    "Classification Confidence",
    min_value=0.0,
    max_value=1.0,
    value=0.60,
    step=0.05
)

st.sidebar.info(
    "Logs below the confidence threshold "
    "are sent to quarantine."
)


# --------------------------------------------------
# File upload
# --------------------------------------------------

uploaded_file = st.file_uploader(
    "Upload a log file",
    type=["log", "txt"],
)


# --------------------------------------------------
# Analyze
# --------------------------------------------------

if uploaded_file is not None:

    st.success(f"File loaded: {uploaded_file.name}")

    # Show raw log
    with st.expander("View Raw Logs"):
        content = uploaded_file.getvalue().decode(
            "utf-8",
            errors="replace"
        )

        st.text_area(
            "Raw log",
            content,
            height=300
        )

    if st.button(
        "🚀 Analyze Logs",
        type="primary",
        use_container_width=True
    ):

        with st.spinner("Processing logs..."):

            try:

                # Temporary working directory
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

                    # Save uploaded file
                    with open(
                        input_path,
                        "wb"
                    ) as f:
                        f.write(uploaded_file.getvalue())

                    # ------------------------------------------
                    # Existing ULPF backend
                    # ------------------------------------------

                    classifier = ulpf.LogTypeClassifier(
                        MODEL_PATH,
                        threshold
                    )

                    registry = ulpf.Registry(
                        PLUGINS_PATH,
                        self_test=True,
                        strict=False
                    )

                    sink = ulpf.JsonlSink(output_path)

                    with open(
                        quarantine_path,
                        "w",
                        encoding="utf-8"
                    ) as qfh:

                        quarantine = ulpf.Quarantine(qfh)

                        pipeline = ulpf.Pipeline(
                            classifier,
                            registry,
                            sink,
                            quarantine
                        )

                        pipeline.process_file(input_path)

                        summary = pipeline.summary()

                    sink.close()

                    # ------------------------------------------
                    # Read results
                    # ------------------------------------------

                    normalized_events = []

                    if os.path.exists(output_path):

                        with open(
                            output_path,
                            encoding="utf-8"
                        ) as f:

                            for line in f:
                                if line.strip():
                                    normalized_events.append(
                                        json.loads(line)
                                    )

                    quarantined_events = []

                    if os.path.exists(quarantine_path):

                        with open(
                            quarantine_path,
                            encoding="utf-8"
                        ) as f:

                            for line in f:
                                if line.strip():
                                    quarantined_events.append(
                                        json.loads(line)
                                    )

                # ------------------------------------------
                # Display results
                # ------------------------------------------

                st.success("Analysis completed!")

                st.divider()

                # Metrics
                col1, col2, col3, col4 = st.columns(4)

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
                    success_rate = summary["success_rate"]

                    if success_rate is not None:
                        success_rate = f"{success_rate * 100:.1f}%"
                    else:
                        success_rate = "N/A"

                    st.metric(
                        "Success Rate",
                        success_rate
                    )

                # ------------------------------------------
                # Processing information
                # ------------------------------------------

                st.subheader("📊 Processing Statistics")

                col1, col2, col3 = st.columns(3)

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
                        len(summary["per_type_ok"])
                    )

                # ------------------------------------------
                # Log type breakdown
                # ------------------------------------------

                if summary["per_type_ok"]:

                    st.subheader("🔍 Log Type Breakdown")

                    st.bar_chart(
                        summary["per_type_ok"]
                    )

                # ------------------------------------------
                # Normalized events
                # ------------------------------------------

                st.subheader("✅ Normalized Events")

                if normalized_events:

                    st.json(normalized_events)

                else:

                    st.info(
                        "No events were successfully normalized."
                    )

                # ------------------------------------------
                # Quarantine
                # ------------------------------------------

                st.subheader("⚠️ Quarantined Events")

                if quarantined_events:

                    st.warning(
                        f"{len(quarantined_events)} "
                        "events were quarantined."
                    )

                    st.json(quarantined_events)

                else:

                    st.success(
                        "No events were quarantined."
                    )

            except Exception as e:

                st.error(
                    f"Error while processing logs: {e}"
                )