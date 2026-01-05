import logging
from datetime import datetime

import streamlit as st


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with consistent formatting.

    Args:
        name: The name of the logger (typically __name__).

    Returns:
        A configured logger instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def log_runtime_error(msg: str):
    """Log a runtime error to the session state."""
    if "runtime_logs" not in st.session_state:
        st.session_state["runtime_logs"] = []

    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state["runtime_logs"].append(f"[{timestamp}] {msg}")
