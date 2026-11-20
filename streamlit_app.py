"""Entry point for Streamlit Community Cloud and the devcontainer.

The application lives in app.py; this file simply runs it so either
`streamlit run streamlit_app.py` or `streamlit run app.py` works.
"""

import runpy
from pathlib import Path

runpy.run_path(str(Path(__file__).with_name("app.py")), run_name="__main__")
