import base64
import html
from functools import lru_cache
from pathlib import Path

import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ASSETS_DIR = PROJECT_ROOT / "assets"


@lru_cache(maxsize=None)
def _uri(name: str) -> str:
    encoded = base64.b64encode((ASSETS_DIR / name).read_bytes()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


_CSS = """
<style>
:root {
  --bg: #070c14;
  --panel: #0e1827;
  --panel-2: #122033;
  --line: rgba(143, 179, 201, 0.18);
  --text: #e8f1f7;
  --muted: #8ba3b8;
  --amber: #f5a524;
  --teal: #35d0c0;
  --red: #d64545;
}

[data-testid="stAppViewContainer"] {
  background:
    linear-gradient(180deg, rgba(7, 12, 20, 0.88), rgba(7, 12, 20, 0.96)),
    url("__BANNER_URI__") center / cover no-repeat fixed;
  color: var(--text);
}

[data-testid="stMain"],
[data-testid="stMainBlockContainer"] {
  position: relative;
  z-index: 2;
}

.main .block-container,
[data-testid="stMainBlockContainer"] {
  padding-top: 4.4rem;
  padding-bottom: 2.5rem;
  max-width: 1500px;
}

/* ---- Top header bar ---- */
[data-testid="stHeader"],
.stAppHeader {
  height: 3.25rem;
  min-height: 3.25rem;
  background: linear-gradient(90deg, rgba(10, 17, 28, 0.94) 0%, rgba(13, 24, 39, 0.9) 50%, rgba(10, 17, 28, 0.94) 100%);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border-bottom: 1px solid rgba(143, 179, 201, 0.12);
  box-shadow: 0 6px 22px rgba(0, 0, 0, 0.35);
  display: flex;
  align-items: center;
  padding: 0;
}

/* Thin amber → teal accent line under the header */
[data-testid="stHeader"]::after,
.stAppHeader::after {
  content: "";
  position: absolute;
  left: 0;
  right: 0;
  bottom: -1px;
  height: 2px;
  background: linear-gradient(90deg, transparent 0%, var(--amber) 22%, var(--teal) 78%, transparent 100%);
  opacity: 0.7;
  pointer-events: none;
}

/* Status label on the left of the header */
[data-testid="stHeader"]::before,
.stAppHeader::before {
  content: "●  SECURE SESSION  ·  TRACE AI  //  CYBER EVIDENCE WORKSPACE";
  position: absolute;
  left: 1.5rem;
  top: 50%;
  transform: translateY(-50%);
  font-family: "JetBrains Mono", "Fira Code", ui-monospace, monospace;
  font-size: 0.72rem;
  letter-spacing: 0.22em;
  color: var(--muted);
  white-space: nowrap;
  pointer-events: none;
}

[data-testid="stDecoration"] {
  display: none;
}

[data-testid="stToolbar"],
.stAppToolbar {
  justify-content: flex-end;
  align-items: center;
  gap: 0.5rem;
  padding-right: 1rem;
  top: 50%;
  transform: translateY(-50%);
}

[data-testid="stMainMenu"] button,
[data-testid="stToolbar"] button {
  border: 1px solid var(--line);
  border-radius: 9px;
  background: rgba(14, 24, 39, 0.8);
  color: var(--muted);
  transition: all 0.18s ease;
}

[data-testid="stMainMenu"] button:hover,
[data-testid="stToolbar"] button:hover {
  border-color: rgba(245, 165, 36, 0.6);
  color: var(--amber);
  background: rgba(245, 165, 36, 0.08);
}

/* Hide the header label when the sidebar is open on narrow screens */
@media (max-width: 1100px) {
  [data-testid="stHeader"]::before,
  .stAppHeader::before { display: none; }
}

.stAppDeployButton,
[data-testid="stAppDeployButton"] {
  display: none !important;
}

[data-testid="stSidebar"] {
  position: relative;
  z-index: 3;
  background: linear-gradient(180deg, #0d1827 0%, #080e17 100%);
  border-right: 1px solid var(--line);
}

[data-testid="stSidebar"] [data-testid="stSidebarContent"] {
  padding-top: 1rem;
}

[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 {
  color: var(--amber);
  letter-spacing: 0.08em;
}

h1, h2, h3, h4 {
  color: var(--text);
}

.stTabs [role="tab"] {
  background: rgba(14, 24, 39, 0.86);
  border: 1px solid var(--line);
  border-radius: 11px;
  color: var(--muted);
  font-weight: 650;
  padding: 0.55rem 0.85rem;
  margin-right: 0.35rem;
  transition: all 0.18s ease;
}

.stTabs [role="tab"]:hover {
  color: var(--text);
  border-color: rgba(245, 165, 36, 0.55);
}

.stTabs [aria-selected="true"] {
  background: linear-gradient(120deg, var(--amber), #d97706);
  border-color: transparent;
  color: #0a111b;
  box-shadow: 0 8px 24px rgba(245, 165, 36, 0.22);
}

.stButton button,
.stFormSubmitButton button {
  background: linear-gradient(120deg, var(--amber), #d97706);
  border: 1px solid rgba(255, 211, 126, 0.45);
  border-radius: 10px;
  color: #09111b;
  font-weight: 750;
  letter-spacing: 0.02em;
  box-shadow: 0 6px 18px rgba(245, 165, 36, 0.16);
}

.stButton button:hover,
.stFormSubmitButton button:hover {
  filter: brightness(1.08);
  transform: translateY(-1px);
}

.stDownloadButton button {
  background: linear-gradient(120deg, var(--teal), #12998d);
  border: 1px solid rgba(153, 246, 234, 0.45);
  border-radius: 10px;
  color: #061319;
  font-weight: 750;
}

.stButton button:disabled,
.stDownloadButton button:disabled,
.stFormSubmitButton button:disabled {
  background: rgba(90, 108, 126, 0.34);
  border-color: rgba(143, 179, 201, 0.18);
  color: rgba(232, 241, 247, 0.48);
  box-shadow: none;
  transform: none;
}

.stTextInput input,
.stTextArea textarea,
.stSelectbox [data-baseweb="select"] > div,
.stNumberInput [data-baseweb="input"] {
  background: rgba(11, 20, 32, 0.92) !important;
  border: 1px solid var(--line) !important;
  border-radius: 10px !important;
  color: var(--text) !important;
}

.stTextInput input:focus,
.stTextArea textarea:focus {
  border-color: var(--teal) !important;
  box-shadow: 0 0 0 2px rgba(53, 208, 192, 0.16) !important;
}

[data-testid="stDataFrame"] {
  border: 1px solid var(--line);
  border-radius: 14px;
  overflow: hidden;
  box-shadow: 0 14px 36px rgba(0, 0, 0, 0.28);
}

[data-testid="stExpander"] {
  background: rgba(13, 24, 39, 0.82);
  border: 1px solid var(--line);
  border-radius: 14px;
  overflow: hidden;
}

[data-testid="stExpander"] summary {
  color: var(--text);
  font-weight: 600;
}

[data-testid="stChatMessage"] {
  background: rgba(13, 24, 39, 0.86);
  border: 1px solid var(--line);
  border-radius: 16px;
  padding: 0.65rem 0.8rem;
}

[data-testid="stChatInput"] textarea {
  background: rgba(11, 20, 32, 0.95) !important;
  border: 1px solid rgba(53, 208, 192, 0.4) !important;
  border-radius: 14px !important;
  color: var(--text) !important;
}

[data-testid="stAlert"] {
  border-radius: 12px;
}

hr {
  border-color: var(--line);
}

.stCaption {
  color: var(--muted) !important;
}

.case-hero {
  position: relative;
  display: grid;
  grid-template-columns: 1.05fr 0.95fr;
  gap: 1.4rem;
  align-items: center;
  padding: 1.45rem 1.65rem;
  margin-bottom: 1.2rem;
  border: 1px solid rgba(245, 165, 36, 0.34);
  border-radius: 22px;
  background: linear-gradient(115deg, rgba(10, 19, 31, 0.97), rgba(21, 32, 47, 0.92));
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.48);
  overflow: hidden;
}

.case-hero::after {
  content: "";
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg, transparent 35%, rgba(245, 165, 36, 0.07));
  pointer-events: none;
}

.hero-eyebrow {
  display: flex;
  align-items: center;
  gap: 0.55rem;
  color: var(--teal);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.72rem;
  letter-spacing: 0.22em;
  text-transform: uppercase;
}

.pulse {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--teal);
  box-shadow: 0 0 0 0 rgba(53, 208, 192, 0.7);
  animation: pulse 2s infinite;
}

@keyframes pulse {
  70% { box-shadow: 0 0 0 10px rgba(53, 208, 192, 0); }
  100% { box-shadow: 0 0 0 0 rgba(53, 208, 192, 0); }
}

.hero-title {
  margin: 0.45rem 0 0.1rem;
  font-size: clamp(2.4rem, 5vw, 4.2rem);
  font-weight: 850;
  letter-spacing: -0.045em;
  line-height: 0.95;
  color: #f4f8fb;
}

.hero-title span {
  color: var(--amber);
}

.hero-subtitle {
  margin: 0.35rem 0 0;
  color: #a8bdd0;
  font-size: 0.95rem;
  letter-spacing: 0.02em;
}

.hero-meta {
  margin-top: 0.9rem;
  color: #7f98ae;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.75rem;
  letter-spacing: 0.08em;
}

.metric-strip {
  display: flex;
  flex-wrap: wrap;
  gap: 0.65rem;
  margin-top: 1rem;
}

.metric-card {
  min-width: 116px;
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: rgba(8, 15, 25, 0.72);
}

.metric-card span {
  display: block;
  color: #7f98ae;
  font-size: 0.62rem;
  letter-spacing: 0.16em;
  text-transform: uppercase;
}

.metric-card strong {
  color: var(--amber);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 1.2rem;
}

.hero-art img {
  width: 100%;
  display: block;
  border: 1px solid rgba(143, 179, 201, 0.28);
  border-radius: 16px;
  box-shadow: 0 16px 38px rgba(0, 0, 0, 0.45);
  transform: rotate(1.2deg);
}

.classified-stamp {
  position: absolute;
  top: 1.1rem;
  right: 1.5rem;
  padding: 0.3rem 0.65rem;
  border: 2px solid rgba(214, 69, 69, 0.75);
  border-radius: 5px;
  color: #ff8a8a;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.68rem;
  letter-spacing: 0.18em;
  transform: rotate(7deg);
  opacity: 0.92;
}

.sidebar-brand {
  display: flex;
  align-items: center;
  gap: 0.7rem;
  padding: 0.25rem 0.2rem 0.9rem;
  margin-bottom: 0.6rem;
  border-bottom: 1px solid var(--line);
}

.sidebar-brand img {
  width: 50px;
  height: 50px;
}

.sidebar-brand strong {
  display: block;
  color: var(--amber);
  font-size: 1.05rem;
  letter-spacing: 0.16em;
}

.sidebar-brand small {
  display: block;
  color: #7f98ae;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.62rem;
  letter-spacing: 0.14em;
}

.section-head {
  display: flex;
  align-items: center;
  gap: 0.85rem;
  padding: 0.15rem 0 1rem;
}

.section-head img {
  width: 46px;
  height: 46px;
  flex: none;
}

.section-head h2 {
  margin: 0;
  color: #f0f6fa;
  font-size: 1.08rem;
  letter-spacing: 0.16em;
  text-transform: uppercase;
}

.section-head p {
  margin: 0.15rem 0 0;
  color: #8ba3b8;
  font-size: 0.8rem;
}

@media (max-width: 900px) {
  .case-hero { grid-template-columns: 1fr; }
  .hero-art { display: none; }
  .classified-stamp { top: 0.6rem; right: 0.7rem; }
}

.auth-card-head {
  text-align: center;
  margin: 1.5rem 0 1.25rem;
}
.auth-card-head .auth-kicker {
  font-family: "JetBrains Mono", ui-monospace, monospace;
  font-size: 0.72rem;
  letter-spacing: 0.22em;
  color: var(--teal);
}
.auth-card-head h1 {
  color: var(--amber);
  font-size: 3rem;
  font-weight: 800;
  letter-spacing: -0.02em;
  margin: 0.4rem 0 0.2rem;
}
.auth-card-head p { color: var(--muted); margin: 0; }

footer {visibility: hidden;}
</style>
"""


def apply_theme() -> None:
    st.markdown(_CSS.replace("__BANNER_URI__", _uri("case_banner.svg")), unsafe_allow_html=True)


def sidebar_brand() -> None:
    st.markdown(
        f"""
        <div class="sidebar-brand">
          <img src="{_uri('badge.svg')}" alt="TRACE AI badge" />
          <div>
            <strong>TRACE AI</strong>
            <small>EVIDENCE RESPONSE UNIT</small>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def hero(case_id: str, case_name: str, evidence_count: int, lead_count: int, activity_count: int) -> None:
    st.markdown(
        f"""
        <div class="case-hero">
          <div class="hero-copy">
            <div class="hero-eyebrow"><span class="pulse"></span> Cyber evidence unit · active case file</div>
            <h1 class="hero-title">TRACE <span>AI</span></h1>
            <p class="hero-subtitle">Traceable Research and Analysis for Cyber Evidence</p>
            <div class="hero-meta">CASE {html.escape(case_id)} // {html.escape(case_name)}</div>
            <div class="metric-strip">
              <div class="metric-card"><span>Evidence</span><strong>{evidence_count:02d}</strong></div>
              <div class="metric-card"><span>Leads</span><strong>{lead_count:02d}</strong></div>
              <div class="metric-card"><span>Log entries</span><strong>{activity_count:02d}</strong></div>
            </div>
          </div>
          <div class="hero-art"><img src="{_uri('case_banner.svg')}" alt="Investigation evidence board" /></div>
          <div class="classified-stamp">CASE FILE // RESTRICTED</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_header(title: str, subtitle: str, icon: str) -> None:
    st.markdown(
        f"""
        <div class="section-head">
          <img src="{_uri(icon)}" alt="" />
          <div><h2>{html.escape(title)}</h2><p>{html.escape(subtitle)}</p></div>
        </div>
        """,
        unsafe_allow_html=True,
    )
