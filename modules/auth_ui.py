"""Streamlit screens for sign-in, officer registration, and the admin panel."""

from __future__ import annotations

from typing import Any

import streamlit as st

from modules import auth
from modules.theme import sidebar_brand

TOKEN_KEY = "auth_token"


def current_user() -> dict[str, Any] | None:
    """Verify the session's JWT on every rerun. Clears it if it is no longer valid."""
    user = auth.verify_token(st.session_state.get(TOKEN_KEY))
    if user is None:
        st.session_state.pop(TOKEN_KEY, None)
    return user


def logout() -> None:
    for key in list(st.session_state):
        del st.session_state[key]


def require_login() -> dict[str, Any]:
    """Return the signed-in, admin-approved user, or render the login page and stop."""
    user = current_user()
    if user:
        return user

    with st.sidebar:
        sidebar_brand()
        st.caption("Restricted system. Authorized police personnel only.")

    _, center, _ = st.columns([1, 1.4, 1])
    with center:
        st.markdown(
            """
            <div class="auth-card-head">
              <span class="auth-kicker">● SECURE ACCESS · CYBER EVIDENCE UNIT</span>
              <h1>TRACE AI</h1>
              <p>Sign in with your approved officer account.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if not auth.admin_exists():
            st.warning(
                "No administrator account exists yet. On the server, run:\n\n"
                "`python -m modules.auth create-admin`",
                icon=":material/admin_panel_settings:",
            )

        sign_in, register = st.tabs([":material/login: Sign in", ":material/person_add: Request access"])

        with sign_in:
            with st.form("login_form"):
                email = st.text_input("Official email", placeholder="officer@police.gov.in")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Sign in", type="primary", width="stretch")
            if submitted:
                try:
                    st.session_state[TOKEN_KEY] = auth.authenticate(email, password)
                except auth.AuthError as exc:
                    st.error(str(exc), icon=":material/lock:")
                else:
                    st.rerun()

        with register:
            st.caption(
                "New accounts stay locked until an administrator verifies your identity "
                "and approves the request."
            )
            with st.form("register_form", clear_on_submit=True):
                full_name = st.text_input("Full name")
                badge = st.text_input("Badge / employee number")
                station = st.text_input("Police station / unit")
                reg_email = st.text_input("Official email")
                reg_password = st.text_input(
                    "Password", type="password",
                    help=f"At least {auth.MIN_PASSWORD_LENGTH} characters, with letters and numbers.",
                )
                reg_confirm = st.text_input("Confirm password", type="password")
                reg_submitted = st.form_submit_button("Submit request", width="stretch")
            if reg_submitted:
                if reg_password != reg_confirm:
                    st.error("Passwords do not match.")
                else:
                    try:
                        auth.register_officer(reg_email, reg_password, full_name, badge, station)
                    except auth.AuthError as exc:
                        st.error(str(exc))
                    else:
                        st.success(
                            "Request submitted. You can sign in after an administrator approves it.",
                            icon=":material/hourglass_top:",
                        )
    st.stop()


def sidebar_account(user: dict[str, Any]) -> None:
    with st.sidebar.container(border=True):
        role_badge = "Admin" if user["role"] == "admin" else "Officer"
        st.markdown(f"**{user['full_name']}**  \n:orange-badge[{role_badge}] `{user['badge_number']}`")
        st.caption(user["email"])
        if st.button("Sign out", icon=":material/logout:", key="logout_button", width="stretch"):
            logout()
            st.rerun()


_STATUS_LABEL = {
    "pending": ":orange-badge[Pending]",
    "approved": ":green-badge[Approved]",
    "rejected": ":red-badge[Rejected]",
    "disabled": ":gray-badge[Disabled]",
}


def admin_panel(admin: dict[str, Any]) -> None:
    """Approve, reject, disable, and change roles of officer accounts."""
    users = auth.list_users()
    pending = [u for u in users if u["status"] == "pending"]

    st.subheader(f"Pending access requests ({len(pending)})")
    if not pending:
        st.caption("No requests waiting for approval.")
    for user in pending:
        with st.container(border=True):
            info, actions = st.columns([3, 2], vertical_alignment="center")
            with info:
                st.markdown(
                    f"**{user['full_name']}** · `{user['badge_number']}`  \n"
                    f"{user['email']} · {user['police_station'] or 'Unit not given'}"
                )
                st.caption(f"Requested {user['created_at'][:16].replace('T', ' ')} UTC")
            with actions:
                with st.container(horizontal=True):
                    if st.button("Approve", key=f"approve_{user['user_id']}", type="primary",
                                 icon=":material/check:"):
                        _admin_action(auth.set_user_status, admin, user["user_id"], "approved")
                    if st.button("Reject", key=f"reject_{user['user_id']}", icon=":material/close:"):
                        _admin_action(auth.set_user_status, admin, user["user_id"], "rejected")

    st.subheader("All accounts")
    for user in users:
        if user["status"] == "pending":
            continue
        is_self = user["user_id"] == admin["user_id"]
        with st.container(border=True):
            info, actions = st.columns([3, 2], vertical_alignment="center")
            with info:
                you = " (you)" if is_self else ""
                st.markdown(
                    f"**{user['full_name']}**{you} · {_STATUS_LABEL[user['status']]} "
                    f":blue-badge[{user['role'].title()}]  \n{user['email']} · `{user['badge_number']}`"
                )
                last = user["last_login_at"]
                st.caption(f"Last sign-in: {last[:16].replace('T', ' ') + ' UTC' if last else 'never'}")
            with actions:
                if is_self:
                    st.caption("You cannot change your own account here.")
                    continue
                with st.container(horizontal=True):
                    if user["status"] == "approved":
                        if st.button("Disable", key=f"disable_{user['user_id']}", icon=":material/block:"):
                            _admin_action(auth.set_user_status, admin, user["user_id"], "disabled")
                    else:
                        if st.button("Re-enable", key=f"enable_{user['user_id']}", icon=":material/check:"):
                            _admin_action(auth.set_user_status, admin, user["user_id"], "approved")
                    new_role = "officer" if user["role"] == "admin" else "admin"
                    label = "Make officer" if new_role == "officer" else "Make admin"
                    if st.button(label, key=f"role_{user['user_id']}", icon=":material/manage_accounts:"):
                        _admin_action(auth.set_user_role, admin, user["user_id"], new_role)

    with st.expander("Sign-in audit log", icon=":material/history:"):
        log = auth.list_auth_log()
        if log:
            st.dataframe(log, hide_index=True)
        else:
            st.caption("No events yet.")


def _admin_action(func, admin: dict[str, Any], user_id: str, value: str) -> None:
    try:
        func(admin, user_id, value)
    except auth.AuthError as exc:
        st.error(str(exc))
    else:
        st.rerun()
