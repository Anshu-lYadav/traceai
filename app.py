import json
from datetime import datetime, time as dtime
from pathlib import Path
from zoneinfo import ZoneInfo

import streamlit as st

from modules import access, auth, database, jobs
from modules.anomaly_engine import analyze_structured_evidence
from modules.auth import initialize_auth
from modules.auth_ui import admin_panel, require_login, sidebar_account
from modules.database import (
    CUSTODY_ACTIONS,
    add_custody_event,
    clear_chat,
    count_evidence_chunks,
    count_timeline,
    delete_case,
    delete_evidence,
    ensure_default_case,
    get_provenance,
    get_translation,
    initialize_database,
    list_activity,
    list_chat_messages,
    list_custody,
    list_evidence,
    list_leads,
    list_reports,
    load_analysis_result,
    log_activity,
    query_timeline,
    read_original,
    record_provenance,
    save_analysis_result,
    save_chat_message,
    save_leads,
    save_report,
    update_lead_status,
    verify_audit_chain,
    verify_original,
)
from modules.embedding_engine import EMBEDDING_MODEL
from modules.evidence_processor import IMAGE_EXTENSIONS, LARGE_FILE_EXTENSIONS, SUPPORTED_EXTENSIONS
from modules.i18n import tr
from modules.llm_engine import generate_answer, generate_case_report, resolve_followup_query
from modules.recommendation_engine import generate_investigative_leads
from modules.relationship_engine import (
    build_relationship_graph,
    render_relationship_graph,
    supporting_records,
)
from modules.report_generator import make_case_diary, make_custody_report, make_pdf, make_report
from modules.search_engine import search_evidence
from modules.theme import apply_theme, hero, section_header, sidebar_brand

st.set_page_config(page_title="TRACE AI", page_icon="🛡️", layout="wide")
apply_theme()
initialize_database()
initialize_auth()

# Nothing below this line runs unless the session holds a valid JWT for an
# admin-approved account.
current_user = require_login()
database.set_actor(current_user["email"])
jobs.ensure_workers()
ensure_default_case()

ACQUISITION_METHODS = [
    "Logical extraction (device)", "Physical extraction (device)", "Disk imaging (write-blocked)",
    "Memory acquisition", "Network capture", "Cloud / service-provider disclosure",
    "Export / screenshot by complainant", "Seized document / printout", "Other",
]
TIMEZONES = {"IST (Asia/Kolkata)": "Asia/Kolkata", "UTC": "UTC"}

with st.sidebar:
    sidebar_brand()
    sidebar_account(current_user)
    interface_language = st.selectbox("Interface language / इंटरफ़ेस भाषा", ["English", "हिन्दी"], key="interface_language")


def T(text: str) -> str:
    return tr(text, interface_language)


with st.sidebar:
    if database.DB_ENCRYPTED:
        st.caption(":material/lock: " + T("Database and evidence encrypted at rest (AES-256)."))
    else:
        st.warning(T("SQLCipher is not installed: the database is NOT encrypted. Evidence files are still encrypted."))
    st.header(T("Investigation"))
    with st.expander(T("Create a case")):
        with st.form("create_case_form", clear_on_submit=True):
            new_case_id = st.text_input(T("Case ID"), placeholder="CASE-002")
            new_case_name = st.text_input(T("Case name"), placeholder="FIR 123/2026 — cyber fraud")
            new_case_description = st.text_area(T("Description (optional)"))
            create_submitted = st.form_submit_button(T("Create case"))
        if create_submitted:
            try:
                database.create_case(new_case_id, new_case_name, new_case_description,
                                     created_by_user_id=current_user["user_id"])
                st.session_state.active_case_selector = new_case_id.strip()
                st.rerun()
            except Exception as exc:
                st.error(f"{T('Could not create case')}: {exc}")

    cases = access.accessible_cases(current_user)
    if not cases:
        st.info(T("You are not a member of any case yet. Create a case or ask a case lead to add you."))
        st.stop()
    case_ids = [case["case_id"] for case in cases]
    preferred_id = st.session_state.get("active_case_id", case_ids[0])
    if preferred_id not in case_ids:
        preferred_id = case_ids[0]
    if st.session_state.get("active_case_selector") not in case_ids:
        st.session_state.active_case_selector = preferred_id
    case_id = st.selectbox(T("Active case"), case_ids, key="active_case_selector")
    st.session_state.active_case_id = case_id
    active_case = next(case for case in cases if case["case_id"] == case_id)

    my_role = access.case_role(current_user, case_id)
    can_edit = access.can(current_user, case_id, "edit")
    can_manage = access.can(current_user, case_id, "manage")
    st.caption(f'{T("Your role in this case")}: **{my_role}**')

    with st.expander(T("Case team"), icon=":material/group:"):
        for member in database.list_case_members(case_id):
            member_user = auth.get_user(member["user_id"])
            label = member_user["email"] if member_user else member["user_id"]
            cols = st.columns([3, 1], vertical_alignment="center")
            cols[0].markdown(f"{label}  \n:blue-badge[{member['case_role']}]")
            if can_manage and cols[1].button(":material/person_remove:", key=f"rm_{member['user_id']}",
                                             help=T("Remove from case")):
                try:
                    database.remove_case_member(case_id, member["user_id"], label)
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))
        if can_manage:
            with st.form(f"add_member_{case_id}", clear_on_submit=True):
                member_email = st.text_input(T("Officer email"))
                member_role = st.selectbox(T("Case role"), list(database.CASE_ROLES), index=1)
                if st.form_submit_button(T("Add or update member")):
                    target = auth.get_user_by_email(member_email)
                    if not target or target["status"] != "approved":
                        st.error(T("No approved officer account with that email."))
                    else:
                        database.set_case_member(case_id, target["user_id"], member_role, target["email"])
                        st.rerun()
        else:
            st.caption(T("Only the case lead or an admin can change the team."))

    if can_manage:
        with st.expander(T("Delete case")):
            st.warning(T(
                "This permanently removes the case's evidence originals, chat, leads and reports. "
                "The signed audit trail and chain-of-custody records are kept."
            ))
            case_delete_confirmation = st.text_input(
                T("Type case ID to confirm deletion"), key="delete_case_confirmation",
            )
            if st.button(T("Delete this case"), type="secondary",
                         disabled=case_delete_confirmation.strip() != case_id):
                try:
                    access.require(current_user, case_id, "manage")
                    result = delete_case(case_id)
                    for key in list(st.session_state):
                        if key.startswith(f"anomaly_{case_id}") or key.startswith(f"relationships_{case_id}"):
                            st.session_state.pop(key, None)
                    st.session_state.pop("active_case_selector", None)
                    st.session_state.pop("active_case_id", None)
                    st.session_state.delete_notice = f'{T("Deleted case")} {result["case_id"]}.'
                    st.rerun()
                except Exception as exc:
                    st.error(f"{T('Could not delete case')}: {exc}")

    st.caption(active_case["name"])
    if active_case["description"]:
        st.write(active_case["description"])
    st.info(T("Use only authorized evidence. Access is limited to case members and every action is recorded in a signed audit log."))

case_delete_notice = st.session_state.pop("delete_notice", None)
if case_delete_notice:
    st.success(case_delete_notice)

# Reload the active case on each rerun so cases stay isolated.
st.session_state.evidence = list_evidence(case_id)
st.session_state.chat_history = list_chat_messages(case_id)
case_activity = list_activity(case_id)
hero(case_id, active_case["name"], len(st.session_state.evidence), len(list_leads(case_id)), len(case_activity))
anomaly_key = f"anomaly_{case_id}"
relationship_key = f"relationships_{case_id}"
if anomaly_key not in st.session_state:
    st.session_state[anomaly_key] = load_analysis_result(case_id, "anomaly")
if relationship_key not in st.session_state:
    stored_relationships = load_analysis_result(case_id, "relationships")
    if stored_relationships:
        stored_relationships["html"] = render_relationship_graph(stored_relationships["catalog"])
    st.session_state[relationship_key] = stored_relationships

is_admin = access.is_admin(current_user)
tab_labels = [
    T("Evidence Vault"), T("Investigation Search"), T("AI Investigation Chat"), T("Timeline"),
    T("Anomaly Review"), T("Evidence Relationships"), T("Leads & Case Diary"), T("Case Report"),
    T("Audit & Custody"),
]
if is_admin:
    tab_labels.append(":material/admin_panel_settings: Admin")
tabs = st.tabs(tab_labels)
vault, search, chat, timeline, anomaly, relationships, operations, report, audit = tabs[:9]


def read_only_notice():
    st.caption(":material/visibility: " + T("You have view-only access to this case."))


# --------------------------------------------------------------------------- #
# Background jobs
# --------------------------------------------------------------------------- #
def render_jobs():
    job_rows = jobs.list_jobs(case_id, 15)
    if not job_rows:
        return
    finished = {j["job_id"] for j in job_rows if j["status"] in {"done", "failed"}}
    seen_key = f"seen_jobs_{case_id}"
    if seen_key not in st.session_state:
        st.session_state[seen_key] = finished
    elif finished - st.session_state[seen_key]:
        st.session_state[seen_key] = finished
        st.rerun()
    with st.expander(f'{T("Processing queue")} ({sum(j["status"] in {"queued", "running"} for j in job_rows)} {T("active")})',
                     expanded=any(j["status"] in {"queued", "running"} for j in job_rows),
                     icon=":material/pending_actions:"):
        st.dataframe([{
            T("Job"): job["label"], T("Status"): job["status"],
            T("Progress"): job["progress"], T("Message"): job["error"] or job["message"],
            T("Queued (UTC)"): job["created_at"][:19],
        } for job in job_rows], hide_index=True, width="stretch",
            column_config={T("Progress"): st.column_config.ProgressColumn(min_value=0.0, max_value=1.0)})


# --------------------------------------------------------------------------- #
# Evidence vault
# --------------------------------------------------------------------------- #
def provenance_fields(prefix: str) -> dict:
    left, right = st.columns(2)
    with left:
        source = st.text_input(T("Source (device / account / person)") + " *", key=f"{prefix}_source",
                               placeholder="Samsung A52 seized from complainant")
        device = st.text_input(T("Device identifier (IMEI / serial / account ID)"), key=f"{prefix}_device")
        acquired_by = st.text_input(T("Acquired by (name, rank, badge)") + " *", key=f"{prefix}_by",
                                    value=f'{current_user["full_name"]} ({current_user["badge_number"]})')
        method = st.selectbox(T("Acquisition method") + " *", ACQUISITION_METHODS, key=f"{prefix}_method")
        tool = st.text_input(T("Acquisition tool and version"), key=f"{prefix}_tool",
                             placeholder="FTK Imager 4.7 / Cellebrite UFED 7.x")
    with right:
        date_col, time_col, tz_col = st.columns([1.2, 1, 1.2])
        acquired_date = date_col.date_input(T("Acquired on") + " *", key=f"{prefix}_date")
        acquired_time = time_col.time_input(T("Time"), value=dtime(10, 0), key=f"{prefix}_time")
        tz_label = tz_col.selectbox(T("Time zone"), list(TIMEZONES), key=f"{prefix}_tz")
        authority = st.text_input(T("Legal authority (FIR / seizure memo / warrant no.)") + " *",
                                  key=f"{prefix}_authority")
        certificate = st.text_input(T("Section 63 BSA / 65B certificate reference"), key=f"{prefix}_cert")
        notes = st.text_area(T("Custody notes"), key=f"{prefix}_notes", height=68)
    acquired_at = datetime.combine(acquired_date, acquired_time, ZoneInfo(TIMEZONES[tz_label])).isoformat()
    return {"source_description": source, "device_identifier": device, "acquired_by": acquired_by,
            "acquisition_method": method, "acquisition_tool": tool, "acquired_at": acquired_at,
            "legal_authority": authority, "certificate_reference": certificate, "notes": notes}


def parse_hash_lines(text: str, filenames: list[str]) -> dict[str, str]:
    """Accept `sha256sum` output ('<hash>  <name>') or a single bare hash for one file."""
    mapping = {}
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    for line in lines:
        parts = line.replace("*", " ").split(maxsplit=1)
        if len(parts) == 2:
            mapping[Path(parts[1].strip()).name] = parts[0].lower()
        elif len(parts) == 1 and len(filenames) == 1 and len(lines) == 1:
            mapping[filenames[0]] = parts[0].lower()
    return mapping


with vault:
    section_header(T("Evidence Vault"), "Encrypted acquisition register · provenance, custody and hash verification",
                   "icon_evidence.svg")
    evidence_notice = st.session_state.pop("evidence_notice", None)
    if evidence_notice:
        st.success(evidence_notice)

    if can_edit:
        with st.expander(T("Add evidence with chain-of-custody details"), expanded=not st.session_state.evidence,
                         icon=":material/upload_file:"):
            with st.form(f"ingest_form_{case_id}", clear_on_submit=True):
                uploads = st.file_uploader(
                    T("Evidence files (documents, images, logs, EVTX, PCAP, disk and memory images)"),
                    type=sorted(ext.lstrip(".") for ext in SUPPORTED_EXTENSIONS),
                    accept_multiple_files=True,
                    key=f"uploads_{case_id}",
                )
                server_path = st.text_input(
                    T("Or import a large disk/memory image from the server import folder"),
                    placeholder=str(database.DATA_DIR / "import" / "suspect_laptop.E01"),
                    help=T("Large images are read on the server and streamed into the encrypted vault. "
                           "Allowed folders are set with TRACE_IMPORT_DIRS."),
                )
                st.markdown("**" + T("Provenance and chain of custody") + "**")
                no_provenance = st.checkbox(T("Provenance not available (training / fictional data only)"))
                provenance = provenance_fields(f"prov_{case_id}")
                hash_text = st.text_area(
                    T("Acquisition SHA-256 hashes (optional; `sha256sum` output or one hash for one file)"),
                    height=80, help=T("If supplied, the uploaded file must match exactly or it is rejected."),
                )
                queued = st.form_submit_button(T("Queue evidence for processing"), type="primary")
            if queued:
                filenames = [upload.name for upload in uploads or []]
                hashes = parse_hash_lines(hash_text, filenames + ([Path(server_path).name] if server_path else []))
                missing = [f for f in database.PROVENANCE_REQUIRED if not str(provenance.get(f, "")).strip()]
                if not uploads and not server_path.strip():
                    st.error(T("Choose at least one file or a server path."))
                elif not no_provenance and missing:
                    st.error(T("Fill in the required chain-of-custody fields (*)."))
                else:
                    count = 0
                    for upload in uploads or []:
                        record = None if no_provenance else {**provenance, "acquisition_sha256": hashes.get(upload.name, "")}
                        jobs.enqueue("ingest_upload", case_id, {
                            "staging_token": jobs.stage_upload(upload.getvalue()),
                            "filename": upload.name, "provenance": record, "label": upload.name,
                        }, current_user["email"])
                        count += 1
                    if server_path.strip():
                        name = Path(server_path.strip()).name
                        record = None if no_provenance else {**provenance, "acquisition_sha256": hashes.get(name, "")}
                        jobs.enqueue("ingest_path", case_id, {
                            "path": server_path.strip(), "filename": name, "provenance": record, "label": name,
                        }, current_user["email"])
                        count += 1
                    st.session_state.evidence_notice = f"{count} {T('item(s) queued. Processing continues in the background.')}"
                    st.rerun()
            large = ", ".join(sorted(LARGE_FILE_EXTENSIONS))
            st.caption(T("Disk and memory images") + f" ({large}) " + T("can be uploaded up to the server upload limit or imported from the server."))
    else:
        read_only_notice()

    active_jobs = jobs.active_job_count(case_id)
    st.fragment(run_every=3 if active_jobs else None)(render_jobs)()

    evidence = st.session_state.evidence
    if evidence:
        st.dataframe(
            [{
                T("Evidence ID"): item["evidence_id"],
                T("Filename"): item["filename"],
                T("Type"): item["file_type"],
                T("SHA-256"): item["sha256"],
                T("Extracted characters"): len(item.get("text", "")),
                T("Uploaded bytes"): item["raw_bytes"],
                T("Extraction status"): item["extraction_status"],
                T("Ingested at (UTC)"): item["ingested_at"][:19],
            } for item in evidence],
            width="stretch", hide_index=True,
        )
        evidence_by_id = {item["evidence_id"]: item for item in evidence}
        selected_id = st.selectbox(
            T("Inspect evidence"), list(evidence_by_id),
            format_func=lambda eid: f'{eid} · {evidence_by_id[eid]["filename"]}', key=f"inspect_{case_id}",
        )
        item = evidence_by_id[selected_id]
        content_tab, custody_tab, translate_tab, actions_tab = st.tabs([
            T("Content"), T("Provenance & custody"), T("Translation"), T("Integrity & actions"),
        ])
        with content_tab:
            metadata = item.get("metadata") or {}
            is_image = f'.{item["file_type"]}' in IMAGE_EXTENSIONS
            if is_image and item["raw_bytes"] <= 25 * 1024 * 1024:
                try:
                    st.image(read_original(item["evidence_id"], case_id),
                             caption=T("Stored image preview"), width="stretch")
                except Exception as exc:
                    st.error(f"{T('Could not decrypt the stored image')}: {exc}")
            for warning in metadata.get("warnings", []):
                st.warning(warning)
            extracted = item.get("text", "")
            if extracted.strip():
                st.text(extracted[:3000])
                if len(extracted) > 3000:
                    st.caption(T("Preview limited to the first 3,000 characters. Use search or the timeline for the rest."))
            else:
                st.info(T("No text was extracted from this item."))
            with st.expander(T("Technical metadata")):
                st.json(metadata)
        with custody_tab:
            provenance = get_provenance(item["evidence_id"])
            if provenance:
                verified = {1: ":green-badge[acquisition hash matches]", 0: ":red-badge[hash mismatch]",
                            None: ":orange-badge[no acquisition hash supplied]"}[provenance["hash_verified"]]
                st.markdown(
                    f'**{T("Source")}:** {provenance["source_description"]}  \n'
                    f'**{T("Device")}:** {provenance["device_identifier"] or "—"}  \n'
                    f'**{T("Acquired by")}:** {provenance["acquired_by"]} · {provenance["acquired_at"]}  \n'
                    f'**{T("Method / tool")}:** {provenance["acquisition_method"]} / {provenance["acquisition_tool"] or "—"}  \n'
                    f'**{T("Legal authority")}:** {provenance["legal_authority"]}  \n'
                    f'**{T("Certificate")}:** {provenance["certificate_reference"] or "—"}  \n'
                    f'{verified}'
                )
                st.caption(T("Provenance is write-once. Use a 'correction' custody event to record changes."))
            else:
                st.warning(T("No acquisition record. A court cannot be shown where this file came from."))
                if can_edit:
                    with st.form(f"late_prov_{item['evidence_id']}"):
                        late = provenance_fields(f"late_{item['evidence_id']}")
                        late_hash = st.text_input(T("Acquisition SHA-256 (optional)"))
                        if st.form_submit_button(T("Record provenance")):
                            try:
                                record_provenance(case_id, item["evidence_id"], {**late, "acquisition_sha256": late_hash})
                                st.rerun()
                            except ValueError as exc:
                                st.error(str(exc))
            custody = list_custody(item["evidence_id"])
            st.markdown("**" + T("Custody history") + "**")
            st.dataframe([{
                T("When"): event["occurred_at"][:19], T("Action"): event["action"],
                T("From"): event["from_party"], T("To"): event["to_party"],
                T("Location"): event["location"], T("Notes"): event["notes"],
                T("Recorded by"): event["recorded_by"],
            } for event in custody], hide_index=True, width="stretch")
            if can_edit:
                with st.form(f"custody_{item['evidence_id']}", clear_on_submit=True):
                    c1, c2, c3 = st.columns(3)
                    action = c1.selectbox(T("Action"), [a for a in CUSTODY_ACTIONS
                                                         if a not in {"acquired", "received_into_vault", "removed_from_vault"}])
                    from_party = c2.text_input(T("From"))
                    to_party = c3.text_input(T("To"))
                    location = st.text_input(T("Location / malkhana entry"))
                    custody_notes = st.text_area(T("Notes"), height=68)
                    if st.form_submit_button(T("Record custody event")):
                        add_custody_event(case_id, item["evidence_id"], action, from_party, to_party,
                                          location, "", custody_notes)
                        st.rerun()
        with translate_tab:
            st.caption(T("Machine translation helps reading. The original text remains the evidence."))
            for language in ("English", "Hindi"):
                existing = get_translation(item["evidence_id"], language)
                if existing:
                    with st.expander(f'{language} · {existing["model"]} · {existing["created_at"][:19]}'):
                        st.text(existing["text"][:5000])
            if can_edit and item.get("text", "").strip():
                target_language = st.segmented_control(T("Translate into"), ["English", "Hindi"], default="English",
                                                        key=f"tl_{item['evidence_id']}")
                if st.button(T("Queue translation"), key=f"tlb_{item['evidence_id']}"):
                    jobs.enqueue("translate_evidence", case_id, {
                        "evidence_id": item["evidence_id"], "language": target_language or "English",
                        "label": f'Translate {item["filename"]} → {target_language}',
                    }, current_user["email"])
                    st.rerun()
        with actions_tab:
            if st.button(T("Verify stored original SHA-256"), key=f'verify_{item["evidence_id"]}'):
                matches, verification_message = verify_original(item["evidence_id"], case_id)
                (st.success if matches else st.error)(verification_message)
            if can_edit:
                copy_key = f"copy_{item['evidence_id']}"
                if st.button(T("Prepare verified working copy"), key=f"prep_{copy_key}",
                             help=T("Decrypts, re-checks the SHA-256 and records a custody event.")):
                    try:
                        raw = read_original(item["evidence_id"], case_id)
                        import hashlib
                        if hashlib.sha256(raw).hexdigest() != item["sha256"]:
                            st.error(T("Hash mismatch — copy not released."))
                        else:
                            add_custody_event(case_id, item["evidence_id"], "copied_for_analysis",
                                              "TRACE AI vault", current_user["email"], "Download", "",
                                              f"Verified working copy, SHA-256 {item['sha256']}")
                            st.session_state[copy_key] = raw
                    except Exception as exc:
                        st.error(str(exc))
                if st.session_state.get(copy_key):
                    st.download_button(T("Download working copy"), st.session_state[copy_key],
                                       file_name=item["filename"], key=f"dl_{copy_key}")
            if can_manage:
                st.divider()
                st.warning(T("Deleting evidence removes its record, index entries and encrypted original. "
                             "The audit log and custody history are kept."))
                confirm_delete = st.checkbox(T("I understand this cannot be undone."),
                                             key=f'confirm_delete_{item["evidence_id"]}')
                if st.button(T("Delete evidence"), key=f'delete_evidence_{item["evidence_id"]}',
                             type="secondary", disabled=not confirm_delete):
                    try:
                        access.require(current_user, case_id, "manage")
                        result = delete_evidence(case_id, item["evidence_id"])
                        st.session_state.pop(anomaly_key, None)
                        st.session_state.pop(relationship_key, None)
                        message = f'{T("Deleted evidence")} {result["filename"]}.'
                        if result["file_warnings"]:
                            message += " " + "; ".join(result["file_warnings"])
                        st.session_state.evidence_notice = message
                        st.rerun()
                    except Exception as exc:
                        st.error(f"{T('Could not delete evidence')}: {exc}")
    else:
        st.info(T("No evidence has been added to this case yet."))

# --------------------------------------------------------------------------- #
# Search
# --------------------------------------------------------------------------- #
with search:
    section_header(T("Investigation Search"), "Full-text, semantic and cross-lingual passage retrieval",
                   "icon_search.svg")
    question = st.text_input(T("Investigation question"), placeholder="Find messages about confidential files",
                             key="search_question")
    col_k, col_x = st.columns([2, 1], vertical_alignment="bottom")
    top_k = col_k.slider(T("Matching passages"), 1, 20, 5, key="search_top_k")
    cross_lingual = col_x.toggle(T("Search across Hindi ↔ English"), key="cross_lingual",
                                 help=T("Translates the query with the local model when the query and evidence use different scripts."))
    indexed_count = sum(bool((item.get("text") or "").strip()) for item in st.session_state.evidence)
    semantic_count = count_evidence_chunks(case_id, EMBEDDING_MODEL)
    st.caption(f'{T("Evidence files with extracted text")}: {indexed_count} / {len(st.session_state.evidence)} · '
               f'{T("semantic chunks")}: {semantic_count} ({EMBEDDING_MODEL})')
    if can_edit and st.button(T("Build or refresh semantic index"), disabled=not st.session_state.evidence,
                              key="build_semantic_index"):
        jobs.enqueue("build_index", case_id, {"label": "Semantic index"}, current_user["email"])
        st.rerun()
    if st.button(T("Search"), disabled=not question or not st.session_state.evidence):
        results = search_evidence(question, st.session_state.evidence, top_k, cross_lingual=cross_lingual)
        if not results:
            st.warning(T("No matching passages found. Try terms found in the extracted text."))
        elif len(results[0].get("query_variants", [])) > 1:
            st.caption(T("Also searched") + ": " + " · ".join(results[0]["query_variants"][1:]))
        for result in results:
            with st.expander(f'{result["evidence_id"]} · {result["filename"]} · score {result["score"]:.3f}',
                             expanded=True):
                st.write(result["snippet"])
                st.caption(f'{T("Retrieval")}: {result.get("retrieval_mode", "TF-IDF")}. '
                           + T("Score is a ranking, not a probability or proof."))

# --------------------------------------------------------------------------- #
# Chat
# --------------------------------------------------------------------------- #
def show_verification(report: dict):
    if not report:
        return
    if report.get("rejected"):
        st.caption(":material/gpp_bad: " + T("Withheld") + f": {report['rejected']}")
    elif report.get("cited_claims") is not None and report.get("claims"):
        st.caption(f":material/fact_check: {report.get('supported', 0)} {T('claims verified against cited evidence')}"
                   f" · {report.get('unsupported', 0)} {T('removed')}")
    removed = [c for c in report.get("claims", []) if not c.get("supported")]
    if removed:
        with st.expander(T("Removed or unsupported claims")):
            for claim in removed:
                st.markdown(f"- ~~{claim['sentence'][:300]}~~  \n  _{claim['reason']}_")


with chat:
    section_header(T("AI Investigation Chat"), "Tool-using local agent · every claim checked against its citation",
                   "icon_chat.svg")
    agent_mode = st.toggle(T("Agent mode (the AI can search, read evidence, filter the timeline and records)"),
                           value=True, key="agent_mode")
    if can_edit and st.button(f"🗑️ {T('Clear Chat')}", key="clear_chat"):
        clear_chat(case_id)
        st.rerun()

    for message in st.session_state.chat_history:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
            meta = message.get("meta") or {}
            if message["role"] == "assistant":
                if meta.get("steps"):
                    with st.expander(f'{T("Agent steps")} ({len(meta["steps"])})'):
                        for step in meta["steps"]:
                            st.markdown(f'`{step["tool"]}` {json.dumps(step["arguments"], ensure_ascii=False)} → {step["summary"]}')
                elif message.get("retrieval_query"):
                    st.caption(f'{T("Evidence search used")}: {message["retrieval_query"]}')
                show_verification(meta.get("verification"))
                if message.get("sources"):
                    with st.expander(T("Retrieved evidence sources")):
                        for source in message["sources"]:
                            st.markdown(f'**{source["evidence_id"]} · {source["filename"]}**')
                            st.write(source["snippet"][:1500])

    if not st.session_state.evidence:
        st.info(T("Add evidence in the Evidence Vault before asking questions."))
    question = st.chat_input(T("Ask your investigation question..."),
                             disabled=not st.session_state.evidence or not can_edit)
    if question:
        access.require(current_user, case_id, "edit")
        prior_history = list(st.session_state.chat_history)
        with st.spinner(T("Searching evidence and analyzing with the local LLM...")):
            try:
                if agent_mode:
                    from modules.agent import run_agent
                    outcome = run_agent(
                        question, case_id, st.session_state.evidence,
                        lambda q, ev, k: search_evidence(q, ev, k, cross_lingual=st.session_state.get("cross_lingual", False)),
                        interface_language, prior_history,
                    )
                    answer, sources, search_query = outcome["answer"], outcome["sources"], ""
                    meta = {"steps": outcome["steps"], "verification": outcome["verification"], "mode": "agent"}
                else:
                    search_query = resolve_followup_query(question, prior_history)
                    sources = search_evidence(search_query, st.session_state.evidence, top_k=5,
                                              cross_lingual=st.session_state.get("cross_lingual", False))
                    answer, verification = generate_answer(question, sources, interface_language, prior_history,
                                                            with_report=True)
                    meta = {"verification": verification, "mode": "retrieval"}
            except Exception as exc:
                st.error(str(exc))
                st.stop()
        save_chat_message(case_id, "user", question)
        save_chat_message(case_id, "assistant", answer, sources, retrieval_query=search_query, meta=meta)
        log_activity(case_id, "investigator_question_processed", {
            "question": question, "mode": meta["mode"],
            "tools_used": [s["tool"] for s in meta.get("steps", [])],
            "evidence_ids": sorted({item["evidence_id"] for item in sources}),
            "claims_removed": (meta.get("verification") or {}).get("unsupported", 0),
        })
        st.rerun()

# --------------------------------------------------------------------------- #
# Timeline
# --------------------------------------------------------------------------- #
with timeline:
    section_header(T("Timeline"), "Unified UTC timeline from logs, EVTX, PCAP, file systems and records",
                   "icon_anomaly.svg")
    total_events = count_timeline(case_id)
    st.caption(f"{total_events:,} {T('timestamped events in this case')}")
    if total_events:
        f1, f2, f3 = st.columns(3)
        start_date = f1.date_input(T("From (UTC date)"), value=None, key=f"tl_start_{case_id}")
        end_date = f2.date_input(T("To (UTC date)"), value=None, key=f"tl_end_{case_id}")
        keyword = f3.text_input(T("Keyword / user / IP"), key=f"tl_kw_{case_id}")
        source_filter = st.selectbox(
            T("Evidence item"), ["All"] + [i["evidence_id"] for i in st.session_state.evidence],
            format_func=lambda eid: eid if eid == "All" else
            f'{eid} · {next(i["filename"] for i in st.session_state.evidence if i["evidence_id"] == eid)}',
            key=f"tl_src_{case_id}",
        )
        events = query_timeline(
            case_id, start_date.isoformat() if start_date else None,
            f"{end_date.isoformat()}T23:59:59.999999" if end_date else None,
            keyword or None, None if source_filter == "All" else source_filter, limit=2000,
        )
        st.dataframe([{
            T("Time"): e["ts"], T("Event"): e["summary"], T("Source"): e["source"],
            T("Evidence ID"): e["evidence_id"],
            T("Timezone"): e["fields"].get("timezone", "UTC"),
        } for e in events], hide_index=True, width="stretch", height=480)
        if len(events) == 2000:
            st.caption(T("Showing the first 2,000 matching events. Narrow the filters to see more."))
        st.caption(T("Events marked 'unspecified' come from timestamps without a time zone and are ordered as written."))
    else:
        st.info(T("No timestamped events yet. EVTX, PCAP, disk images and CSV/JSON logs with time columns add events."))

# --------------------------------------------------------------------------- #
# Anomaly review
# --------------------------------------------------------------------------- #
with anomaly:
    section_header(T("Anomaly Review"), "Rule indicators and local Isolation Forest ranking on structured logs",
                   "icon_anomaly.svg")
    st.write(T("Review rule-based indicators and a local Isolation Forest ranking on CSV/JSON logs. Flags are leads for human review, not evidence of intent or wrongdoing."))
    structured_items = [item for item in st.session_state.evidence
                        if item.get("file_type", "").lower() in {"csv", "json"}]
    if not structured_items:
        st.info(T("Add CSV or JSON log evidence to run anomaly review."))
    else:
        st.caption(T("Timestamp checks run only when source values include an explicit timezone."))
        if can_edit and st.button(T("Analyze structured logs"), key="analyze_logs"):
            with st.spinner(T("Analyzing structured records locally...")):
                flagged, summaries = analyze_structured_evidence(structured_items)
            st.session_state[anomaly_key] = {"flagged": flagged, "summaries": summaries}
            save_analysis_result(case_id, "anomaly", st.session_state[anomaly_key])

        analysis = st.session_state.get(anomaly_key)
        if analysis:
            st.markdown(f'#### {T("Files analyzed")}')
            st.dataframe(analysis["summaries"], width="stretch")
            st.markdown(f'#### {T("Records flagged for review")}')
            flagged = analysis["flagged"]
            if not flagged:
                st.success(T("No records were flagged by the current rules or model. This does not establish that the logs are free of suspicious activity."))
            else:
                st.dataframe([{
                    "Evidence ID": row["evidence_id"], "File": row["filename"],
                    "Source row": row["row_number"], "Review reasons": "; ".join(row["reasons"]),
                } for row in flagged], width="stretch")
                selection = st.selectbox(
                    T("Inspect flagged source record"), range(len(flagged)),
                    format_func=lambda index: f'{flagged[index]["evidence_id"]} · {flagged[index]["filename"]} · row {flagged[index]["row_number"]}',
                    key=f"anomaly_record_{case_id}",
                )
                selected = flagged[selection]
                st.markdown(f'**{T("Review reasons")}**')
                for reason in selected["reasons"]:
                    st.write(f"- {reason}")
                st.markdown(f'**{T("Original parsed record")}**')
                st.json(selected["original_record"])

# --------------------------------------------------------------------------- #
# Relationships
# --------------------------------------------------------------------------- #
with relationships:
    section_header(T("Evidence Relationships"), "Identifier and time-proximity link map for review", "icon_network.svg")
    st.write(T("The map links explicit identifiers that occur in the same source record. Timezone-explicit records from different files may also be connected when they are close in time."))
    if not st.session_state.evidence:
        st.info(T("Add evidence to this case before building a relationship map."))
    else:
        if can_edit and st.button(T("Build relationship map"), key="build_relationships"):
            with st.spinner(T("Extracting explicit identifiers and building the graph locally...")):
                graph_html, record_catalog, graph_stats = build_relationship_graph(st.session_state.evidence)
            st.session_state[relationship_key] = {"html": graph_html, "catalog": record_catalog, "stats": graph_stats}
            save_analysis_result(case_id, "relationships", {"catalog": record_catalog, "stats": graph_stats})

        relationship_result = st.session_state.get(relationship_key)
        if relationship_result:
            stats = relationship_result["stats"]
            st.caption(f'{stats["records"]} records · {stats["entities"]} explicit identifiers · '
                       f'{stats["temporal_links"]} possible time-proximity links')
            if stats["truncated"]:
                st.warning(f'Graph input exceeded the {stats["records"]:,}-record limit; '
                           f'at least {stats["truncated"]:,} additional records were omitted.')
            if relationship_result["html"]:
                st.components.v1.html(relationship_result["html"], height=650, scrolling=True)
            else:
                st.info(T("No records were available to graph."))
            record_catalog = relationship_result["catalog"]
            identifiers = sorted({identifier for record in record_catalog for identifier in record["identities"]})
            if identifiers:
                selected_identifier = st.selectbox(T("Inspect an identifier and its supporting source records"),
                                                   identifiers, key=f"relationship_entity_{case_id}")
                for record in supporting_records(record_catalog, selected_identifier):
                    with st.expander(f'{record["evidence_id"]} · {record["filename"]} · record {record["row_number"]}'):
                        if record["timestamp"]:
                            st.caption(f'Parsed timestamp: {record["timestamp"]}')
                        st.json(record["record"])
            st.caption(T("Entity extraction is deterministic and identifier-focused. Names are included only when explicit fields or labels are present. A time-proximity edge is a review cue, not proof of communication or causation."))

# --------------------------------------------------------------------------- #
# Leads and diary
# --------------------------------------------------------------------------- #
with operations:
    section_header(T("Leads & Case Diary"), "Unverified leads and investigator-recorded actions", "icon_leads.svg")
    st.caption(T("Rule-generated suggestions are unverified and must be reviewed against source evidence."))
    if can_edit and st.button(T("Generate or refresh leads"), key="generate_leads", disabled=not st.session_state.evidence):
        anomaly_result = st.session_state.get(anomaly_key) or {}
        relationship_result = st.session_state.get(relationship_key) or {}
        save_leads(case_id, generate_investigative_leads(anomaly_result.get("flagged", []),
                                                         relationship_result.get("catalog", [])))
        st.rerun()

    leads = list_leads(case_id)
    if leads:
        stored_status_options = ["Unreviewed", "Under Review", "Actioned", "Closed - no further action", "Needs refresh"]
        display_status_options = [T(value) for value in stored_status_options]
        for lead in leads:
            with st.expander(f'{lead["lead_id"]} · {lead["type"]} · {lead["status"]}'):
                st.write(lead["statement"])
                st.caption(lead["basis"])
                st.write("**Supporting evidence:** " + ", ".join(lead["supporting_evidence"]))
                st.write("**Suggested follow-up:** " + lead["suggested_follow_up"])
                current_status = lead["status"] if lead["status"] in stored_status_options else stored_status_options[0]
                new_status = st.selectbox(T("Review status"), display_status_options,
                                          index=stored_status_options.index(current_status),
                                          key=f'lead_status_{case_id}_{lead["lead_id"]}', disabled=not can_edit)
                if can_edit and st.button(T("Save lead status"), key=f'lead_save_{case_id}_{lead["lead_id"]}'):
                    update_lead_status(case_id, lead["lead_id"],
                                       stored_status_options[display_status_options.index(new_status)])
                    st.rerun()
    else:
        st.info(T("No leads have been generated for this case yet. Run Anomaly Review and build the relationship map first."))

    st.divider()
    st.subheader(T("Case diary and investigator actions"))
    if can_edit:
        with st.form(f"activity_form_{case_id}", clear_on_submit=True):
            action_type = st.selectbox(T("Action type"), [T(value) for value in
                                       ["Investigator note", "Evidence reviewed", "Follow-up action", "Decision or disposition"]])
            action_details = st.text_area(T("Describe the action taken"), max_chars=4000)
            evidence_options = ["None"] + [item["evidence_id"] for item in st.session_state.evidence]
            related_evidence = st.selectbox(T("Related evidence (optional)"), evidence_options)
            log_submitted = st.form_submit_button(T("Record action"))
        if log_submitted:
            if not action_details.strip():
                st.error(T("Enter a short description before recording the action."))
            else:
                details = {"description": action_details.strip()}
                if related_evidence != "None":
                    details["evidence_id"] = related_evidence
                log_activity(case_id, action_type, details)
                st.success(T("Action added to the case activity log."))
                case_activity = list_activity(case_id)

    if case_activity:
        st.dataframe([{
            "#": entry["seq"], T("Time (UTC)"): entry["created_at"][:19], T("Officer"): entry["actor"],
            T("Event"): entry["event_type"],
            T("Details"): "; ".join(f'{key}: {value}' for key, value in entry["details"].items()),
        } for entry in case_activity], width="stretch", hide_index=True)
    diary_text = make_case_diary(case_id, active_case["name"], case_activity)
    st.download_button(T("Download case diary (TXT)"), diary_text, file_name=f"{case_id}_case_diary.txt", mime="text/plain")
    diary_pdf_key = f"diary_pdf_{case_id}"
    if st.button(T("Prepare case diary PDF"), key=f"prepare_diary_pdf_{case_id}"):
        st.session_state[diary_pdf_key] = make_pdf(f"{case_id} Case Diary", diary_text, interface_language)
    if st.session_state.get(diary_pdf_key):
        st.download_button(T("Download case diary (PDF)"), st.session_state[diary_pdf_key],
                           file_name=f"{case_id}_case_diary.pdf", mime="application/pdf")

# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
with report:
    section_header(T("Case Report"), "Inventory, custody register and saved, versioned report drafts", "icon_report.svg")
    evidence = st.session_state.evidence
    if not evidence:
        st.info(T("Add evidence to this case before generating a report."))
    else:
        inventory_text = make_report(case_id, evidence)
        col_text, col_pdf, col_save = st.columns(3)
        col_text.download_button(T("Download evidence inventory (TXT)"), inventory_text,
                                 file_name=f"{case_id}_inventory.txt", mime="text/plain")
        if col_pdf.button(T("Prepare evidence inventory PDF"), key=f"inventory_pdf_{case_id}"):
            st.session_state[f"inventory_pdf_data_{case_id}"] = make_pdf(f"{case_id} Evidence Inventory",
                                                                         inventory_text, interface_language)
        if st.session_state.get(f"inventory_pdf_data_{case_id}"):
            col_pdf.download_button(T("Download evidence inventory (PDF)"), st.session_state[f"inventory_pdf_data_{case_id}"],
                                    file_name=f"{case_id}_inventory.pdf", mime="application/pdf")
        if can_edit and col_save.button(T("Save inventory snapshot"), key=f"save_inv_{case_id}"):
            save_report(case_id, "inventory", f"{case_id} Evidence Inventory", inventory_text, interface_language,
                        [i["evidence_id"] for i in evidence])
            st.rerun()

        st.markdown(f'#### {T("AI-assisted report draft")}')
        st.caption(T("Requires the configured local Ollama model. Each sentence is checked against the evidence it cites; drafts are saved permanently."))
        if can_edit and st.button(T("Draft report with local AI"), key=f"draft_report_{case_id}"):
            passages = search_evidence("case events access communications files accounts investigation", evidence, top_k=8)
            try:
                draft, verification = generate_case_report(case_id, passages, list_leads(case_id), case_activity,
                                                           interface_language, with_report=True)
            except Exception as exc:
                st.error(str(exc))
            else:
                save_report(case_id, "ai_draft", f"{case_id} AI Report Draft", draft, interface_language,
                            sorted({p["evidence_id"] for p in passages}),
                            {k: verification.get(k) for k in ("supported", "unsupported", "cited_claims", "rejected")})
                st.rerun()

    saved_reports = list_reports(case_id)
    if saved_reports:
        st.markdown(f'#### {T("Saved reports")} ({len(saved_reports)})')
        chosen = st.selectbox(
            T("Open saved report"), range(len(saved_reports)),
            format_func=lambda i: f'{saved_reports[i]["created_at"][:19]} · {saved_reports[i]["title"]} · '
                                  f'{saved_reports[i]["created_by"]}',
            key=f"saved_report_{case_id}",
        )
        saved = saved_reports[chosen]
        verification = saved["verification"] or {}
        if verification:
            st.caption(f'{T("Claim check")}: {verification.get("supported", 0)} {T("verified")}, '
                       f'{verification.get("unsupported", 0)} {T("removed")} · SHA-256 {saved["sha256"][:16]}…')
        with st.container(border=True, height=420):
            st.markdown(saved["content"])
        d1, d2 = st.columns(2)
        d1.download_button(T("Download (TXT)"), saved["content"], file_name=f'{saved["report_id"]}.txt',
                           mime="text/plain", key=f'dl_txt_{saved["report_id"]}')
        if d2.button(T("Prepare PDF"), key=f'pdf_{saved["report_id"]}'):
            st.session_state[f'pdf_{saved["report_id"]}_data'] = make_pdf(saved["title"], saved["content"], saved["language"])
        if st.session_state.get(f'pdf_{saved["report_id"]}_data'):
            d2.download_button(T("Download (PDF)"), st.session_state[f'pdf_{saved["report_id"]}_data'],
                               file_name=f'{saved["report_id"]}.pdf', mime="application/pdf",
                               key=f'dl_pdf_{saved["report_id"]}')

# --------------------------------------------------------------------------- #
# Audit and custody
# --------------------------------------------------------------------------- #
with audit:
    section_header(T("Audit & Custody"), "Signed hash-chained audit log, custody register and verification",
                   "badge.svg")
    st.write(T("Every action is written to an append-only audit log. Each entry includes the hash of the previous entry and is signed with an Ed25519 key, so any edit, insertion or reordering is detectable."))
    if st.button(T("Verify audit chain now"), key=f"verify_chain_{case_id}", type="primary"):
        status = verify_audit_chain()
        st.session_state[f"chain_status_{case_id}"] = status
        log_activity(case_id, "audit_chain_verified", {"valid": status["valid"], "entries": status["entries"]})
    status = st.session_state.get(f"chain_status_{case_id}")
    if status:
        if status["valid"]:
            st.success(f'{T("Audit chain intact")}: {status["entries"]} {T("signed entries")} · head #{status["head_seq"]} '
                       f'`{status["head_hash"][:24]}…` · {T("key")} {status["public_key_id"]} · '
                       f'{status["anchors"]} {T("trusted timestamp anchor(s)")}')
        else:
            st.error(T("Audit chain problems found") + ":\n\n" + "\n".join(f"- {p}" for p in status["problems"]))

    provenance_map = {item["evidence_id"]: get_provenance(item["evidence_id"]) for item in st.session_state.evidence}
    custody_map = {item["evidence_id"]: list_custody(item["evidence_id"]) for item in st.session_state.evidence}
    missing_provenance = [eid for eid, p in provenance_map.items() if not p]
    if missing_provenance:
        st.warning(f'{len(missing_provenance)} {T("evidence item(s) have no acquisition record")}: {", ".join(missing_provenance)}')
    custody_text = make_custody_report(case_id, st.session_state.evidence,
                                       {k: v for k, v in provenance_map.items() if v}, custody_map, status)
    a1, a2 = st.columns(2)
    a1.download_button(T("Download chain-of-custody register (TXT)"), custody_text,
                       file_name=f"{case_id}_custody_register.txt", mime="text/plain")
    if can_manage:
        if a2.button(T("Prepare signed audit export for this case"), key=f"export_audit_{case_id}"):
            bundle = database.export_audit_bundle(case_id)
            log_activity(case_id, "audit_bundle_exported", {"entries": len(bundle["entries"])})
            st.session_state[f"audit_bundle_{case_id}"] = json.dumps(bundle, ensure_ascii=False, indent=1)
        if st.session_state.get(f"audit_bundle_{case_id}"):
            a2.download_button(T("Download audit bundle (JSON)"), st.session_state[f"audit_bundle_{case_id}"],
                               file_name=f"{case_id}_audit_bundle.json", mime="application/json")
        st.caption(T("Verify a bundle independently with tools/verify_audit_bundle.py and the public key from the Admin tab."))

# --------------------------------------------------------------------------- #
# Admin
# --------------------------------------------------------------------------- #
if is_admin:
    with tabs[9]:
        section_header("Officer access control", "Approve officers, assign roles, and protect the audit trail.",
                       "badge.svg")
        admin_panel(current_user)
        st.divider()
        st.subheader(T("System security"))
        from modules import crypto, timestamping
        from modules.forensics import tool_status
        from modules.ocr import ocr_status
        s1, s2, s3 = st.columns(3)
        s1.metric(T("Database encryption"), "SQLCipher AES-256" if database.DB_ENCRYPTED else "OFF")
        s2.metric(T("Audit signing key"), crypto.public_key_id())
        ocr = ocr_status()
        s3.metric(T("OCR engines"), ", ".join(ocr["engines"]) or "none")
        if not ocr["tesseract"]["available"]:
            st.caption(T("For Hindi OCR install Tesseract: sudo apt install tesseract-ocr tesseract-ocr-hin"))
        st.caption(T("Forensic parsers") + ": " + ", ".join(f"{k}: {'yes' if v else 'no'}" for k, v in tool_status().items()))
        st.caption(T("Keys are stored in") + f" `{crypto.KEY_DIR}`. " +
                   T("Back up this folder separately and securely — without it encrypted evidence cannot be recovered."))
        st.download_button(T("Download audit public key (PEM)"), crypto.public_key_pem(),
                           file_name="trace_ai_audit_public_key.pem", mime="application/x-pem-file")
        b1, b2 = st.columns(2)
        if b1.button(T("Anchor audit chain with RFC 3161 timestamp"), disabled=not timestamping.tsa_url(),
                     help=T("Sends only the head hash to the Time-Stamp Authority set in TRACE_TSA_URL.")):
            try:
                anchor = timestamping.anchor_audit_head()
                st.success(f'{T("Anchored entry")} #{anchor["seq"]} {T("at")} {anchor["tsa_time"]}')
            except Exception as exc:
                st.error(str(exc))
        if not timestamping.tsa_url():
            b1.caption(T("Set TRACE_TSA_URL to an approved Time-Stamp Authority to enable anchoring."))
        if b2.button(T("Prepare full audit export")):
            st.session_state["full_audit_bundle"] = json.dumps(database.export_audit_bundle(), ensure_ascii=False, indent=1)
            database.append_system_audit("audit_bundle_exported", {"scope": "full"})
        if st.session_state.get("full_audit_bundle"):
            b2.download_button(T("Download full audit bundle (JSON)"), st.session_state["full_audit_bundle"],
                               file_name="trace_ai_full_audit_bundle.json", mime="application/json")

st.divider()
st.caption(T("Investigator assistant: findings are drafts. Verify against source evidence and follow approved forensic procedures."))
