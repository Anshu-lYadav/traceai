from pathlib import Path

import streamlit as st

from modules.database import (
    clear_chat,
    create_case,
    count_evidence_chunks,
    delete_case,
    delete_evidence,
    ensure_default_case,
    initialize_database,
    list_cases,
    list_chat_messages,
    list_activity,
    list_evidence,
    list_leads,
    load_analysis_result,
    log_activity as _db_log_activity,
    save_analysis_result,
    save_chat_message,
    save_evidence,
    save_leads,
    update_lead_status,
    verify_original,
)
from modules.anomaly_engine import analyze_structured_evidence
from modules.evidence_processor import IMAGE_EXTENSIONS, process_upload
from modules.embedding_engine import EMBEDDING_MODEL
from modules.i18n import tr
from modules.auth import initialize_auth
from modules.auth_ui import admin_panel, require_login, sidebar_account
from modules.theme import apply_theme, hero, section_header, sidebar_brand
from modules.llm_engine import (
    generate_answer,
    generate_case_report,
    resolve_followup_query,
)
from modules.report_generator import make_case_diary, make_pdf, make_report
from modules.recommendation_engine import generate_investigative_leads
from modules.relationship_engine import (
    build_relationship_graph,
    render_relationship_graph,
    supporting_records,
)
from modules.search_engine import build_semantic_index, search_evidence


st.set_page_config(page_title="TRACE AI", page_icon="🛡️", layout="wide")
apply_theme()
initialize_database()
initialize_auth()

# Nothing below this line runs unless the session holds a valid JWT for an
# admin-approved account.
current_user = require_login()
ensure_default_case()


def log_activity(case_id: str, event_type: str, details: dict) -> None:
    """Record every case action with the signed-in officer's identity."""
    _db_log_activity(case_id, event_type, {
        **details,
        "officer": current_user["email"],
        "badge_number": current_user["badge_number"],
    })


with st.sidebar:
    sidebar_brand()
    sidebar_account(current_user)
    interface_language = st.selectbox("Interface language / इंटरफ़ेस भाषा", ["English", "हिन्दी"], key="interface_language")
    st.header(tr("Investigation", interface_language))
    with st.expander("Create a case"):
        with st.form("create_case_form", clear_on_submit=True):
            new_case_id = st.text_input(tr("Case ID", interface_language), placeholder="CASE-002")
            new_case_name = st.text_input(tr("Case name", interface_language), placeholder="Investigation name")
            new_case_description = st.text_area(tr("Description (optional)", interface_language))
            create_submitted = st.form_submit_button(tr("Create case", interface_language))
        if create_submitted:
            try:
                create_case(new_case_id, new_case_name, new_case_description)
                st.session_state.active_case_selector = new_case_id.strip()
                st.rerun()
            except Exception as exc:
                st.error(f"{tr('Could not create case', interface_language)}: {exc}")

    cases = list_cases()
    case_ids = [case["case_id"] for case in cases]
    preferred_id = st.session_state.get("active_case_id", case_ids[0])
    if preferred_id not in case_ids:
        preferred_id = case_ids[0]
    if st.session_state.get("active_case_selector") not in case_ids:
        st.session_state.active_case_selector = preferred_id
    case_id = st.selectbox(tr("Active case", interface_language), case_ids, key="active_case_selector")
    st.session_state.active_case_id = case_id
    active_case = next(case for case in cases if case["case_id"] == case_id)

    with st.expander(tr("Delete case", interface_language)):
        st.warning(tr(
            "This permanently removes the case, its evidence originals, chat, leads, reports, and activity log. Other cases are not affected.",
            interface_language,
        ))
        case_delete_confirmation = st.text_input(
            tr("Type case ID to confirm deletion", interface_language),
            key="delete_case_confirmation",
        )
        if st.button(
            tr("Delete this case", interface_language),
            type="secondary",
            disabled=case_delete_confirmation.strip() != case_id,
        ):
            try:
                result = delete_case(case_id)
                for key in list(st.session_state):
                    if key.startswith(f"anomaly_{case_id}") or key.startswith(f"relationships_{case_id}"):
                        st.session_state.pop(key, None)
                st.session_state.pop("active_case_selector", None)
                st.session_state.pop("active_case_id", None)
                st.session_state.delete_notice = (
                    f'{tr("Deleted case", interface_language)} {result["case_id"]}.'
                )
                st.rerun()
            except Exception as exc:
                st.error(f"{tr('Could not delete case', interface_language)}: {exc}")

    st.caption(active_case["name"])
    if active_case["description"]:
        st.write(active_case["description"])
    st.info(tr("Use fictional or authorized evidence. Evidence and database files are stored locally and are not encrypted by this prototype.", interface_language))

case_delete_notice = st.session_state.pop("delete_notice", None)
if case_delete_notice:
    st.success(case_delete_notice)

# Reload the active case on each rerun. This keeps cases isolated and makes
# records available after closing and reopening the app.
st.session_state.evidence = list_evidence(case_id)
st.session_state.chat_history = list_chat_messages(case_id)
hero(
    case_id,
    active_case["name"],
    len(st.session_state.evidence),
    len(list_leads(case_id)),
    len(list_activity(case_id)),
)
anomaly_key = f"anomaly_{case_id}"
relationship_key = f"relationships_{case_id}"
if anomaly_key not in st.session_state:
    st.session_state[anomaly_key] = load_analysis_result(case_id, "anomaly")
if relationship_key not in st.session_state:
    stored_relationships = load_analysis_result(case_id, "relationships")
    if stored_relationships:
        stored_relationships["html"] = render_relationship_graph(stored_relationships["catalog"])
    st.session_state[relationship_key] = stored_relationships

is_admin = current_user["role"] == "admin"
tab_labels = [
    tr("Evidence Vault", interface_language),
    tr("Investigation Search", interface_language),
    tr("AI Investigation Chat", interface_language),
    tr("Anomaly Review", interface_language),
    tr("Evidence Relationships", interface_language),
    tr("Leads & Case Diary", interface_language),
    tr("Case Report", interface_language),
]
if is_admin:
    tab_labels.append(":material/admin_panel_settings: Admin")
tabs = st.tabs(tab_labels)
vault, search, chat, anomaly, relationships, operations, report = tabs[:7]

if is_admin:
    with tabs[7]:
        section_header(
            "Officer access control",
            "Approve new officer accounts, disable access, and assign admin rights.",
            "badge.svg",
        )
        admin_panel(current_user)

with vault:
    section_header(
        tr("Evidence Vault", interface_language),
        "Acquisition register · originals preserved and hash verified",
        "icon_evidence.svg",
    )
    evidence_delete_notice = st.session_state.pop("evidence_notice", None)
    if evidence_delete_notice:
        st.success(evidence_delete_notice)
    uploads = st.file_uploader(
        tr("Upload PDF, TXT, CSV, JSON, DOCX, or image evidence", interface_language),
        type=[
            "pdf", "txt", "csv", "json", "docx",
            "png", "jpg", "jpeg", "webp", "bmp", "gif", "tif", "tiff",
        ],
        accept_multiple_files=True,
        key=f"uploads_{case_id}",
    )
    if st.button(tr("Process evidence", interface_language), type="primary", disabled=not uploads):
        added = 0
        for upload in uploads:
            try:
                item = process_upload(upload, case_id)
                if save_evidence(case_id, item, upload.getvalue()):
                    added += 1
            except Exception as exc:
                st.error(f"{tr('Could not process', interface_language)} {upload.name}: {exc}")
        st.session_state.evidence = list_evidence(case_id)
        st.session_state.pop(anomaly_key, None)
        st.session_state.pop(relationship_key, None)
        st.success(f"Saved {added} new evidence file(s) to this case.")

    evidence = st.session_state.evidence
    if evidence:
        st.dataframe(
            [{
                tr("Evidence ID", interface_language): item["evidence_id"],
                tr("Filename", interface_language): item["filename"],
                tr("Type", interface_language): item["file_type"],
                tr("SHA-256", interface_language): item["sha256"],
                "Extracted characters": len(item.get("text", "")),
                tr("Image dimensions", interface_language): (
                    f'{item.get("metadata", {}).get("width")} × {item.get("metadata", {}).get("height")}'
                    if item.get("metadata", {}).get("width") else "—"
                ),
                tr("Uploaded bytes", interface_language): item["raw_bytes"],
                tr("Extraction status", interface_language): item["extraction_status"],
                "Ingested at (UTC)": item["ingested_at"],
            } for item in evidence],
            width="stretch",
        )
        st.markdown(f'#### {tr("Extracted text preview", interface_language)}')
        for item in evidence:
            with st.expander(f'{item["evidence_id"]} · {item["filename"]}'):
                if st.button(
                    tr("Verify stored original SHA-256", interface_language),
                    key=f'verify_{item["evidence_id"]}',
                ):
                    matches, verification_message = verify_original(item["evidence_id"], case_id)
                    if matches:
                        st.success(verification_message)
                    else:
                        st.error(verification_message)
                extracted = item.get("text", "")
                metadata = item.get("metadata") or {}
                is_image = f'.{item["file_type"]}' in IMAGE_EXTENSIONS
                if is_image and Path(item["original_path"]).is_file():
                    st.image(
                        item["original_path"],
                        caption=tr("Stored image preview", interface_language),
                        width="stretch",
                    )
                    image_details = []
                    if metadata.get("width") and metadata.get("height"):
                        image_details.append(f'{metadata["width"]} × {metadata["height"]} px')
                    if metadata.get("format") or item["file_type"]:
                        image_details.append(str(metadata.get("format") or item["file_type"].upper()))
                    image_details.append(f'{metadata.get("frames", 1)} frame(s)')
                    st.caption(" · ".join(image_details))
                if extracted.strip():
                    st.text(extracted[:1500])
                    if len(extracted) > 1500:
                        st.caption("Preview limited to first 1,500 characters.")
                elif is_image:
                    st.info(tr(
                        "Image stored as the original file. OCR is not included; visual content is not searchable as text.",
                        interface_language,
                    ))
                else:
                    st.warning(tr("No selectable text was extracted. Scanned PDFs need OCR, which is not included yet.", interface_language))

                st.markdown("---")
                st.warning(tr(
                    "Deleting evidence removes its record, semantic chunks, and stored original. Chat history and the activity log are kept.",
                    interface_language,
                ))
                confirm_delete = st.checkbox(
                    tr("I understand this cannot be undone.", interface_language),
                    key=f'confirm_delete_{item["evidence_id"]}',
                )
                if st.button(
                    tr("Delete evidence", interface_language),
                    key=f'delete_evidence_{item["evidence_id"]}',
                    type="secondary",
                    disabled=not confirm_delete,
                ):
                    try:
                        result = delete_evidence(case_id, item["evidence_id"])
                        st.session_state.evidence = list_evidence(case_id)
                        st.session_state.pop(anomaly_key, None)
                        st.session_state.pop(relationship_key, None)
                        message = (
                            f'{tr("Deleted evidence", interface_language)} {result["filename"]}.'
                        )
                        if not result["original_removed"]:
                            message += " Stored original was already missing or shared."
                        if result["file_warnings"]:
                            message += " " + "; ".join(result["file_warnings"])
                        st.session_state.evidence_notice = message
                        st.rerun()
                    except Exception as exc:
                        st.error(f"{tr('Could not delete evidence', interface_language)}: {exc}")
    else:
        st.info(tr("No evidence has been added to this case yet.", interface_language))

with search:
    section_header(
        tr("Investigation Search", interface_language),
        "Keyword and semantic passage retrieval across this case",
        "icon_search.svg",
    )
    question = st.text_input(
        tr("Investigation question", interface_language),
        placeholder="Find messages about confidential files",
        key="search_question",
    )
    top_k = st.slider(tr("Matching passages", interface_language), 1, 10, 5, key="search_top_k")
    indexed_count = sum(bool((item.get("text") or "").strip()) for item in st.session_state.evidence)
    st.caption(f'{tr("Evidence files with extracted text", interface_language)}: {indexed_count} / {len(st.session_state.evidence)}')
    semantic_count = count_evidence_chunks(case_id, EMBEDDING_MODEL)
    st.caption(f"Multilingual semantic chunks indexed: {semantic_count} · model: {EMBEDDING_MODEL}")
    if st.button(tr("Build or refresh semantic index", interface_language), disabled=not st.session_state.evidence, key="build_semantic_index"):
        try:
            with st.spinner("Generating local embeddings. The first run may take longer..."):
                index_result = build_semantic_index(st.session_state.evidence)
            st.success(f'Indexed {index_result["chunks_indexed"]} passage(s) with {index_result["model"]}.')
        except Exception as exc:
            st.error(f"Could not build the semantic index: {exc}")
    if st.button(tr("Search", interface_language), disabled=not question or not st.session_state.evidence):
        results = search_evidence(question, st.session_state.evidence, top_k)
        if not results:
            st.warning(tr("No matching passages found. Try terms found in the extracted text.", interface_language))
        for result in results:
            with st.expander(
                f'{result["evidence_id"]} · {result["filename"]} · score {result["score"]:.3f}',
                expanded=True,
            ):
                st.write(result["snippet"])
                st.caption(f'Retrieval: {result.get("retrieval_mode", "TF-IDF")}. Score is a ranking, not a probability or proof.')

with chat:
    section_header(
        tr("AI Investigation Chat", interface_language),
        "Evidence-grounded drafting · every turn retrieves fresh sources",
        "icon_chat.svg",
    )
    st.write(tr("Ask questions about this case's evidence. Each question triggers fresh local retrieval.", interface_language))

    clear_col, _ = st.columns([1, 5])
    with clear_col:
        if st.button(f"🗑️ {tr('Clear Chat', interface_language)}", key="clear_chat"):
            clear_chat(case_id)
            st.session_state.chat_history = []
            st.rerun()

    for message in st.session_state.chat_history:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
            if message["role"] == "assistant" and message.get("retrieval_query"):
                st.caption(f'Evidence search used: {message["retrieval_query"]}')
            if message["role"] == "assistant" and message.get("sources"):
                with st.expander("Retrieved evidence sources"):
                    for source in message["sources"]:
                        st.markdown(
                            f'**{source["evidence_id"]} · {source["filename"]}** '
                            f'(score {source["score"]:.3f})'
                        )
                        st.write(source["snippet"])

    if not st.session_state.evidence:
        st.info(tr("Add evidence in the Evidence Vault before asking questions.", interface_language))
    question = st.chat_input(
        tr("Ask your investigation question...", interface_language),
        disabled=not st.session_state.evidence,
    )
    if question:
        prior_history = list(st.session_state.chat_history)
        with st.spinner("Searching evidence and analyzing with the local LLM..."):
            search_query = resolve_followup_query(question, prior_history)
            evidence_results = search_evidence(
                search_query, st.session_state.evidence, top_k=5
            )
            try:
                answer = generate_answer(
                    question, evidence_results, interface_language, prior_history
                )
            except Exception as exc:
                st.error(str(exc))
                st.stop()
        save_chat_message(case_id, "user", question)
        save_chat_message(
            case_id, "assistant", answer, evidence_results,
            retrieval_query=search_query,
        )
        log_activity(case_id, "investigator_question_processed", {
            "question": question,
            "retrieval_query": search_query,
            "evidence_ids": sorted({item["evidence_id"] for item in evidence_results}),
        })
        st.rerun()

with anomaly:
    section_header(
        tr("Anomaly Review", interface_language),
        "Rule indicators and local Isolation Forest ranking on structured logs",
        "icon_anomaly.svg",
    )
    st.write(tr("Review rule-based indicators and a local Isolation Forest ranking on CSV/JSON logs. Flags are leads for human review, not evidence of intent or wrongdoing.", interface_language))
    structured_items = [
        item for item in st.session_state.evidence
        if item.get("file_type", "").lower() in {"csv", "json"}
    ]
    if not structured_items:
        st.info(tr("Add CSV or JSON log evidence to run anomaly review.", interface_language))
    else:
        st.caption(
            "Timestamp checks run only when source values include an explicit timezone. "
            "Naive timestamps are not treated as UTC because the source timezone is unknown."
        )
        if st.button(tr("Analyze structured logs", interface_language), key="analyze_logs"):
            with st.spinner("Analyzing structured records locally..."):
                flagged, summaries = analyze_structured_evidence(structured_items)
            st.session_state[f"anomaly_{case_id}"] = {
                "flagged": flagged,
                "summaries": summaries,
            }
            save_analysis_result(case_id, "anomaly", st.session_state[f"anomaly_{case_id}"])

        analysis = st.session_state.get(f"anomaly_{case_id}")
        if analysis:
            st.markdown(f'#### {tr("Files analyzed", interface_language)}')
            st.dataframe(analysis["summaries"], width="stretch")
            st.markdown(f'#### {tr("Records flagged for review", interface_language)}')
            flagged = analysis["flagged"]
            if not flagged:
                st.success("No records were flagged by the current rules or model. This does not establish that the logs are free of suspicious activity.")
            else:
                st.dataframe(
                    [{
                        "Evidence ID": row["evidence_id"],
                        "File": row["filename"],
                        "Source row": row["row_number"],
                        "Review reasons": "; ".join(row["reasons"]),
                    } for row in flagged],
                    width="stretch",
                )
                selection = st.selectbox(
                    tr("Inspect flagged source record", interface_language),
                    range(len(flagged)),
                    format_func=lambda index: (
                        f'{flagged[index]["evidence_id"]} · '
                        f'{flagged[index]["filename"]} · row {flagged[index]["row_number"]}'
                    ),
                    key=f"anomaly_record_{case_id}",
                )
                selected = flagged[selection]
                st.markdown(f'**{tr("Review reasons", interface_language)}**')
                for reason in selected["reasons"]:
                    st.write(f"- {reason}")
                st.markdown(f'**{tr("Original parsed record", interface_language)}**')
                st.json(selected["original_record"])

with relationships:
    section_header(
        tr("Evidence Relationships", interface_language),
        "Identifier and time-proximity link map for review",
        "icon_network.svg",
    )
    st.write(tr("The map links explicit identifiers that occur in the same source record. Timezone-explicit records from different files may also be connected when they are close in time.", interface_language))
    if not st.session_state.evidence:
        st.info(tr("Add evidence to this case before building a relationship map.", interface_language))
    else:
        if st.button(tr("Build relationship map", interface_language), key="build_relationships"):
            with st.spinner("Extracting explicit identifiers and building the graph locally..."):
                graph_html, record_catalog, graph_stats = build_relationship_graph(
                    st.session_state.evidence
                )
            st.session_state[f"relationships_{case_id}"] = {
                "html": graph_html,
                "catalog": record_catalog,
                "stats": graph_stats,
            }
            save_analysis_result(case_id, "relationships", {
                "catalog": record_catalog,
                "stats": graph_stats,
            })

        relationship_result = st.session_state.get(f"relationships_{case_id}")
        if relationship_result:
            stats = relationship_result["stats"]
            st.caption(
                f'{stats["records"]} records · {stats["entities"]} explicit identifiers · '
                f'{stats["temporal_links"]} possible time-proximity links'
            )
            if stats["truncated"]:
                st.warning(
                    f'Graph input exceeded the {stats["records"]:,}-record limit; '
                    f'at least {stats["truncated"]:,} additional records were omitted.'
                )
            graph_html = relationship_result["html"]
            if graph_html:
                st.components.v1.html(graph_html, height=650, scrolling=True)
            else:
                st.info("No records were available to graph.")

            record_catalog = relationship_result["catalog"]
            identifiers = sorted({
                identifier
                for record in record_catalog
                for identifier in record["identities"]
            })
            if identifiers:
                selected_identifier = st.selectbox(
                    "Inspect an identifier and its supporting source records",
                    identifiers,
                    key=f"relationship_entity_{case_id}",
                )
                matches = supporting_records(record_catalog, selected_identifier)
                for record in matches:
                    with st.expander(
                        f'{record["evidence_id"]} · {record["filename"]} · record {record["row_number"]}'
                    ):
                        if record["timestamp"]:
                            st.caption(f'Parsed timestamp: {record["timestamp"]}')
                        st.json(record["record"])
            st.caption(tr("Entity extraction is deterministic and identifier-focused. Names are included only when explicit fields or labels are present. A time-proximity edge is a review cue, not proof of communication or causation.", interface_language))

with operations:
    section_header(
        tr("Leads & Case Diary", interface_language),
        "Unverified leads and investigator-recorded actions",
        "icon_leads.svg",
    )
    st.caption(tr("Rule-generated suggestions are unverified and must be reviewed against source evidence.", interface_language))
    if st.button(tr("Generate or refresh leads", interface_language), key="generate_leads", disabled=not st.session_state.evidence):
        anomaly_result = st.session_state.get(f"anomaly_{case_id}") or {}
        relationship_result = st.session_state.get(f"relationships_{case_id}") or {}
        leads = generate_investigative_leads(
            anomaly_result.get("flagged", []),
            relationship_result.get("catalog", []),
        )
        save_leads(case_id, leads)
        st.rerun()

    leads = list_leads(case_id)
    if leads:
        for lead in leads:
            with st.expander(f'{lead["lead_id"]} · {lead["type"]} · {lead["status"]}'):
                st.write(lead["statement"])
                st.caption(lead["basis"])
                st.write("**Supporting evidence:** " + ", ".join(lead["supporting_evidence"]))
                st.write("**Suggested follow-up:** " + lead["suggested_follow_up"])
                stored_status_options = ["Unreviewed", "Under Review", "Actioned", "Closed - no further action", "Needs refresh"]
                display_status_options = [tr(value, interface_language) for value in stored_status_options]
                current_status = lead["status"] if lead["status"] in stored_status_options else stored_status_options[0]
                new_status = st.selectbox(
                    tr("Review status", interface_language), display_status_options,
                    index=stored_status_options.index(current_status),
                    key=f'lead_status_{case_id}_{lead["lead_id"]}',
                )
                if st.button(tr("Save lead status", interface_language), key=f'lead_save_{case_id}_{lead["lead_id"]}'):
                    update_lead_status(case_id, lead["lead_id"], stored_status_options[display_status_options.index(new_status)])
                    st.rerun()
    else:
        st.info(tr("No leads have been generated for this case yet. Run Anomaly Review and build the relationship map first.", interface_language))

    st.divider()
    st.subheader(tr("Case diary and investigator actions", interface_language))
    with st.form(f"activity_form_{case_id}", clear_on_submit=True):
        action_type = st.selectbox(
            tr("Action type", interface_language),
            [tr(value, interface_language) for value in ["Investigator note", "Evidence reviewed", "Follow-up action", "Decision or disposition"]],
        )
        action_details = st.text_area(tr("Describe the action taken", interface_language), max_chars=4000)
        evidence_options = ["None"] + [item["evidence_id"] for item in st.session_state.evidence]
        related_evidence = st.selectbox(tr("Related evidence (optional)", interface_language), evidence_options)
        log_submitted = st.form_submit_button(tr("Record action", interface_language))
    if log_submitted:
        if not action_details.strip():
            st.error(tr("Enter a short description before recording the action.", interface_language))
        else:
            details = {"description": action_details.strip()}
            if related_evidence != "None":
                details["evidence_id"] = related_evidence
            log_activity(case_id, action_type, details)
            st.success(tr("Action added to the case activity log.", interface_language))

    activity = list_activity(case_id)
    if activity:
        st.dataframe(
            [{
                tr("Time (UTC)", interface_language): entry["created_at"],
                tr("Event", interface_language): entry["event_type"],
                tr("Details", interface_language): "; ".join(f'{key}: {value}' for key, value in entry["details"].items()),
            } for entry in activity],
            width="stretch",
        )
    diary_text = make_case_diary(case_id, active_case["name"], activity)
    st.download_button(
        tr("Download case diary (TXT)", interface_language), diary_text,
        file_name=f"{case_id}_case_diary.txt", mime="text/plain",
    )
    diary_pdf_key = f"diary_pdf_{case_id}"
    if st.button(tr("Prepare case diary PDF", interface_language), key=f"prepare_diary_pdf_{case_id}"):
        st.session_state[diary_pdf_key] = make_pdf(f"{case_id} Case Diary", diary_text, interface_language)
    if st.session_state.get(diary_pdf_key):
        st.download_button(
            tr("Download case diary (PDF)", interface_language), st.session_state[diary_pdf_key],
            file_name=f"{case_id}_case_diary.pdf", mime="application/pdf",
        )

with report:
    section_header(
        tr("Case Report", interface_language),
        "Inventory, diary, and draft report exports",
        "icon_report.svg",
    )
    evidence = st.session_state.evidence
    if not evidence:
        st.info(tr("Add evidence to this case before generating a report.", interface_language))
    else:
        inventory_text = make_report(case_id, evidence)
        col_text, col_pdf = st.columns(2)
        with col_text:
            st.download_button(
                tr("Download evidence inventory (TXT)", interface_language), inventory_text,
                file_name=f"{case_id}_inventory.txt", mime="text/plain",
            )
        with col_pdf:
            if st.button(tr("Prepare evidence inventory PDF", interface_language), key=f"inventory_pdf_{case_id}"):
                st.session_state[f"inventory_pdf_data_{case_id}"] = make_pdf(
                    f"{case_id} Evidence Inventory", inventory_text, interface_language
                )
            pdf_data = st.session_state.get(f"inventory_pdf_data_{case_id}")
            if pdf_data:
                st.download_button(
                    tr("Download evidence inventory (PDF)", interface_language), pdf_data,
                    file_name=f"{case_id}_inventory.pdf", mime="application/pdf",
                )

        st.markdown(f'#### {tr("AI-assisted report draft", interface_language)}')
        st.caption(tr("Requires the configured local Ollama model. Generated text is a draft and must be checked against the cited records.", interface_language))
        if st.button(tr("Draft report with local AI", interface_language), key=f"draft_report_{case_id}"):
            passages = search_evidence(
                "case events access communications files accounts investigation",
                evidence,
                top_k=8,
            )
            try:
                draft = generate_case_report(
                    case_id, passages, list_leads(case_id), list_activity(case_id), interface_language
                )
            except Exception as exc:
                st.error(str(exc))
            else:
                st.session_state[f"ai_report_{case_id}"] = draft
                log_activity(case_id, "AI report draft generated", {
                    "evidence_ids": sorted({item["evidence_id"] for item in passages})
                })
        ai_draft = st.session_state.get(f"ai_report_{case_id}")
        if ai_draft:
            st.markdown(ai_draft)
            st.download_button(
                tr("Download AI report draft (TXT)", interface_language), ai_draft,
                file_name=f"{case_id}_AI_report_draft.txt", mime="text/plain",
            )
            if st.button(tr("Prepare AI report PDF", interface_language), key=f"ai_report_pdf_{case_id}"):
                st.session_state[f"ai_report_pdf_data_{case_id}"] = make_pdf(
                    f"{case_id} AI Report Draft", ai_draft, interface_language
                )
            ai_pdf = st.session_state.get(f"ai_report_pdf_data_{case_id}")
            if ai_pdf:
                st.download_button(
                    tr("Download AI report draft (PDF)", interface_language), ai_pdf,
                    file_name=f"{case_id}_AI_report_draft.pdf", mime="application/pdf",
                )

st.divider()
st.caption(
    "Local prototype: search uses TF-IDF; Ollama is used for answer generation. "
    "Hashes help detect changes to a copy but do not establish forensic provenance. "
    "Have a qualified investigator verify findings and preserve originals using approved procedures."
)
