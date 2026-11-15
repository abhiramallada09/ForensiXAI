import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.event import TimelineEvent
from backend.app.models.finding import ForensicFinding
from backend.app.api.v1.schemas import (
    CorrelationCluster,
    CorrelatedEventItem,
    CorrelationReportResponse,
)


def correlate_case_events(
    case_id: str,
    db: Session,
    time_window_seconds: int = 60,
    min_cluster_size: int = 2,
    generate_findings: bool = True,
) -> CorrelationReportResponse:
    """
    ForensiX Multi-Evidence Correlation Engine.
    Identifies temporal proximity clusters and cross-artifact causality chains
    across heterogeneous evidence sources (Filesystem MACB, Event Logs, Memory, Network).
    Enforces the Forensic Safety Rule: Only assign CORRELATED if multiple independent
    artifacts support the finding.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise ValueError(f"Case with ID '{case_id}' does not exist.")

    # 1. Fetch all timeline events for the case ordered chronologically
    events = (
        db.query(TimelineEvent)
        .filter(TimelineEvent.case_id == case_id)
        .order_by(TimelineEvent.timestamp.asc())
        .all()
    )

    if not events:
        return CorrelationReportResponse(
            case_id=case_id,
            time_window_seconds=time_window_seconds,
            total_events_analyzed=0,
            total_clusters=0,
            multi_source_correlations_count=0,
            findings_generated_count=0,
            clusters=[],
            generated_at=datetime.now(timezone.utc),
        )

    # Preload evidence map
    evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    evidence_map: Dict[str, Evidence] = {e.id: e for e in evidence_items}

    # 2. Sliding window temporal clustering
    raw_clusters: List[List[TimelineEvent]] = []
    current_cluster: List[TimelineEvent] = []

    for event in events:
        if not current_cluster:
            current_cluster.append(event)
            continue

        prev_event = current_cluster[-1]
        time_diff = (event.timestamp - prev_event.timestamp).total_seconds()

        # If event falls within window relative to previous event in the cluster
        if 0 <= time_diff <= time_window_seconds:
            current_cluster.append(event)
        else:
            if len(current_cluster) >= min_cluster_size:
                raw_clusters.append(current_cluster)
            current_cluster = [event]

    if len(current_cluster) >= min_cluster_size:
        raw_clusters.append(current_cluster)

    # 3. Analyze each cluster, compute confidence and classification
    analyzed_clusters: List[CorrelationCluster] = []
    findings_created = 0
    multi_source_count = 0

    for idx, cluster_events in enumerate(raw_clusters, start=1):
        start_time = cluster_events[0].timestamp
        end_time = cluster_events[-1].timestamp
        duration = max(0.0, (end_time - start_time).total_seconds())

        # Collect unique evidence sources
        source_evidence_ids = {e.evidence_id for e in cluster_events if e.evidence_id}
        source_filenames = []
        for eid in source_evidence_ids:
            if eid in evidence_map:
                source_filenames.append(evidence_map[eid].filename)

        source_count = len(source_evidence_ids)
        is_multi_source = source_count >= 2

        if is_multi_source:
            multi_source_count += 1

        # Check for chronological anomalies (e.g. deletion before creation, or modified earlier than created)
        has_anomaly = False
        anomaly_reason = ""
        created_times = [
            e.timestamp for e in cluster_events if e.event_type == "File Created"
        ]
        modified_times = [
            e.timestamp for e in cluster_events if e.event_type == "File Modified"
        ]
        if created_times and modified_times:
            if min(modified_times) < min(created_times):
                has_anomaly = True
                anomaly_reason = "File Modified timestamp precedes File Created timestamp (Possible Timestomping / Inconsistency)."

        # Determine confidence and classification
        if is_multi_source:
            # 2 sources = 0.82 base, 3+ sources = 0.92 base + event density bonus
            base_conf = 0.82 if source_count == 2 else 0.90
            density_bonus = min(0.06, len(cluster_events) * 0.015)
            confidence = round(min(0.98, base_conf + density_bonus), 2)
            classification = "SUSPICIOUS" if has_anomaly else "CORRELATED"
        else:
            # Single evidence item events clustered in time
            confidence = round(min(0.78, 0.60 + min(0.15, len(cluster_events) * 0.03)), 2)
            classification = "SUSPICIOUS" if has_anomaly else "OBSERVED"

        # Build CorrelatedEventItems with relative time delta
        event_items: List[CorrelatedEventItem] = []
        for ev in cluster_events:
            delta = max(0.0, (ev.timestamp - start_time).total_seconds())
            evi = evidence_map.get(ev.evidence_id) if ev.evidence_id else None
            filename = evi.filename if evi else ev.artifact_category

            event_items.append(
                CorrelatedEventItem(
                    id=ev.id,
                    timestamp=ev.timestamp,
                    event_type=ev.event_type,
                    timestamp_source=ev.timestamp_source,
                    description=ev.description,
                    classification=classification if is_multi_source else ev.classification,
                    confidence=confidence if is_multi_source else ev.confidence,
                    evidence_id=ev.evidence_id,
                    evidence_filename=filename,
                    time_delta_seconds=round(delta, 2),
                )
            )

        # Summary description
        if is_multi_source:
            summary = (
                f"Multi-evidence cluster correlating {len(cluster_events)} events across "
                f"{source_count} independent sources ({', '.join(source_filenames[:3])}) within {duration:.1f}s."
            )
        else:
            summary = (
                f"Temporal cluster of {len(cluster_events)} events observed on "
                f"{source_filenames[0] if source_filenames else 'evidence artifact'} within {duration:.1f}s."
            )

        cluster_obj = CorrelationCluster(
            cluster_id=f"cluster-{case_id[:8]}-{idx:02d}",
            start_time=start_time,
            end_time=end_time,
            duration_seconds=round(duration, 2),
            event_count=len(cluster_events),
            evidence_sources_count=source_count,
            evidence_filenames=source_filenames,
            confidence=confidence,
            cluster_classification=classification,
            summary=summary,
            events=event_items,
        )
        analyzed_clusters.append(cluster_obj)

        # 4. Synthesize ForensicFinding if requested and significant
        if generate_findings and (is_multi_source or has_anomaly):
            finding_title = (
                f"Anomaly: {anomaly_reason}"
                if has_anomaly
                else f"Correlated Evidence Cluster: {len(cluster_events)} events across {source_count} sources"
            )

            # Check if duplicate finding already exists
            existing_finding = (
                db.query(ForensicFinding)
                .filter(
                    ForensicFinding.case_id == case_id,
                    ForensicFinding.title == finding_title,
                )
                .first()
            )

            if not existing_finding:
                severity = "High" if has_anomaly else ("Medium" if is_multi_source else "Low")
                reason_text = (
                    f"Temporal correlation confirmed: {len(cluster_events)} actions occurred within a "
                    f"{duration:.1f}s window across {source_count} distinct forensic evidence items. "
                    f"Sources: {', '.join(source_filenames)}."
                )
                if has_anomaly:
                    reason_text += f" Warning: {anomaly_reason}"

                artifacts_payload = [
                    {
                        "event_id": ev.id,
                        "event_type": ev.event_type,
                        "timestamp": ev.timestamp.isoformat(),
                        "source": ev.timestamp_source,
                        "evidence_id": ev.evidence_id,
                        "delta_s": round((ev.timestamp - start_time).total_seconds(), 2),
                    }
                    for ev in cluster_events
                ]

                new_finding = ForensicFinding(
                    case_id=case_id,
                    title=finding_title,
                    finding_type="Timestamp Correlation" if has_anomaly else "Multi-Evidence Correlation",
                    classification=classification,
                    severity=severity,
                    confidence=confidence,
                    reason=reason_text,
                    explanation=f"Correlated via ForensiX Time-Delta Sliding Window Engine (window={time_window_seconds}s). Provenance corroborated across {source_count} distinct artifacts.",
                    supporting_artifacts=artifacts_payload,
                    recommendation="Proceed to memory artifact cross-validation in Phase 6."
                    if not has_anomaly
                    else "Manual forensic verification recommended: Inspect MFT $STANDARD_INFORMATION vs $FILE_NAME attributes.",
                )
                db.add(new_finding)
                findings_created += 1

                # Update events classification if multi-source corroborated
                for ev in cluster_events:
                    if is_multi_source:
                        ev.classification = classification
                        if ev.confidence < confidence:
                            ev.confidence = confidence

    if findings_created > 0:
        db.commit()

    return CorrelationReportResponse(
        case_id=case_id,
        time_window_seconds=time_window_seconds,
        total_events_analyzed=len(events),
        total_clusters=len(analyzed_clusters),
        multi_source_correlations_count=multi_source_count,
        findings_generated_count=findings_created,
        clusters=analyzed_clusters,
        generated_at=datetime.now(timezone.utc),
    )

