import { Clock3, Download, Eye, Fingerprint, ListChecks, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";

import { SeverityBadge, SourceTypeBadge } from "@/components/sentivra/badges";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { detectionLabel, displayedScenario, durationMs, formatDuration, formatTimestamp, readable, runOutcome, timelineElapsed } from "@/lib/simulation";
import type { SimulationRun, SimulationScenario } from "@/types/api";
import styles from "./command-center.module.css";

export function RunDetails({ run, scenarios, onDownload }: { run: SimulationRun; scenarios: SimulationScenario[]; onDownload: () => void }) {
  const outcome = runOutcome(run);
  const scenario = displayedScenario(run, scenarios)!;
  const results = run.detector_results?.length ? run.detector_results : run.findings ?? [];
  const evidenceCount = results.reduce((total, result) => total + result.evidence.length, 0);
  const topEvidence = results.flatMap((result) => result.evidence.map((evidence) => ({ detector: result.detector, detail: evidence.detail }))).slice(0, 3);
  const errors = [...new Set([...(run.errors ?? []), ...(run.error ? [run.error] : [])])];
  const timeline = run.timeline ?? [];
  const VerdictIcon = outcome.kind === "block" ? ShieldX : outcome.kind === "allow" ? ShieldCheck : outcome.kind === "review" ? Eye : ShieldAlert;

  return (
    <section className={styles.report} aria-label="Selected execution report">
      <Card className={styles.resultCard} data-tone={outcome.tone}>
        <CardHeader>
          <div className={styles.sectionHeading}><div><p className={styles.eyebrow}>Selected execution</p><h2>{scenario.name}</h2></div><div><SourceTypeBadge sourceType={run.source_type} /><span className={styles.marker}>SIMULATED EVENT</span></div></div>
          <p className={styles.executionId}><Fingerprint size={14} aria-hidden="true" />{run.execution_id}</p>
        </CardHeader>
        <CardContent className={styles.resultBody}>
           <div className={styles.verdict}><VerdictIcon size={22} aria-hidden="true" /><div><h3>{outcome.label}</h3><p>{outcome.explanation}</p><Button variant="outline" size="sm" onClick={onDownload}><Download /> Download report (.md)</Button></div></div>
          <div className={styles.keyEvidence}><strong>Key evidence</strong>{topEvidence.length ? <ul>{topEvidence.map((item, index) => <li key={`${item.detector}-${index}`}><span>{item.detector}</span>{item.detail}</li>)}</ul> : <p>No evidence items were recorded. That does not establish safety outside this fixture.</p>}</div>
           <dl className={styles.resultMetrics}>
            <div><dt>Execution</dt><dd>{readable(run.status)}</dd></div>
            <div><dt>Detection</dt><dd>{detectionLabel(run.detection_state)}</dd></div>
            <div><dt>Risk assessment</dt><dd>{run.risk_assessment ? <><SeverityBadge severity={run.risk_assessment.severity} /><span>{run.risk_assessment.risk_score}/100</span></> : "Not recorded"}</dd></div>
             <div><dt>Recorded duration</dt><dd>{formatDuration(durationMs(run))}</dd></div>
           </dl>
           {run.target ? <div className={styles.policyExplanation}><strong>Local target request</strong><p>{run.target.endpoint}</p><p>HTTP {run.target.status_code} · Target outcome: {readable(run.target.target_execution_state)} · Protected operation: {run.target.protected_operation_executed ? "EXECUTED" : "NOT EXECUTED"}</p><pre className={styles.targetResponse}>{JSON.stringify(run.target.response, null, 2)}</pre></div> : null}
           {run.fusion_incident ? <div className={styles.fusionIncident}><strong>Correlated attack-chain incident</strong><p>{readable(run.fusion_incident.classification)} · {run.fusion_incident.signal_count} supporting signal{run.fusion_incident.signal_count === 1 ? "" : "s"}</p><p className={styles.muted}>Dry-run mitigation: {run.fusion_incident.mitigation.actions.join(", ")}. Real-world action: none.</p></div> : null}
          <div className={styles.policyExplanation}><strong>Policy explanation</strong><p>{run.enforcement?.reason ?? "No policy explanation was recorded."}</p><p className={styles.muted}>Recorded decision: {readable(run.enforcement_decision)} · Real-world action: {run.enforcement?.real_world_action_taken === false ? "none" : run.enforcement?.real_world_action_taken ? "unexpected action reported" : "not recorded"}</p></div>
          {errors.length ? <div role="status" className={styles.analysisErrors}><strong>Analysis limitations / errors</strong><ul>{errors.map((error) => <li key={error}>{error}</li>)}</ul></div> : null}
          <details className={styles.technicalDetails}><summary>Show technical details</summary><p className={styles.muted}>{scenario.limitation}</p><p className={styles.muted}>Execution ID: <code>{run.execution_id}</code> · Event: <code>{run.event_id ?? "not persisted"}</code> · Alert: <code>{run.alert_id ?? "none"}</code></p></details>
        </CardContent>
      </Card>

      <div className={styles.reportGrid}>
        <Card>
          <CardHeader><div className={styles.sectionHeading}><h2><ListChecks size={17} aria-hidden="true" /> Detector evidence</h2><span className={styles.count}>{evidenceCount} items</span></div><p className={styles.muted}>All returned detector results, including clean and failed analyses.</p></CardHeader>
          <CardContent className={styles.evidencePanel}>
            {Object.keys(run.detector_availability ?? {}).length ? <dl className={styles.availabilityList}>{Object.entries(run.detector_availability!).map(([name, availability]) => <div key={name}><dt>{name}</dt><dd><span className={styles.badge} data-tone={availability.status === "Available" ? "cyan" : "amber"}>{availability.status}</span><p>{availability.detail}</p></dd></div>)}</dl> : <p className={styles.muted}>Detector availability was not recorded for this execution.</p>}
            {!evidenceCount ? <p className={styles.noEvidence}>No evidence was recorded. {outcome.kind === "allow" ? "The available detector reported no suspicious finding for this fixture." : "An absence of evidence does not establish a safe result."}</p> : null}
            {results.map((result, index) => (
              <details className={styles.detectorResult} key={`${result.detector}-${index}`} open>
                <summary><span>{result.detector}</span><span className={styles.muted}>{result.status ? readable(result.status) : result.severity}</span></summary>
                <div className={styles.detectorBody}>
                  <div className={styles.resultTags}><SeverityBadge severity={result.severity} /><span>Score {result.score}</span><span>Confidence {(result.confidence * 100).toFixed(0)}%</span></div>
                  {result.evidence.length ? <ul className={styles.evidenceList}>{result.evidence.map((evidence, i) => <li key={`${evidence.type}-${i}`}><strong>{readable(evidence.type)}</strong><p>{evidence.detail}</p>{evidence.excerpt ? <pre>{evidence.excerpt}</pre> : null}</li>)}</ul> : <p className={styles.muted}>This detector returned no evidence items.</p>}
                  {result.rule_ids?.length ? <p className={styles.muted}>Rules: {result.rule_ids.join(", ")}</p> : null}
                  {result.model_id ? <p className={styles.muted}>Model: {result.model_id}{result.model_version ? ` · ${result.model_version}` : ""}</p> : null}
                </div>
              </details>
            ))}
            <dl className={styles.linkedRecords}><div><dt>Event ID</dt><dd>{run.event_id ?? "Not persisted"}</dd></div><div><dt>Alert ID</dt><dd>{run.alert_id ?? "No alert created"}</dd></div></dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><h2 className={styles.sectionTitle}><Clock3 size={17} aria-hidden="true" /> Execution timeline</h2><p className={styles.muted}>Recorded backend timestamps; elapsed from the execution start.</p></CardHeader>
          <CardContent>
            <div className={styles.timingSummary}><span>Started</span><time dateTime={run.started_at} title={run.started_at}>{formatTimestamp(run.started_at)}</time></div>
            {timeline.length ? <ol className={styles.timeline}>{timeline.map((entry, index) => <li key={`${entry.stage}-${index}`}><span className={styles.timelineDot} /><div><strong>{readable(entry.stage)}</strong><time dateTime={entry.timestamp} title={entry.timestamp}>{entry.timestamp}</time></div><span className={styles.elapsed}>{timelineElapsed(entry.timestamp, run.started_at)}</span></li>)}</ol> : <p className={styles.noEvidence}>No stage timestamps were recorded{run.status === "RUNNING" ? " yet. The read-only status refresh will check this execution." : " for this execution."}</p>}
            <div className={styles.timingSummary}><span>Completed</span>{run.completed_at ? <time dateTime={run.completed_at} title={run.completed_at}>{formatTimestamp(run.completed_at)}</time> : <span>Not recorded</span>}</div>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}
