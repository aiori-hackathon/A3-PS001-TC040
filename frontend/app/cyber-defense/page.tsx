"use client";

import { useEffect, useRef, useState } from "react";
import { Activity, ArrowLeft, ArrowRight, Check, Copy, Crosshair, Download, History, Maximize2, Minimize2, Play, RefreshCw, RotateCcw, ShieldCheck } from "lucide-react";

import { EmptyState, ErrorState, LoadingBlock, PageHeader } from "@/components/sentivra/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api";
import { createRequestKey, detectionLabel, displayedScenario, formatDuration, formatTimestamp, HISTORY_PAGE_SIZE, relativeTime, runOutcome, shortId, SIMULATION_NOTICE } from "@/lib/simulation";
import type { RansomwareHealth, SimulationRun, SimulationScenario, SimulationStats } from "@/types/api";
import { RunDetails } from "./run-details";
import { Topology } from "./topology";
import { ComparisonPanel } from "./comparison";
import styles from "./command-center.module.css";

type Attempt = { scenarioId: string; requestKey: string };

const VERIFIED_STANDARDS = [
  ["OAuth 2.0 client credentials", "RFC 6749", "https://www.rfc-editor.org/rfc/rfc6749"],
  ["Bearer token authorization", "RFC 6750", "https://www.rfc-editor.org/rfc/rfc6750"],
  ["HTTP semantics", "RFC 9110", "https://www.rfc-editor.org/rfc/rfc9110"],
  ["JSON data interchange", "RFC 8259", "https://www.rfc-editor.org/rfc/rfc8259"],
  ["Sigma / MITRE ATT&CK", "non-IETF", "https://sigmahq.io/"],
] as const;

export default function CyberDefensePage() {
  const scenarios = useApi<SimulationScenario[]>("/api/simulation/scenarios");
  const stats = useApi<SimulationStats>("/api/simulation/stats");
  const ransomwareHealth = useApi<RansomwareHealth>("/api/v1/ransomware/health");
  const [offset, setOffset] = useState(0);
  // The extra row is a lookahead; pagination does not depend on stale aggregate counts.
  const history = useApi<SimulationRun[]>(`/api/simulation/runs?limit=${HISTORY_PAGE_SIZE + 1}&offset=${offset}`, { keepPreviousData: false });
  const [selectedId, setSelectedId] = useState("");
  const [selectedRun, setSelectedRun] = useState<SimulationRun | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [attempt, setAttempt] = useState<Attempt | null>(null);
  const [comparisonRuns, setComparisonRuns] = useState<SimulationRun[]>([]);
  const [comparisonError, setComparisonError] = useState<unknown>(null);
  const [sequenceBusy, setSequenceBusy] = useState(false);
  const [presentationMode, setPresentationMode] = useState(false);
  const [presentationCaption, setPresentationCaption] = useState<string | null>(null);
  const [historyFilter, setHistoryFilter] = useState<"all" | "block" | "allow">("all");
  const [downloadMessage, setDownloadMessage] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const inFlight = useRef(false);
  const pendingAttempt = useRef<Attempt | null>(null);
  const detail = useApi<SimulationRun>(selectedRun ? `/api/simulation/runs/${encodeURIComponent(selectedRun.execution_id)}` : null, {
    keepPreviousData: false,
    refreshInterval: (data) => (data ?? selectedRun)?.status === "RUNNING" ? 2_000 : 0,
    shouldRetryOnError: false,
  });
  const run = detail.data?.execution_id === selectedRun?.execution_id ? detail.data ?? null : selectedRun;
  const selected = selectedId || scenarios.data?.[0]?.scenario_id || "";
  const scenario = scenarios.data?.find((item) => item.scenario_id === selected);
  const ransomwareScenario = scenarios.data?.find((item) => item.scenario_id === "ransomware-replay");
  const ransomwareChainScenario = scenarios.data?.find((item) => item.scenario_id === "ransomware-attack-chain");
  const runScenario = displayedScenario(run, scenarios.data);
  const rows = (history.data?.slice(0, HISTORY_PAGE_SIZE) ?? []).filter((item) => historyFilter === "all" || runOutcome(item).kind === historyFilter);
  const counts = stats.data?.totals;
  const pending = Boolean(attempt);
  const controlsBusy = busy || sequenceBusy;
  const recordedStages = new Set(run?.timeline?.map((entry) => entry.stage) ?? []);
  const story = [
    { label: "Attack sent", done: Boolean(run) || busy || recordedStages.has("target_request_created") },
    { label: "Detected", done: recordedStages.has("detection_completed") || Boolean(run?.detection_state && run.detection_state !== "REVIEW_REQUIRED") },
    { label: "Blocked", done: runOutcome(run).kind === "block" },
    { label: "Report ready", done: Boolean(run?.execution_id && run?.status !== "RUNNING") },
  ];
  const previousStatus = useRef<string | null>(null);
  const { mutate: mutateStats } = stats;
  const { mutate: mutateHistory } = history;

  // GET polling may observe a previously uncertain execution finishing; refresh
  // aggregates then, without ever replaying the POST automatically.
  useEffect(() => {
    if (previousStatus.current === "RUNNING" && run && run.status !== "RUNNING") {
      void mutateStats();
      void mutateHistory();
    }
    previousStatus.current = run?.status ?? null;
  }, [run, mutateStats, mutateHistory]);

  useEffect(() => {
    if (!presentationMode) return;
    const onKeyDown = (event: KeyboardEvent) => { if (event.key === "Escape") setPresentationMode(false); };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [presentationMode]);

  async function execute(retry = false, scenarioIdOverride?: string) {
    if (inFlight.current) return;
    const request = retry ? pendingAttempt.current : scenarioIdOverride ? { scenarioId: scenarioIdOverride, requestKey: createRequestKey() } : scenario ? { scenarioId: scenario.scenario_id, requestKey: createRequestKey() } : null;
    if (!request || (!retry && pendingAttempt.current)) return;
    // A synchronous guard prevents same-tick double submissions before React renders.
    inFlight.current = true;
    pendingAttempt.current = request;
    setAttempt(request);
    setBusy(true);
    setError(null);
    setSelectedRun(null);
    setComparisonRuns([]);
    try {
      const result = await api.runSimulation(request.scenarioId, request.requestKey);
      setSelectedRun(result);
      pendingAttempt.current = null;
      setAttempt(null);
      if (offset !== 0) setOffset(0);
      void mutateHistory();
      void mutateStats();
    } catch (cause) {
      // Keep the original key and scenario. Only the explicit retry button can
      // resubmit, so a lost response cannot silently create a second execution.
      setError(cause);
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }

  async function runBothScenarios(presentation = false) {
    if (inFlight.current) return;
    const ids = ["sqli-indicator", "benign-control"].filter((id) => scenarios.data?.some((item) => item.scenario_id === id));
    if (ids.length !== 2) return;
    inFlight.current = true;
    setSequenceBusy(true);
    setBusy(true);
    setSelectedRun(null);
    setComparisonRuns([]);
    setComparisonError(null);
    setError(null);
    if (presentation) setPresentationCaption("1. Normal request passes");
    try {
      const results: SimulationRun[] = [];
      for (const scenarioId of ids) {
        const result = await api.runSimulation(scenarioId, createRequestKey());
        results.push(result);
        setComparisonRuns([...results]);
        setSelectedRun(result);
        if (results.length === 1) {
          // Let the first confirmed execution complete its full presentation
          // before resetting the temporary marker for the second request.
          setBusy(false);
          if (presentation) await new Promise((resolve) => window.setTimeout(resolve, 10_000));
          else await new Promise((resolve) => window.setTimeout(resolve, 6_500));
          if (presentation) setPresentationCaption("2. SQL injection arrives");
          setSelectedRun(null);
          setBusy(true);
        } else if (presentation) {
          setPresentationCaption("3. Sentivra detects it");
          await new Promise((resolve) => window.setTimeout(resolve, 12_000));
          setPresentationCaption("4. Blocked, report ready");
          await new Promise((resolve) => window.setTimeout(resolve, 23_000));
        }
      }
      void mutateHistory();
      void mutateStats();
    } catch (cause) {
      setComparisonError(cause);
    } finally {
      inFlight.current = false;
      setSequenceBusy(false);
      setBusy(false);
    }
  }

  function startPresentation() {
    if (presentationMode) { setPresentationMode(false); return; }
    setPresentationMode(true);
    void runBothScenarios(true);
  }

  function dismissRequest() {
    if (inFlight.current) return;
    pendingAttempt.current = null;
    setAttempt(null);
    setError(null);
    void mutateHistory();
    void mutateStats();
  }

  async function downloadReport(executionId: string) {
    try {
      const filename = await api.downloadExecutionReport(executionId);
      setDownloadMessage(`Downloaded ${filename}`);
    } catch (cause) {
      setDownloadMessage(cause instanceof Error ? cause.message : "Report download failed.");
    }
  }

  async function copyExecutionId(executionId: string) {
    await navigator.clipboard?.writeText(executionId);
    setCopiedId(executionId);
    window.setTimeout(() => setCopiedId(null), 1_500);
  }

  return (
    <div className={`${styles.commandCenter} ${presentationMode ? styles.presentationMode : ""}`}>
      <div className={styles.hero}>
        <p className={styles.eyebrow}><Crosshair size={14} aria-hidden="true" /> Sentivra / defense lab</p>
        <PageHeader title="Cyber Defense Lab" description="Watch Sentivra stop an attack, live."
           actions={<div className={styles.headerActions}><Button variant="outline" onClick={startPresentation} aria-pressed={presentationMode}>{presentationMode ? <Minimize2 /> : <Maximize2 />}{presentationMode ? "Exit presentation" : "Presentation mode"}</Button><Button variant="outline" onClick={() => setSelectedRun(null)} disabled={controlsBusy || !selectedRun}><RotateCcw /> Reset visualization</Button></div>} />
      </div>

      <div role="note" className={styles.safetyNotice}><ShieldCheck size={20} aria-hidden="true" /><span className={styles.badge} data-tone="cyan">Simulation</span><p>{SIMULATION_NOTICE}</p></div>

      <ol className={styles.story} aria-label="Simulation progress">
        {story.map((step, index) => <li key={step.label} data-complete={step.done || undefined} data-current={!step.done && (index === 0 || story[index - 1].done) ? true : undefined}><span className={styles.storyNumber}>{step.done ? "✓" : index + 1}</span><span>{step.label}</span></li>)}
      </ol>
      {presentationCaption ? <div className={styles.presentationCaption} role="status" aria-live="polite">{presentationCaption}</div> : null}

      <div className={styles.workspace}>
        <Card className={styles.topologyCard}>
          <CardHeader><div className={styles.sectionHeading}><h2><Activity size={17} aria-hidden="true" /> Attack theater</h2><span className={styles.badge} data-tone="cyan">LIVE REPLAY</span></div><p className={styles.muted}>{runScenario ? `Showing: ${runScenario.name}` : "Five steps. One synthetic request. A real detector result."}</p></CardHeader>
          <CardContent><Topology run={run} scenarios={scenarios.data ?? []} busy={busy} /></CardContent>
        </Card>

        <Card className={styles.launcher}>
          <CardHeader><p className={styles.eyebrow}>Scenario launcher</p><h2 className={styles.sectionTitle}>Choose the next simulation</h2><p className={styles.muted}>Fixtures and detector allowlists are owned by the server.</p></CardHeader>
          <CardContent className={styles.launcherBody}>
            {scenarios.error ? <div className={styles.errorWithRetry}><ErrorState error={scenarios.error} /><Button variant="outline" disabled={scenarios.isValidating} onClick={() => void scenarios.mutate()}>Retry scenarios</Button></div> : null}
            {!scenarios.data && !scenarios.error ? <LoadingBlock label="Loading trusted scenarios…" /> : null}
            {scenarios.data?.length === 0 ? <EmptyState title="No scenarios available">The server has no registered simulation fixtures.</EmptyState> : null}
             {scenarios.data?.length ? <>
               <div className={styles.scenarioCards} role="radiogroup" aria-label="Choose a test scenario">
                  {scenarios.data.filter((item) => ["sqli-indicator", "benign-control", "ransomware-replay", "ransomware-attack-chain"].includes(item.scenario_id)).map((item) => <button key={item.scenario_id} type="button" role="radio" aria-checked={selected === item.scenario_id} className={styles.scenarioCard} data-selected={selected === item.scenario_id} onClick={() => setSelectedId(item.scenario_id)} disabled={controlsBusy || pending}><strong>{item.scenario_id === "sqli-indicator" ? "SQL injection attack" : item.scenario_id === "benign-control" ? "Normal request (control)" : item.scenario_id === "ransomware-attack-chain" ? "Ransomware attack chain" : "MLRan ransomware replay"}</strong><span>{item.description}</span><small>{item.detector} · {item.detector_availability.status}</small></button>)}
                </div>
                <Button size="lg" className={styles.launchButton} disabled={controlsBusy || pending || !scenario} onClick={() => void execute()}><Play aria-hidden="true" />{busy ? "Running simulation…" : "Run simulation"}</Button>
                <button type="button" className={styles.textLink} disabled={controlsBusy || pending} onClick={() => void runBothScenarios()}>Run both scenarios for comparison →</button>
                <div className={styles.ransomwareLabPanel}><div className={styles.sectionHeading}><strong>Host-safe ransomware lab</strong><span className={styles.badge} data-tone={ransomwareHealth.data?.status === "Available" ? "green" : "amber"}>{ransomwareHealth.data?.status ?? "Checking"}</span></div><p className={styles.muted}>MLRan held-out behavioral replay only. No files, registry, processes, network calls, or host-device operations are performed.</p><div className={styles.launchActions}><Button variant="outline" size="sm" disabled={controlsBusy || pending || !ransomwareScenario} onClick={() => void execute(false, "ransomware-replay")}>Run ransomware replay</Button><Button variant="outline" size="sm" disabled={controlsBusy || pending || !ransomwareChainScenario} onClick={() => void execute(false, "ransomware-attack-chain")}>Run attack-chain replay</Button></div></div>
                <p className={styles.muted}>Sentivra analyzes trusted local test scenarios. No real application or network target is contacted.</p>
             </> : null}
             <p className={styles.launchHint} role="status">{busy ? "Waiting for the backend result. The visualization begins only after a response." : run?.status === "RUNNING" ? "This execution is still running. Its status is refreshed with read-only requests." : "Each launch records one execution. Reset clears only the displayed result; it never cancels or deletes a run."}</p>
            {error ? <div className={styles.requestError}><ErrorState error={error} /><p>The result is unconfirmed. Retry reuses the same request key to recover this execution.</p><code>{attempt?.requestKey}</code><Button variant="outline" disabled={busy} onClick={() => void execute(true)}><RefreshCw /> Retry same request</Button><Button variant="ghost" disabled={busy} onClick={dismissRequest}>Dismiss pending request</Button><p>Dismissing only clears local request state; backend work is not cancelled.</p></div> : null}
          </CardContent>
        </Card>
      </div>

      {selectedRun && detail.error ? <div className={styles.errorWithRetry}><ErrorState error={detail.error} /><p className={styles.muted}>Showing the last received snapshot for this execution.</p><Button variant="outline" disabled={detail.isValidating || busy} onClick={() => void detail.mutate()}>Retry execution details</Button></div> : null}
      {comparisonError ? <ErrorState error={comparisonError} /> : null}
      {comparisonRuns.length === 2 ? <ComparisonPanel runs={comparisonRuns} scenarios={scenarios.data ?? []} selectedExecutionId={selectedRun?.execution_id} presentationMode={presentationMode} onSelectExecution={setSelectedRun} /> : null}
      {run ? <RunDetails run={run} scenarios={scenarios.data ?? []} onDownload={() => void downloadReport(run.execution_id)} /> : <EmptyState title={busy ? "Analyzing the selected scenario" : "Ready to run a test"}>{busy ? "The result will appear when the backend returns it." : "Choose a scenario above to see threat sent, detected, policy decision, and report."}</EmptyState>}
      <section className={styles.standards} aria-label="Standards in play"><h2>Standards in play</h2><div>{VERIFIED_STANDARDS.map(([name, identifier, href]) => <a key={identifier} href={href} target="_blank" rel="noreferrer">{name} <span>{identifier}</span></a>)}</div></section>

      <Card className={styles.historySection}>
        <CardHeader><div className={styles.sectionHeading}><div><h2><History size={17} aria-hidden="true" /> Execution history</h2><p className={styles.muted}>Your saved test runs, with a report for every result.</p></div><div className={styles.headerActions}><Button variant="outline" size="sm" disabled={controlsBusy} onClick={() => void api.downloadFilteredReport(historyFilter === "all" ? undefined : historyFilter === "block" ? "BLOCKED" : "ALLOWED")}><Download /> Download filtered history</Button><Button variant="ghost" size="sm" disabled={controlsBusy || history.isValidating} onClick={() => { void history.mutate(); void stats.mutate(); }}><RefreshCw /> Refresh</Button></div></div></CardHeader>
        <CardContent>
          <div className={styles.historyToolbar} role="group" aria-label="History filters">{(["all", "block", "allow"] as const).map((filter) => <button key={filter} type="button" aria-pressed={historyFilter === filter} onClick={() => setHistoryFilter(filter)}>{filter === "all" ? "All" : filter === "block" ? "Blocked" : "Allowed"}</button>)}{downloadMessage ? <span role="status">{downloadMessage}</span> : null}</div>
          {history.error ? <div className={styles.errorWithRetry}><ErrorState error={history.error} /><Button variant="outline" disabled={history.isValidating} onClick={() => void history.mutate()}>Retry history</Button></div> : null}
          {history.isLoading ? <LoadingBlock label="Loading execution history…" /> : null}
          {!history.isLoading && !history.error && !rows.length ? <EmptyState title={offset ? "No more executions" : "No simulations yet"}>{offset ? "Return to the previous page or refresh history." : "Your first recorded simulation will appear here."}</EmptyState> : null}
           {rows.length ? <div className={styles.historyList}><div className={styles.historyTableHeader}><span>Time</span><span>Scenario</span><span>Verdict</span><span>Duration</span><span>Report</span></div>{rows.map((item) => {
             const outcome = runOutcome(item);
             return <div key={item.execution_id} className={styles.historyRow} data-selected={run?.execution_id === item.execution_id}><div role="button" tabIndex={0} aria-pressed={run?.execution_id === item.execution_id} className={styles.historySelect} onClick={() => setSelectedRun(item)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelectedRun(item); } }}><span className={styles.historyIdentity}><time dateTime={item.started_at} title={formatTimestamp(item.started_at)}>{relativeTime(item.started_at)}</time><small>{formatTimestamp(item.started_at)}</small></span><span className={styles.historyScenario}>{item.scenario?.name ?? scenarios.data?.find((entry) => entry.scenario_id === item.scenario_id)?.name ?? item.scenario_id}<small><code>{shortId(item.execution_id)}</code><button type="button" className={styles.copyButton} aria-label={`Copy execution ID ${shortId(item.execution_id)}`} onClick={(event) => { event.stopPropagation(); void copyExecutionId(item.execution_id); }}>{copiedId === item.execution_id ? <Check /> : <Copy />}</button></small></span><span className={styles.historyStatus}><span className={styles.badge} data-tone={outcome.tone}>{outcome.label}</span><small>{detectionLabel(item.detection_state)}</small></span><span className={styles.historyDuration}>{formatDuration(item.duration_ms ?? null)}</span></div><button type="button" className={styles.reportButton} aria-label={`Download report for ${shortId(item.execution_id)}`} onClick={() => void downloadReport(item.execution_id)}><Download /></button></div>;
           })}</div> : null}
          <div className={styles.pagination}><span>{rows.length ? `${offset + 1}–${offset + rows.length}` : "0"} shown · Page {Math.floor(offset / HISTORY_PAGE_SIZE) + 1}</span><div><Button variant="outline" size="sm" disabled={busy || history.isLoading || offset === 0} onClick={() => setOffset(Math.max(0, offset - HISTORY_PAGE_SIZE))}><ArrowLeft /> Previous</Button><Button variant="outline" size="sm" disabled={busy || history.isLoading || Boolean(history.error) || (history.data?.length ?? 0) <= HISTORY_PAGE_SIZE} onClick={() => setOffset(offset + HISTORY_PAGE_SIZE)}>Next <ArrowRight /></Button></div></div>
        </CardContent>
      </Card>
      <details className={styles.technicalDetails}><summary>Simulation totals and technical details</summary><div className={styles.statsGrid} aria-busy={stats.isLoading}>{[
        { label: "Total runs", value: counts?.runs, detail: counts ? `${counts.completed} completed` : "Loading" },
        { label: "Detected", value: counts?.detected, detail: "Runs with a finding" },
        { label: "Simulated blocks", value: counts?.blocks, detail: "Blocked decisions in the simulation ledger" },
        { label: "Failed or partial", value: counts ? counts.partial + counts.failed : undefined, detail: counts ? `${counts.partial} partial · ${counts.failed} failed` : "Loading" },
      ].map((metric) => <div key={metric.label} className={styles.statCard}><p className={styles.metricLabel}>{metric.label}</p><p className={styles.metricValue}>{metric.value?.toLocaleString() ?? "—"}</p><p className={styles.metricDetail}>{metric.detail}</p></div>)}</div></details>
    </div>
  );
}
