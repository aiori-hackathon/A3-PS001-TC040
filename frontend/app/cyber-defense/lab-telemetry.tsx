"use client";

import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { streamLabTelemetry } from "@/lib/api";
import type { HostTelemetrySample, LabTelemetryEvent, LabTelemetryRun } from "@/types/api";
import styles from "./command-center.module.css";

const SOURCE_LABELS = { host: "HOST", simulated: "SIMULATED", sentivra: "SENTIVRA", mitigation: "MITIGATION" } as const;

export function useLabHostTelemetry(enabled: boolean) {
  const [samples, setSamples] = useState<HostTelemetrySample[]>([]);
  useEffect(() => {
    if (!enabled) {
      return;
    }
    const controller = new AbortController();
    let retry: ReturnType<typeof setTimeout> | undefined;
    let active = true;
    const connect = async () => {
      try {
        await streamLabTelemetry((sample) => {
          if (!active) return;
          setSamples((current) => [...current, sample].slice(-900));
        }, controller.signal);
      } catch {
        if (active && !controller.signal.aborted) retry = setTimeout(() => void connect(), 1_000);
      }
    };
    void connect();
    return () => {
      active = false;
      controller.abort();
      if (retry) clearTimeout(retry);
    };
  }, [enabled]);
  return enabled ? samples : [];
}

function sourceBadge(source: keyof typeof SOURCE_LABELS) {
  return <span className={styles.telemetrySource} data-source={source}>{SOURCE_LABELS[source]}</span>;
}

function displayNumber(value: number | null | undefined, suffix = "") {
  return typeof value === "number" && Number.isFinite(value) ? `${value.toFixed(value >= 100 ? 0 : 1)}${suffix}` : "n/a";
}

function bytes(value: number | null | undefined) {
  if (typeof value !== "number" || !Number.isFinite(value)) return "n/a";
  if (value < 1024) return `${value.toFixed(0)} B/s`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB/s`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB/s`;
  return `${(value / 1024 ** 3).toFixed(1)} GB/s`;
}

function Sparkline({ values, color }: { values: (number | null)[]; color: string }) {
  const valid = values.filter((value): value is number => typeof value === "number" && Number.isFinite(value));
  if (!valid.length) return <div className={styles.telemetryNoData}>n/a</div>;
  const max = Math.max(...valid, 1);
  const min = Math.min(...valid, 0);
  const points = values.map((value, index) => {
    const x = values.length <= 1 ? 0 : (index / (values.length - 1)) * 120;
    const y = typeof value === "number" ? 28 - ((value - min) / Math.max(max - min, 1)) * 24 : 28;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  return <svg className={styles.telemetrySparkline} viewBox="0 0 120 32" role="img" aria-label="Recent aggregate telemetry trend"><polyline points={points} fill="none" stroke={color} strokeWidth="2" vectorEffect="non-scaling-stroke" /></svg>;
}

function TelemetryMetric({ label, value, values, color }: { label: string; value: string; values: (number | null)[]; color: string }) {
  return <div className={styles.telemetryMetric}><div className={styles.telemetryMetricHeader}><span>{label}</span>{sourceBadge("host")}</div><strong>{value}</strong><Sparkline values={values} color={color} /></div>;
}

export function HostTelemetryPanel({ enabled, samples }: { enabled: boolean; samples: HostTelemetrySample[] }) {
  if (!enabled) return null;
  const latest = samples.at(-1);
  const diskValues = samples.map((sample) => sample.disk_read_bytes_per_second == null && sample.disk_write_bytes_per_second == null ? null : (sample.disk_read_bytes_per_second ?? 0) + (sample.disk_write_bytes_per_second ?? 0));
  const networkValues = samples.map((sample) => sample.network_sent_bytes_per_second == null && sample.network_received_bytes_per_second == null ? null : (sample.network_sent_bytes_per_second ?? 0) + (sample.network_received_bytes_per_second ?? 0));
  return <section className={styles.hostTelemetry} aria-label="Live host telemetry">
    <div className={styles.telemetrySectionHeader}><div><p className={styles.eyebrow}>Host telemetry</p><h2>Aggregate system view</h2></div><div className={styles.telemetryHeaderBadges}>{sourceBadge("host")}<span className={styles.telemetryReadOnly}>live, read-only</span><span className={styles.modeUnsupported}>Mode B: Not enabled</span></div></div>
    <p className={styles.muted}>Only aggregate counters are sampled while this Lab page is open. No process names, paths, users, hostnames, IPs, or contents are collected.</p>
    <div className={styles.telemetryGrid} aria-live="polite">
      <TelemetryMetric label="CPU" value={displayNumber(latest?.cpu_percent, "%")} values={samples.map((sample) => sample.cpu_percent)} color="#70d0e3" />
      <TelemetryMetric label="Memory" value={displayNumber(latest?.memory_percent, "%")} values={samples.map((sample) => sample.memory_percent)} color="#bba5f1" />
      <TelemetryMetric label="Disk I/O" value={bytes(latest && latest.disk_read_bytes_per_second == null && latest.disk_write_bytes_per_second == null ? null : latest ? (latest.disk_read_bytes_per_second ?? 0) + (latest.disk_write_bytes_per_second ?? 0) : null)} values={diskValues} color="#eac16c" />
      <TelemetryMetric label="Network I/O" value={bytes(latest && latest.network_sent_bytes_per_second == null && latest.network_received_bytes_per_second == null ? null : latest ? (latest.network_sent_bytes_per_second ?? 0) + (latest.network_received_bytes_per_second ?? 0) : null)} values={networkValues} color="#8dd8ae" />
      <TelemetryMetric label="Processes" value={latest?.process_count == null ? "n/a" : latest.process_count.toLocaleString()} values={samples.map((sample) => sample.process_count)} color="#ef949c" />
    </div>
    <div className={styles.telemetryFootline}><span>Threads: {latest?.thread_count == null ? "n/a" : latest.thread_count.toLocaleString()} {sourceBadge("host")}</span><span>Samples held in memory: {samples.length}</span><span>{latest ? new Date(latest.timestamp).toLocaleTimeString() : "Waiting for first sample…"}</span></div>
  </section>;
}

function stageDone(events: LabTelemetryEvent[], types: readonly string[]) {
  return events.some((event) => types.includes(event.type));
}

function metric(label: string, value: string, source: keyof typeof SOURCE_LABELS) {
  return <div className={styles.scenarioMetric}><span>{label}</span><strong>{value}</strong>{sourceBadge(source)}</div>;
}

export function ScenarioTelemetryStrip({ run, onDownload }: { run: LabTelemetryRun | null; onDownload: (format: "json" | "zip" | "html") => Promise<void> }) {
  const [downloadError, setDownloadError] = useState<string | null>(null);
  if (!run) return null;
  const events = run.timeline ?? [];
  const score = [...events].reverse().find((event) => event.type === "ransomware_score")?.payload.score;
  const stages = [
    ["Initial signal", ["scenario_started", "stage_signal"]],
    ["Detection", ["detection", "ransomware_score"]],
    ["Fusion incident", ["fusion_incident"]],
    ["Mitigation", ["mitigation_triggered", "containment_complete"]],
    ["Complete", ["scenario_ended"]],
  ] as const;
  const isRunning = run.status === "RUNNING";
  const download = async (format: "json" | "zip" | "html") => {
    try {
      setDownloadError(null);
      await onDownload(format);
    } catch (error) {
      setDownloadError(error instanceof Error ? error.message : "Telemetry download failed.");
    }
  };
  return <section className={styles.scenarioTelemetry} aria-label="Scenario telemetry" aria-live="polite">
    <div className={styles.scenarioTelemetryHeader}><div><p className={styles.eyebrow}>Pinned scenario telemetry</p><h2>{run.scenario_type}</h2><p className={styles.muted}>Scenario run {run.scenario_run_id.slice(0, 16)} · {run.mode}</p></div><div className={styles.telemetryDownloads}><Button variant="outline" size="sm" onClick={() => void download("json")}>JSON</Button><Button variant="outline" size="sm" onClick={() => void download("zip")}>CSV ZIP</Button><Button variant="outline" size="sm" onClick={() => void download("html")}>Offline HTML</Button></div></div>
    <p className={styles.telemetrySafetyNote}>Replay mode: attack telemetry is simulated; host was not touched.</p>
    <div className={styles.stageTimeline}>{stages.map(([label, types]) => <div key={label} className={styles.stageItem} data-complete={stageDone(events, types) || undefined}><span className={styles.stageDot}>{stageDone(events, types) ? "✓" : ""}</span><span>{label}</span></div>)}</div>
    <div className={styles.scenarioMetrics}>
      {metric("Ransomware score", displayNumber(score), "sentivra")}
      {metric("Time to detect", run.summary.time_to_detect_ms == null ? "n/a" : `${run.summary.time_to_detect_ms} ms`, "sentivra")}
      {metric("Time to contain", run.summary.time_to_contain_ms == null ? "n/a" : `${run.summary.time_to_contain_ms} ms`, "mitigation")}
      {metric("Samples before alert", run.summary.samples_replayed_before_alert == null ? "n/a" : String(run.summary.samples_replayed_before_alert), "simulated")}
      {metric("Final status", isRunning ? "RUNNING" : run.final_status, "sentivra")}
    </div>
    <div className={styles.telemetryEventLog}><div className={styles.sectionHeading}><h3>Ordered event log</h3><span className={styles.muted}>{events.length} events</span></div>{events.length ? <ol>{events.map((event, index) => <li key={`${event.timestamp}-${index}`}><span className={styles.telemetryEventOffset}>{event.t_offset_ms} ms</span><span className={styles.telemetryEventSource} data-source={event.source}>{SOURCE_LABELS[event.source]}</span><div><strong>{event.type.replaceAll("_", " ")}</strong><p>{event.message}</p></div></li>)}</ol> : <p className={styles.muted}>Waiting for scenario events…</p>}</div>
    {downloadError ? <p className={styles.telemetryDownloadError} role="alert">{downloadError}</p> : null}
  </section>;
}

export function telemetryForRun(run: { lab_telemetry?: LabTelemetryRun } | null) {
  return run?.lab_telemetry ?? null;
}
