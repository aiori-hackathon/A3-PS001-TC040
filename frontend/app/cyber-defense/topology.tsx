"use client";

import { useId, useState } from "react";
import { Activity, Database, Gauge, GitBranch, LockKeyhole, Server, Shield, Square } from "lucide-react";

import { useReducedMotion } from "@/hooks/use-reduced-motion";
import { detectionLabel, displayedScenario, runOutcome, topologyRoute } from "@/lib/simulation";
import type { SimulationRun, SimulationScenario } from "@/types/api";
import styles from "./command-center.module.css";

const nodes = [
  { id: "source", label: "Simulated source", x: 90, y: 90, icon: Activity, help: "A trusted, server-owned fixture represents the event. No real traffic is generated." },
  { id: "gateway", label: "Request gateway", x: 270, y: 90, icon: GitBranch, help: "Only registered scenario IDs and simulation mode are accepted by the authenticated API." },
  { id: "engine", label: "Sentivra engine", x: 450, y: 90, icon: Server, help: "The existing local analysis pipeline invokes the scenario's detector allowlist." },
  { id: "detector", label: "Local detector", x: 630, y: 90, icon: Gauge, help: "Actual detector results include clean, suspicious, partial, and failed analyses." },
  { id: "risk", label: "Risk assessment", x: 630, y: 260, icon: Shield, help: "The existing risk engine aggregates detector findings. Missing analysis is not a safe result." },
  { id: "enforce", label: "Simulation policy", x: 450, y: 260, icon: LockKeyhole, help: "A decision-only adapter records a simulated block, allow, review, or unavailable result." },
  { id: "resource", label: "Protected resource", x: 270, y: 260, icon: Square, help: "A conceptual destination, reached only by an explicit completed simulated allow." },
  { id: "store", label: "Event & alert store", x: 90, y: 260, icon: Database, help: "The stored execution links its event and alert when persistence succeeds. Storage is separate from enforcement." },
] as const;

type NodeId = typeof nodes[number]["id"];

export function Topology({ run, scenarios, busy }: { run: SimulationRun | null; scenarios: SimulationScenario[]; busy: boolean }) {
  const [selected, setSelected] = useState<NodeId>("engine");
  const reducedMotion = useReducedMotion();
  const id = useId();
  const outcome = runOutcome(run);
  const route = topologyRoute(outcome.kind);
  const metadata = displayedScenario(run, scenarios);
  const selectedNode = nodes.find((node) => node.id === selected)!;
  const selectedDetail = !run ? "Run a scenario or select a stored execution to inspect its recorded details." : ({
    source: `${metadata?.name} · SIMULATED EVENT`,
    gateway: `Scenario ID: ${run.scenario_id} · version ${run.scenario_version}`,
    engine: `Execution status: ${run.status}`,
    detector: `${metadata?.detectors.join(", ") || "No detector recorded"} · ${detectionLabel(run.detection_state)}`,
    risk: run.risk_assessment ? `${run.risk_assessment.risk_score}/100 · ${run.risk_assessment.severity} · ${run.risk_assessment.classification}` : "No risk assessment was recorded.",
    enforce: `${outcome.label}. ${run.enforcement?.reason ?? outcome.explanation}`,
    resource: outcome.kind === "allow" ? "Reached by the synthetic event. No external application was contacted." : "Not reached by the visualization. No real resource was blocked or contacted.",
    store: `Execution: ${run.execution_id}. Event: ${run.event_id ?? "not persisted"}. Alert: ${run.alert_id ?? "none"}.`,
  } satisfies Record<NodeId, string>)[selected];

  return (
    <div className={styles.topology} data-tone={outcome.tone}>
      <div className={styles.canvasHeading}>
        <span><span className={styles.statusDot} /> Conceptual event path</span>
        <span>{busy ? "Awaiting backend response" : outcome.label}</span>
      </div>
      <div className={styles.canvasScroll}>
        <svg viewBox="0 0 720 360" className={styles.canvas} role="listbox" aria-label="Interactive simulation topology: eight conceptual nodes" aria-describedby={`${id}-topology-help`}>
          <title>Simulation topology</title>
          <desc>Select any node with Enter, Space, or a pointer to inspect its role. Only a completed allow reaches the resource.</desc>
          <defs><pattern id={`${id}-grid`} width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r="1" fill="#294252" /></pattern></defs>
          <rect width="720" height="360" fill={`url(#${id}-grid)`} opacity=".45" />
          <g fill="none" stroke="#3b5265" strokeWidth="2"><path d="M90 90 H630 V260 H270" /><path d="M450 260 V335 H90 V260" strokeDasharray="4 6" /></g>
          <text x="260" y="353" textAnchor="middle" className={styles.wireLabel}>execution record · independent of policy</text>
          {route ? <path d={route.path} className={styles.activePath} fill="none" strokeWidth="2.5" /> : null}
          {route && !reducedMotion ? <circle key={run?.execution_id} r="5" className={styles.particle} style={{ offsetPath: `path('${route.path}')` }} aria-hidden="true" /> : null}
          {nodes.map(({ id: nodeId, label, x, y, icon: Icon }, index) => {
            const reached = route?.nodes.includes(nodeId) || (nodeId === "store" && Boolean(run));
            return <g key={nodeId} role="option" tabIndex={0} aria-label={label} aria-selected={selected === nodeId} aria-controls={`${id}-details`} className={styles.node} data-selected={selected === nodeId} data-reached={reached || undefined} data-endpoint={route?.endpoint === nodeId || undefined} onClick={() => setSelected(nodeId)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelected(nodeId); } }}>
              <rect className={styles.nodeFocus} x={x - 76} y={y - 49} width="152" height="98" rx="15" />
              <rect className={styles.nodeFrame} x={x - 70} y={y - 43} width="140" height="86" rx="11" />
              <text x={x - 57} y={y - 24} className={styles.nodeNumber}>{String(index + 1).padStart(2, "0")}</text>
              <Icon x={x - 11} y={y - 25} width="22" height="22" strokeWidth="1.5" aria-hidden="true" />
              <text x={x} y={y + 17} textAnchor="middle" className={styles.nodeLabel}>{label}</text>
            </g>;
          })}
        </svg>
      </div>
      <div className={styles.nodeDetails} id={`${id}-details`} aria-live="polite">
        <div className={styles.nodeDetailTitle}><selectedNode.icon size={16} aria-hidden="true" /><strong>{selectedNode.label}</strong><span>NODE INSPECTOR</span></div>
        <p>{selectedNode.help}</p>
        <p className={styles.nodeValue}>{selectedDetail}</p>
      </div>
      <div className={styles.legend} role="group" aria-label="Topology legend"><span data-tone="cyan">Analysis</span><span data-tone="red">Block</span><span data-tone="green">Allow</span><span data-tone="violet">Review</span><span data-tone="amber">Unavailable / failed</span></div>
      <p className={styles.canvasFootnote} id={`${id}-topology-help`}>A one-time illustration of the returned result, not live network traffic or measured stage timing. Tab to explore nodes.</p>
    </div>
  );
}
