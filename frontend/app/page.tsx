"use client";

import Link from "next/link";
import { useState } from "react";
import type { ReactNode } from "react";
import { ShieldAlert, ShieldCheck } from "lucide-react";

import { ChartCard } from "@/components/charts/chart-card";
import { TimelineColumns } from "@/components/charts/charts";
import { AlertsTable } from "@/components/sentivra/alerts-table";
import { SourceTypeBadge } from "@/components/sentivra/badges";
import { EmptyState, ErrorState, LoadingBlock, PageHeader } from "@/components/sentivra/states";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useApi } from "@/hooks/use-api";
import { integer } from "@/lib/format";
import { cn } from "@/lib/utils";
import { type AlertListItem, type Health, type Metrics, type SourceType } from "@/types/api";

const WINDOWS = [
  { hours: 24, label: "Last 24 hours" },
  { hours: 24 * 7, label: "Last 7 days" },
  { hours: 24 * 30, label: "Last 30 days" },
];

function bucketLabel(start: string, index: number, bucket: "hour" | "day") {
  const d = new Date(start);
  if (bucket === "hour") {
    d.setUTCHours(d.getUTCHours() + index + 1);
    return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }
  d.setUTCDate(d.getUTCDate() + index + 1);
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function StatTile({ label, value, hint }: { label: string; value: string; hint?: ReactNode }) {
  return (
    <Card size="sm">
      <CardContent className="space-y-1">
        <p className="text-sm text-muted-foreground">{label}</p>
        <p className="text-2xl font-semibold">{value}</p>
        {hint ? <p className="text-[13px] text-muted-foreground">{hint}</p> : null}
      </CardContent>
    </Card>
  );
}

// Domains count alerts any of their detectors contributed to. A zero means
// the capability is implemented but no alert was raised in the selected window.
const DOMAINS: { label: string; domain: "network" | "files" | "endpoint" | "urls" | "prompts" | "sql"; href: string }[] = [
  { label: "Network anomalies", domain: "network", href: "/network" },
  { label: "Malicious files", domain: "files", href: "/files" },
  { label: "Suspicious URLs", domain: "urls", href: "/messages" },
  { label: "Prompt attacks", domain: "prompts", href: "/prompt-security" },
  { label: "SQL injection", domain: "sql", href: "/messages" },
  { label: "Endpoint anomalies", domain: "endpoint", href: "/endpoint" },
];

export default function OverviewPage() {
  const [windowHours, setWindowHours] = useState(24);
  const metrics = useApi<Metrics>(`/api/v1/metrics?window_hours=${windowHours}`);
  const alerts = useApi<AlertListItem[]>("/api/v1/alerts?limit=8");
  const health = useApi<Health>("/api/v1/health");

  const m = metrics.data;
  const engines = health.data ? Object.values(health.data.engines) : [];
  const available = engines.filter((e) => e.status === "Available").length;

  return (
    <>
      <PageHeader title="Overview" description="See what Sentivra has analyzed, what needs attention, and whether the detection layer is ready." />

      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Time window">
        {WINDOWS.map((w) => (
          <button
            key={w.hours}
            type="button"
            onClick={() => setWindowHours(w.hours)}
            aria-pressed={windowHours === w.hours}
            className={cn(
              "rounded-md border px-3 py-1 text-sm",
              windowHours === w.hours ? "border-foreground/30 bg-muted font-medium" : "text-muted-foreground hover:bg-muted",
            )}
          >
            {w.label}
          </button>
        ))}
      </div>

      {metrics.error ? <ErrorState error={metrics.error} /> : null}
      {!m && !metrics.error ? <LoadingBlock /> : null}

      {m ? (
        <div className={cn("space-y-6 transition-opacity", metrics.isValidating && "opacity-70")}>
          <Card className="border-l-4 border-l-status-good">
            <CardContent className="flex flex-wrap items-center justify-between gap-4 py-6">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Threat status · {WINDOWS.find((item) => item.hours === windowHours)?.label}</p>
                <h2 className="mt-1 flex items-center gap-3 text-2xl font-semibold tracking-tight">{m.window.open_alerts ? <ShieldAlert className="size-8 text-status-critical" aria-hidden /> : <ShieldCheck className="size-8 text-status-good" aria-hidden />}{m.window.open_alerts ? `${integer(m.window.open_alerts)} threat${m.window.open_alerts === 1 ? "" : "s"} need attention` : "All clear in this window"}</h2>
                <p className="mt-2 text-sm text-muted-foreground">{m.window.open_alerts ? "Review the open alerts below to understand the evidence." : "Sentivra has no open operational alerts in the selected period."}</p>
              </div>
              <Link href="/demo" className="inline-flex h-9 items-center justify-center rounded-lg bg-primary px-3 text-sm font-medium text-primary-foreground hover:bg-primary/80">Run a demo scenario</Link>
            </CardContent>
          </Card>
          <div className="grid gap-4 md:grid-cols-3">
            <StatTile label="Open alerts" value={integer(m.window.open_alerts)} hint={`${integer(m.window.alerts)} raised in window`} />
            <StatTile label="Events analyzed" value={integer(m.totals.events)} hint="operational events, all time" />
            <StatTile label="Detectors ready" value={health.data ? `${available} of ${engines.length}` : "…"} hint={<Link href="/integrations" className="underline underline-offset-4">See what is missing</Link>} />
          </div>

          <Card>
            <CardHeader><CardTitle>Security score</CardTitle><CardDescription>Available after Sentivra has analyzed at least one operational event.</CardDescription></CardHeader>
            <CardContent className="flex items-center justify-between gap-4">
              <p className="text-4xl font-semibold tracking-tight">{m.totals.events > 0 ? m.security_score.value : "No data yet"}</p>
              <details className="max-w-md text-sm text-muted-foreground"><summary className="cursor-pointer font-medium text-foreground">How is this calculated?</summary><p className="mt-2">{m.security_score.formula}. {m.security_score.note}</p></details>
            </CardContent>
          </Card>

          <p className="rounded-lg border border-dashed px-4 py-3 text-sm text-muted-foreground">Simulation executions are demonstrations and stay out of these operational incident totals. Open <Link href="/cyber-defense" className="font-medium text-foreground underline underline-offset-4">Cyber Defense Lab</Link> to inspect them separately.</p>

          <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
            <span>Alerts by input:</span>
            {(["LIVE", "SIMULATED", "DEMO_DATA"] as SourceType[]).map((t) => (
              <span key={t} className="flex items-center gap-1.5">
                <SourceTypeBadge sourceType={t} /> <span className="tabular text-foreground">{integer(m.window.by_source_type[t] ?? 0)}</span>
              </span>
            ))}
          </div>

          {m.window.alerts === 0 ? (
            <EmptyState title="No alerts in this window">
              Run the scenarios in <Link href="/demo" className="underline underline-offset-4">Demo mode</Link> to see the
              pipeline end to end. Demo results are labeled as demo or simulated data everywhere they appear.
            </EmptyState>
          ) : (
            <>
              <ChartCard
                title="Threats over time"
                description={`Alerts per ${m.window.timeline.bucket}`}
                rows={m.window.timeline.counts.map((value, i) => ({ label: bucketLabel(m.window.timeline.start, i, m.window.timeline.bucket), value }))}
                valueLabel="Alerts"
              >
                <TimelineColumns data={m.window.timeline.counts.map((value, i) => ({ label: bucketLabel(m.window.timeline.start, i, m.window.timeline.bucket), value }))} />
              </ChartCard>
            </>
          )}

          <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-6">
            {DOMAINS.map((d) => (
              <Link key={d.label} href={d.href} className="block">
                <Card size="sm" className="h-full hover:ring-foreground/25">
                  <CardContent className="space-y-1">
                    <p className="text-sm text-muted-foreground">{d.label}</p>
                    <p className="text-2xl font-semibold">{integer(m.window.by_domain[d.domain] ?? 0)}</p>
                    <p className="text-[13px] text-muted-foreground">implemented</p>
                  </CardContent>
                </Card>
              </Link>
            ))}
          </div>
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Recent threats</CardTitle>
          <CardDescription>
            Latest alerts. <Link href="/threats" className="underline underline-offset-4">All threats</Link>
          </CardDescription>
        </CardHeader>
        <CardContent>
          {alerts.error ? <ErrorState error={alerts.error} /> : null}
          {alerts.data && alerts.data.length === 0 ? <EmptyState title="No alerts yet" /> : null}
          {alerts.data && alerts.data.length > 0 ? <AlertsTable alerts={alerts.data} /> : null}
        </CardContent>
      </Card>
    </>
  );
}
