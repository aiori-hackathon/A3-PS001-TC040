"use client";

import { StatusPill } from "@/components/sentivra/badges";
import { ErrorState, LoadingBlock, PageHeader } from "@/components/sentivra/states";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useApi } from "@/hooks/use-api";
import { humanize, metricLabel, significant } from "@/lib/format";
import type { ModelEntry } from "@/types/api";

const DETECTION_CONTEXT: Record<string, string> = {
  "endpoint/fleet_baseline": "Endpoint detection is implemented with baseline-backed rules; this is the learned fleet baseline artifact.",
  "malware/ember": "File detection is implemented with metadata, YARA, and optional ClamAV; the EMBER ML artifact is optional and not trained in this checkout.",
  "network/autoencoder": "Network detection uses this trained model together with behavior rules and other model layers.",
  "network/classifier": "Network detection uses this trained model together with behavior rules and other model layers.",
  "network/isolation_forest": "Network detection uses this trained model together with behavior rules and other model layers.",
  "phishing/url_model": "URL detection is implemented with bounded local heuristics; this optional trained URL model is not present.",
  "prompt/prompt_injection": "Prompt-injection detection is implemented with bounded heuristic and Unicode-obfuscation rules; this optional trained model is not present.",
  "sql_injection/classifier": "SQL/NoSQL detection is implemented with the SQL rule pack and lexical analysis; this optional classifier is not trained.",
};

function Metrics({ metrics }: { metrics: Record<string, number> }) {
  const entries = Object.entries(metrics);
  if (!entries.length) return <p className="text-sm text-muted-foreground">No headline metrics recorded.</p>;
  return (
    <Table>
      <TableHeader><TableRow><TableHead>Metric (test split)</TableHead><TableHead className="text-right">Value</TableHead></TableRow></TableHeader>
      <TableBody>
        {entries.map(([k, v]) => (
          <TableRow key={k}>
            <TableCell>{metricLabel(k)}</TableCell>
            <TableCell className="text-right tabular">{Number.isInteger(v) ? v : v.toFixed(3)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export default function ModelsPage() {
  const { data, error } = useApi<ModelEntry[]>("/api/v1/models");
  return (
    <>
      <PageHeader
        title="Models"
        description="The model registry reports trained artifacts and their provenance. Detection capabilities can also be implemented by rules and heuristics, so an untrained optional model does not mean that the corresponding detector is unavailable."
      />
      <Card>
        <CardContent className="text-sm text-muted-foreground">
          <strong className="text-foreground">How to read this page:</strong> <span className="text-foreground">Available</span> means a verified model artifact is loaded. <span className="text-foreground">Not trained</span> means that optional model is absent; open the detector-specific dashboard page to use the implemented rule or heuristic coverage.
        </CardContent>
      </Card>
      {error ? <ErrorState error={error} /> : null}
      {!data && !error ? <LoadingBlock /> : null}
      <div className="grid gap-4 lg:grid-cols-2">
        {data?.map((entry) => {
          const m = entry.metadata;
          const context = DETECTION_CONTEXT[`${entry.domain}/${entry.name}`];
          return (
            <Card key={`${entry.domain}/${entry.name}`}>
              <CardHeader>
                <CardTitle className="flex flex-wrap items-center gap-2">
                  {humanize(entry.domain)} / {humanize(entry.name)}
                  <StatusPill status={entry.trained ? "Available" : "Not trained"} />
                </CardTitle>
                <CardDescription className="font-mono text-[13px]">{entry.directory}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                {context ? <p className="rounded-md border border-dashed p-2 text-muted-foreground">{context}</p> : null}
                {!m ? (
                  <p className="text-muted-foreground">{entry.reason_untrained}</p>
                ) : (
                  <>
                    <dl className="grid grid-cols-[9rem_1fr] gap-y-1">
                      <dt className="text-muted-foreground">Version</dt><dd>{m.version}</dd>
                      <dt className="text-muted-foreground">Format</dt><dd>{m.artifact_format}</dd>
                      <dt className="text-muted-foreground">Trained on</dt><dd>{m.training_dataset}</dd>
                      <dt className="text-muted-foreground">Split</dt><dd>{m.split_method ?? "—"}</dd>
                      <dt className="text-muted-foreground">Evaluated</dt><dd>{m.evaluation_date ?? "—"}</dd>
                      <dt className="text-muted-foreground">Threshold</dt>
                      <dd>{m.threshold != null ? significant(m.threshold) : "—"}{m.threshold_policy ? <span className="block text-[13px] text-muted-foreground">{m.threshold_policy}</span> : null}</dd>
                      <dt className="text-muted-foreground">SHA-256</dt><dd className="font-mono text-[13px] break-all">{m.sha256}</dd>
                    </dl>
                    <Metrics metrics={m.evaluation_metrics} />
                    {m.limitations.length ? (
                      <div>
                        <p className="mb-1 font-medium">Limitations</p>
                        <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
                          {m.limitations.map((l) => <li key={l}>{l}</li>)}
                        </ul>
                      </div>
                    ) : null}
                  </>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </>
  );
}
