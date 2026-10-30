"use client";

import { StatusPill } from "@/components/sentivra/badges";
import { ErrorState, LoadingBlock, PageHeader } from "@/components/sentivra/states";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useApi } from "@/hooks/use-api";
import type { Integration } from "@/types/api";

const GROUPS: { kind: Integration["kind"]; title: string }[] = [
  { kind: "messaging", title: "Messaging connectors" },
  { kind: "telemetry", title: "Telemetry sources" },
  { kind: "engine", title: "Detection engines" },
];

export default function IntegrationsPage() {
  const { data, error } = useApi<Integration[]>("/api/v1/integrations");
  return (
    <>
      <PageHeader
        title="Integrations"
        description="This page reports integration readiness, not just whether an endpoint exists. A connector can be implemented but still require credentials and provider setup before it can receive data."
      />
      <Card>
        <CardContent className="grid gap-3 text-sm text-muted-foreground sm:grid-cols-2 lg:grid-cols-4">
          <div><p className="font-medium text-foreground">Connected</p><p>Configured and has delivered data.</p></div>
          <div><p className="font-medium text-foreground">Available</p><p>Implemented and ready, but no data has arrived yet.</p></div>
          <div><p className="font-medium text-foreground">Not configured</p><p>Implemented, but required credentials or paths are missing.</p></div>
          <div><p className="font-medium text-foreground">Not implemented</p><p>No ingestion path exists in this build.</p></div>
          <div><p className="font-medium text-foreground">Degraded / Error</p><p>Implemented, but the engine reported a runtime or coverage problem.</p></div>
        </CardContent>
      </Card>
      {error ? <ErrorState error={error} /> : null}
      {!data && !error ? <LoadingBlock /> : null}
      <div className="grid gap-4 lg:grid-cols-3">
        {data
          ? GROUPS.map((g) => (
              <Card key={g.kind}>
                <CardHeader><CardTitle>{g.title}</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  {data.filter((i) => i.kind === g.kind).map((i) => (
                    <div key={i.name} className="space-y-1 rounded-lg border p-3 text-sm">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-medium">{i.name}</span>
                        <StatusPill status={i.status} />
                      </div>
                       <p className="text-muted-foreground">{i.detail}</p>
                       {i.kind === "messaging" && i.status === "Not configured" ? (
                         <p className="text-[13px] font-medium text-amber-700 dark:text-amber-300">
                           Connector implemented; add the listed environment variables and configure the provider webhook to activate it.
                         </p>
                       ) : null}
                      {i.engine_version ? <p className="font-mono text-[13px] text-muted-foreground">version {i.engine_version}</p> : null}
                    </div>
                  ))}
                </CardContent>
              </Card>
            ))
          : null}
      </div>
    </>
  );
}
