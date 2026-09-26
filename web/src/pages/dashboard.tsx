import { useCallback, useEffect, useRef, useState } from "react"
import { toast } from "sonner"

import { CoveragePanel } from "@/components/mirage/coverage-panel"
import { FlashOverlay } from "@/components/mirage/flash-overlay"
import { HostsPanel } from "@/components/mirage/hosts-panel"
import { IncidentCard } from "@/components/mirage/incident-card"
import { RegistryTable } from "@/components/mirage/registry-table"
import { SiteHeader } from "@/components/mirage/site-header"
import { StatusBar } from "@/components/mirage/status-bar"
import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import LatticeLoader from "@/components/ui/lattice-loader"
import { useMirage } from "@/hooks/use-mirage"
import { ACTION_LABEL, incidentTitle } from "@/lib/format"

export function DashboardPage() {
  const [pulse, setPulse] = useState(0)
  const pendingToast = useRef<string | null>(null)
  const { state, error, refresh, offset } = useMirage({
    onIncident: (event) => {
      if (event.severity === "HIGH") {
        setPulse((value) => value + 1)
        pendingToast.current = event.id
      }
    },
    onAlert: (event) => toast.warning(event.title, { description: event.detail || undefined }),
  })
  const onChanged = useCallback(() => void refresh(), [refresh])

  // Name the new HIGH incident once its details have arrived.
  useEffect(() => {
    if (!state || !pendingToast.current) return
    const incident = state.incidents.find((item) => item.id === pendingToast.current)
    if (!incident) return
    pendingToast.current = null
    toast.error(`HIGH · ${incidentTitle(incident)}`, { description: ACTION_LABEL[incident.action]?.text })
  }, [state])

  useEffect(() => {
    const high = state?.incidents.filter((item) => item.status !== "closed" && item.severity === "HIGH").length ?? 0
    document.title = high ? `(${high}) Mirage Engine` : "Mirage Engine"
  }, [state])

  if (!state) return <BootScreen error={error} />

  const open = state.incidents.filter((item) => item.status !== "closed").length

  return (
    <div className="min-h-svh">
      <FlashOverlay pulse={pulse} />
      <SiteHeader org={state.org.name} right={<StatusBar state={state} offset={offset} onChanged={onChanged} />} />
      {error ? (
        <div role="alert" className="border-b border-red-500/50 bg-red-500/10 px-5 py-2 text-center text-sm text-red-100">
          Lost contact with the control plane ({error}). Showing the last known state; retrying every 3 seconds.
        </div>
      ) : null}

      <main className="mx-auto grid max-w-[1500px] gap-4 px-4 py-4 lg:grid-cols-[300px_minmax(0,1fr)] lg:px-5">
        <HostsPanel hosts={state.hosts} onChanged={onChanged} />

        <Card className="gap-0 py-0">
          <CardHeader className="border-b py-3">
            <CardTitle className="text-xs font-semibold tracking-[0.14em] text-muted-foreground uppercase">Incidents</CardTitle>
            <CardAction className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">{open} open</CardAction>
          </CardHeader>
          <CardContent className="flex flex-col gap-3 py-3">
            {state.incidents.length ? (
              state.incidents.map((incident) => <IncidentCard key={incident.id} incident={incident} onChanged={onChanged} />)
            ) : (
              <div className="flex flex-col items-center gap-3 px-4 py-10 text-center text-sm text-muted-foreground">
                <LatticeLoader status="working" label={`Watching ${state.stats.decoys} decoys`} showTimer={false} />
                <p className="max-w-md">
                  No decoy has been touched. Every decoy is unique, so the first touch will say exactly where it came from.
                </p>
              </div>
            )}
          </CardContent>
        </Card>

        <div className="grid gap-4 lg:col-span-2 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
          <RegistryTable decoys={state.decoys} />
          <CoveragePanel coverage={state.coverage} stats={state.stats} />
        </div>
      </main>
    </div>
  )
}

function BootScreen({ error }: { error: string | null }) {
  return (
    <div className="grid min-h-svh place-items-center p-6">
      <div className="flex flex-col items-center gap-4 text-center">
        <LatticeLoader
          status={error ? "error" : "working"}
          label="Connecting to the control plane"
          errorLabel="Control plane unreachable"
          showTimer={!error}
          cellSize={9}
          gap={3}
          fontSize={17}
          step={80}
          glow={!error}
        />
        {error ? (
          <p className="max-w-md text-sm text-muted-foreground">
            Start it with <code className="font-mono">python -m mirage serve control</code>. This page keeps retrying every
            3 seconds.
          </p>
        ) : null}
      </div>
    </div>
  )
}
