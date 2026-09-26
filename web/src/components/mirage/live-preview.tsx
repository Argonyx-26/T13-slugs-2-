import { ArrowRight, Crown, Laptop, Lock, Server } from "lucide-react"

import { BrandMark } from "@/components/mirage/brand"
import { PipelineStatus } from "@/components/mirage/status-bar"
import { SEVERITY_BADGE } from "@/components/mirage/tones"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import LatticeLoader from "@/components/ui/lattice-loader"
import { useRoute } from "@/hooks/use-route"
import type { MirageState } from "@/lib/api"
import { ACTION_LABEL, clock, incidentTitle } from "@/lib/format"
import { cn } from "@/lib/utils"

const ROLE_ICON = { workstation: Laptop, server: Server, crown_jewel: Crown }

/** A compact, live version of the dashboard for the landing page's scroll card. */
export function LivePreview({ state, error, offset }: { state: MirageState | null; error: string | null; offset: number }) {
  const { navigate } = useRoute()

  if (!state) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4 p-6 text-center">
        <LatticeLoader
          status={error ? "error" : "working"}
          label="Loading live data"
          errorLabel="Control plane offline"
          showTimer={!error}
          cellSize={8}
          gap={3}
          fontSize={16}
        />
        {error ? (
          <p className="max-w-sm text-sm text-muted-foreground">
            Start it with <code className="font-mono">python -m mirage serve control</code>. This page keeps retrying.
          </p>
        ) : null}
      </div>
    )
  }

  const incidents = state.incidents.filter((incident) => incident.bucket === "threat").slice(0, 4)
  const open = state.incidents.filter((incident) => incident.status !== "closed").length
  const inResponse = state.incidents
    .filter((incident) => incident.bucket === "threat" && incident.status !== "closed" && incident.severity === "HIGH")
    .slice(0, 3)

  return (
    <div className="flex h-full flex-col gap-3 p-3 text-left md:p-1">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b pb-3">
        <span className="flex items-center gap-2 text-xs font-bold tracking-[0.18em]">
          <BrandMark className="size-4" /> LIVE
        </span>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <PipelineStatus health={state.health} offset={offset} />
          <Badge variant="outline">{open} open</Badge>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        {state.hosts.map((host) => {
          const Icon = ROLE_ICON[host.role]
          const isolated = host.status === "isolated"
          return (
            <div
              key={host.name}
              className={cn(
                "flex items-center justify-between gap-2 rounded-lg border px-2.5 py-2 text-xs",
                isolated ? "border-red-500/60 bg-red-500/10" : "bg-muted/30"
              )}
            >
              <span className="flex min-w-0 items-center gap-1.5 font-mono">
                <Icon className="size-3.5 shrink-0 text-muted-foreground" />
                <span className="truncate">{host.name}</span>
              </span>
              {isolated ? (
                <Lock className="size-3.5 shrink-0 text-red-400" aria-label="isolated" />
              ) : (
                <span className="size-2 shrink-0 rounded-full bg-emerald-400" aria-label="online" />
              )}
            </div>
          )
        })}
      </div>

      <div className="min-h-0 flex-1 overflow-hidden">
        <p className="mb-2 text-[11px] font-semibold tracking-[0.12em] text-muted-foreground uppercase">Latest incidents</p>
        {incidents.length ? (
          <ul className="space-y-2">
            {incidents.map((incident) => (
              <li key={incident.id} className="flex items-center gap-2 rounded-lg border bg-muted/20 px-3 py-2 text-[13px]">
                <Badge variant="outline" className={SEVERITY_BADGE[incident.severity]}>
                  {incident.severity}
                </Badge>
                <span className="min-w-0 flex-1 truncate">{incidentTitle(incident)}</span>
                <span className="hidden text-xs text-muted-foreground sm:inline">
                  {ACTION_LABEL[incident.action]?.text} · {clock(incident.updated_at)}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="flex items-center gap-3 rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
            <LatticeLoader status="working" label={`Watching ${state.stats.decoys} decoys`} showTimer={false} fontSize={13} cellSize={5} />
            <span>Nothing has been touched yet.</span>
          </div>
        )}
      </div>

      {inResponse.length ? (
        <div className="hidden md:block">
          <p className="mb-2 text-[11px] font-semibold tracking-[0.12em] text-muted-foreground uppercase">Response playbooks</p>
          <ul className="grid gap-2 md:grid-cols-3">
            {inResponse.map((incident) => {
              const done = incident.tasks.filter((step) => step.status !== "pending").length
              return (
                <li key={incident.id} className="rounded-lg border bg-muted/20 px-3 py-2">
                  <div className="flex items-center justify-between gap-2 text-xs">
                    <span className="truncate font-mono">{incident.host}</span>
                    <span className="text-muted-foreground tabular-nums">
                      {done}/{incident.tasks.length}
                    </span>
                  </div>
                  <Progress
                    value={(done / Math.max(1, incident.tasks.length)) * 100}
                    className="mt-2 h-1.5 [&>[data-slot=progress-indicator]]:bg-emerald-500"
                  />
                </li>
              )
            })}
          </ul>
        </div>
      ) : null}

      <Button className="self-end" onClick={() => navigate("/dashboard")}>
        Open the live dashboard <ArrowRight />
      </Button>
    </div>
  )
}
