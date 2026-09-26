import { Radar, ShieldCheck } from "lucide-react"
import type { ReactNode } from "react"

import { ActionControl } from "@/components/mirage/action-control"
import LatticeLoader from "@/components/ui/lattice-loader"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useServerNow } from "@/hooks/use-mirage"
import { api, type Health, type MirageState } from "@/lib/api"
import { ago } from "@/lib/format"
import { cn } from "@/lib/utils"

type Tone = "ok" | "bad" | "warn" | "muted"

const TONE: Record<Tone, string> = {
  ok: "border-emerald-500/35 text-foreground",
  bad: "border-red-500/60 bg-red-500/10 text-red-100",
  warn: "border-amber-500/60 bg-amber-500/10 text-amber-100",
  muted: "border-border text-muted-foreground",
}

export function Pill({ tone, children, className }: { tone: Tone; children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex min-h-8 items-center gap-2 rounded-full border bg-card px-3 py-1 text-[12.5px] whitespace-nowrap",
        TONE[tone],
        className
      )}
    >
      {children}
    </span>
  )
}

const small = { cellSize: 4, gap: 1.5, fontSize: 12.5, step: 80 } as const

/** The self-test: a lattice while starting, a check when healthy, a counting cross when silent. */
export function PipelineStatus({ health, offset }: { health: Health; offset: number }) {
  const now = useServerNow(offset)
  if (!health.pipeline_ok && health.starting) {
    return <LatticeLoader status="working" label="Starting self-test" {...small} />
  }
  if (health.pipeline_ok) {
    return (
      <span className="inline-flex items-center gap-1.5">
        <LatticeLoader status="done" label="Checking" doneLabel="Detection pipeline OK" showTimer={false} {...small} />
        <span className="text-muted-foreground">· self-test {ago(now - (health.last_selftest ?? now))}</span>
      </span>
    )
  }
  const silentFor = health.last_selftest == null ? undefined : Math.max(0, now - health.last_selftest)
  return (
    <LatticeLoader
      status="error"
      errorLabel={silentFor == null ? "PIPELINE DOWN" : "PIPELINE DOWN · no self-test for"}
      elapsed={silentFor}
      showTimer={silentFor != null}
      glow
      {...small}
    />
  )
}

export function StatusBar({
  state,
  offset,
  onChanged,
}: {
  state: MirageState
  offset: number
  onChanged: () => void
}) {
  const now = useServerNow(offset)
  const { health, breaker, campaigns } = state
  const reader = health.sensors.readaudit

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Pill tone={health.pipeline_ok ? "ok" : health.starting ? "muted" : "bad"}>
        <PipelineStatus health={health} offset={offset} />
      </Pill>

      {!reader ? (
        <Pill tone="muted">
          <span className="size-2 rounded-full bg-muted-foreground" />
          Read sensor off
        </Pill>
      ) : reader.ok ? (
        <Pill tone="ok">
          <LatticeLoader status="working" label="Read sensor live" pattern="ripple" showTimer={false} color="#34d399" {...small} />
        </Pill>
      ) : (
        <Pill tone="bad">
          <LatticeLoader status="error" errorLabel="Read sensor silent for" elapsed={Math.max(0, now - reader.last)} {...small} />
        </Pill>
      )}

      {campaigns.map((campaign) => (
        <Tooltip key={campaign.ip}>
          <TooltipTrigger asChild>
            <span>
              <Pill tone="bad">
                <Radar className="size-3.5 text-red-400" />
                Campaign: {campaign.ip} hit {campaign.hosts.length} hosts
              </Pill>
            </span>
          </TooltipTrigger>
          <TooltipContent>Same attacker on {campaign.hosts.join(", ")}. Treat them all as compromised.</TooltipContent>
        </Tooltip>
      ))}

      {breaker.open ? (
        <Pill tone="warn">
          <span className="size-2 rounded-full bg-amber-400" />
          Circuit breaker open · approval-only
          <ActionControl
            label="Reset"
            workingLabel="Resetting"
            run={api.resetBreaker}
            onSettled={onChanged}
            size="xs"
            variant="secondary"
          />
        </Pill>
      ) : (
        <Pill tone="ok">
          <ShieldCheck className="size-3.5 text-emerald-400" />
          Auto-response armed · {breaker.recent_auto}/{breaker.limit} in {breaker.window_minutes} min
        </Pill>
      )}
    </div>
  )
}
