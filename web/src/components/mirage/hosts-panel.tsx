import { Crown, Laptop, Lock, LockOpen, Server } from "lucide-react"

import { ActionControl } from "@/components/mirage/action-control"
import { Badge } from "@/components/ui/badge"
import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { api, type Host } from "@/lib/api"
import { ROLE_LABEL } from "@/lib/format"
import { cn } from "@/lib/utils"

const ROLE_ICON = { workstation: Laptop, server: Server, crown_jewel: Crown }
const ROLE_BADGE = {
  workstation: "text-muted-foreground",
  server: "border-sky-500/40 text-sky-300",
  crown_jewel: "border-fuchsia-500/40 text-fuchsia-300",
}

export function HostsPanel({ hosts, onChanged }: { hosts: Host[]; onChanged: () => void }) {
  const isolated = hosts.filter((host) => host.status === "isolated").length
  return (
    <Card className="h-fit gap-0 py-0">
      <CardHeader className="border-b py-3">
        <CardTitle className="text-xs font-semibold tracking-[0.14em] text-muted-foreground uppercase">Hosts</CardTitle>
        <CardAction className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
          {isolated} isolated
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-2 py-3">
        {hosts.map((host) => (
          <HostRow key={host.name} host={host} onChanged={onChanged} />
        ))}
      </CardContent>
    </Card>
  )
}

function HostRow({ host, onChanged }: { host: Host; onChanged: () => void }) {
  const isolated = host.status === "isolated"
  const gated = host.release_blockers > 0
  const Icon = ROLE_ICON[host.role]
  return (
    <div className={cn("rounded-lg border p-3", isolated ? "border-red-500/60 bg-red-500/10" : "bg-muted/30")}>
      <div className="flex items-center justify-between gap-2">
        <span className="flex min-w-0 items-center gap-2 font-mono text-[13px] font-semibold">
          <Icon className="size-4 shrink-0 text-muted-foreground" />
          <span className="truncate">{host.name}</span>
        </span>
        <Badge variant="outline" className={cn("text-[10px] tracking-wider uppercase", ROLE_BADGE[host.role])}>
          {ROLE_LABEL[host.role]}
        </Badge>
      </div>
      <p className="mt-1 text-xs text-muted-foreground">
        {host.owner}
        {host.team && host.team !== host.owner ? ` · ${host.team}` : ""} · {host.os}
      </p>
      <div className="mt-2 flex min-h-7 flex-wrap items-center justify-between gap-2">
        {isolated ? (
          <span className="flex items-center gap-1.5 text-xs font-bold tracking-wider text-red-400">
            <Lock className="size-3.5" /> ISOLATED
          </span>
        ) : (
          <span className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
            <span className="size-2 rounded-full bg-emerald-400" /> Online
          </span>
        )}
        <ActionControl
          available={isolated}
          label={
            gated ? (
              <>Release · {host.release_blockers} steps left</>
            ) : (
              <>
                <LockOpen /> Release
              </>
            )
          }
          title={gated ? "Finish the response playbook first" : "Put the host back on the network"}
          workingLabel="Releasing"
          doneLabel="Released in"
          errorLabel="Refused after"
          variant={gated ? "ghost" : "outline"}
          className={gated ? "border border-dashed border-border text-muted-foreground" : undefined}
          run={() => api.release(host.name)}
          onSettled={onChanged}
        />
      </div>
    </div>
  )
}
