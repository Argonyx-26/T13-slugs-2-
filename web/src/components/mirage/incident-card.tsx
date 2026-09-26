import { ExternalLink, FileText, Lock } from "lucide-react"
import type { ReactNode } from "react"

import { ActionControl } from "@/components/mirage/action-control"
import { Playbook } from "@/components/mirage/playbook"
import { ACTION_TONE, SEVERITY_BADGE, SEVERITY_EDGE, STAGE_DOT, STAGE_TEXT } from "@/components/mirage/tones"
import { Badge } from "@/components/ui/badge"
import { api, reportUrl, type Incident } from "@/lib/api"
import { ACTION_LABEL, clock, incidentTitle } from "@/lib/format"
import { cn } from "@/lib/utils"

const Mono = ({ children }: { children: ReactNode }) => <span className="font-mono text-[12px]">{children}</span>

export function IncidentCard({ incident, onChanged }: { incident: Incident; onChanged: () => void }) {
  const s = incident.summary
  const action = ACTION_LABEL[incident.action]
  const closed = incident.status === "closed"
  const benign = incident.bucket === "benign"
  const tried = [...new Set(s.attempts.map((attempt) => attempt.what))]
  const userAgent = s.attempts[s.attempts.length - 1]?.ua
  const canApprove = incident.action === "approval_required" && incident.status === "open"

  const facts: [string, ReactNode][] = [
    ["File", <><Mono>{s.path}</Mono> · {s.template_label}</>],
    ["Decoy", <><Mono>{s.display}</Mono> · {s.identity} · {s.scope}</>],
  ]
  if (s.source?.ip) facts.push(["Source", <><Mono>{s.source.ip}</Mono> · {s.source.zone} · {s.source.name}</>])
  if (tried.length) facts.push(["Tried", <Mono>{tried.join(" · ")}</Mono>])
  if (userAgent) facts.push(["User-agent", <Mono>{userAgent}</Mono>])
  if (!benign) {
    facts.push([
      "Attribution",
      incident.attribution === "confirmed" && s.reader ? (
        <>
          <b>confirmed</b>: read by <Mono>{s.reader.process}</Mono> (PID {s.reader.pid}) as {s.reader.user}
        </>
      ) : (
        "planted location (no read telemetry yet)"
      ),
    ])
  }
  if (s.evidence) facts.push(["Evidence", <>{s.evidence.artifacts} artifacts · sha256 <Mono>{s.evidence.sha256.slice(0, 16)}…</Mono></>])
  if (s.contained) facts.push(["Containment", `${s.contained.result} by ${s.contained.by} at ${clock(s.contained.ts)}`])

  return (
    <article
      className={cn(
        "rounded-xl border border-l-4 bg-muted/20 p-4 transition-opacity",
        SEVERITY_EDGE[incident.severity],
        closed && "opacity-55"
      )}
    >
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap gap-1.5">
          <Badge variant="outline" className={SEVERITY_BADGE[incident.severity]}>
            {incident.severity}
          </Badge>
          {action ? <Badge className={cn("tracking-wide uppercase", ACTION_TONE[action.tone])}>{action.text}</Badge> : null}
          {incident.breaker_tripped ? (
            <Badge variant="outline" className="border-amber-500 tracking-wide text-amber-400 uppercase">
              Breaker tripped
            </Badge>
          ) : null}
          {closed ? <Badge variant="secondary">Closed</Badge> : null}
        </div>
        <span className="text-xs text-muted-foreground">
          {clock(incident.updated_at)} · {incident.event_count} event{incident.event_count === 1 ? "" : "s"}
        </span>
      </header>

      <h3 className="mt-2 text-[15.5px] font-semibold">{incidentTitle(incident)}</h3>
      <p className="mt-0.5 text-[13px] text-foreground/75">{s.why || incident.label}</p>

      <ol className="mt-3 space-y-1 border-l-2 border-border pl-3">
        {s.timeline.map((entry, index) => {
          const stage = benign && entry.stage === "used" ? "tested" : entry.stage
          return (
            <li key={index} className="relative text-[13px] break-words">
              <span className={cn("absolute top-1.5 -left-[18px] size-2.5 rounded-full", STAGE_DOT[stage])} />
              <span className={cn("mr-1.5 text-[10.5px] font-bold tracking-wider uppercase", STAGE_TEXT[stage])}>{stage}</span>
              <span className="font-mono text-xs text-muted-foreground">{clock(entry.ts)}</span> {entry.text}
              {entry.count ? <b> ×{entry.count}</b> : null}
            </li>
          )
        })}
      </ol>

      <dl className="mt-3 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12.5px]">
        {facts.map(([term, value]) => (
          <div key={term} className="contents">
            <dt className="text-muted-foreground">{term}</dt>
            <dd className="break-words">{value}</dd>
          </div>
        ))}
      </dl>

      <Playbook incident={incident} onChanged={onChanged} />

      <footer className="mt-3 flex flex-wrap items-center gap-3">
        <ActionControl
          available={canApprove}
          label={
            <>
              <Lock /> Approve containment of {incident.host}
            </>
          }
          workingLabel={`Containing ${incident.host}`}
          doneLabel="Contained in"
          variant="default"
          size="default"
          className="bg-red-500 font-semibold text-red-950 hover:bg-red-400"
          run={() => api.approve(incident.id)}
          onSettled={onChanged}
        />
        <a
          href={reportUrl(incident.id)}
          target="_blank"
          rel="noopener"
          className="inline-flex items-center gap-1 text-[12.5px] text-sky-400 hover:underline"
        >
          <FileText className="size-3.5" /> Incident report <ExternalLink className="size-3" />
        </a>
      </footer>
    </article>
  )
}
