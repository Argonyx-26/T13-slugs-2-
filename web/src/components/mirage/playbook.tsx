import { Check, Circle, CircleCheck, Play } from "lucide-react"

import { ActionControl } from "@/components/mirage/action-control"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { api, type Incident, type Phase, type Step, type StepMode } from "@/lib/api"
import { clock } from "@/lib/format"
import { cn } from "@/lib/utils"

const PHASES: Phase[] = ["contain", "preserve", "scope", "eradicate", "recover"]
const PHASE_LABEL: Record<Phase, string> = {
  contain: "Contain",
  preserve: "Preserve evidence",
  scope: "Scope",
  eradicate: "Eradicate",
  recover: "Recover",
}
const MODE: Record<StepMode, { text: string; className: string }> = {
  auto: { text: "Auto", className: "border-sky-500/40 text-sky-300" },
  action: { text: "You run", className: "border-amber-500/40 text-amber-300" },
  manual: { text: "You confirm", className: "border-amber-500/40 text-amber-300" },
  approval: { text: "Needs approval", className: "border-amber-500/40 text-amber-300" },
}
const RUN_LABEL: Record<string, string> = {
  replace_decoy: "Replacing decoy",
  evidence: "Capturing evidence",
}

const isStep = (value: unknown): value is Step => typeof value === "object" && value !== null && "id" in value

export function Playbook({ incident, onChanged }: { incident: Incident; onChanged: () => void }) {
  const steps = incident.tasks.filter(isStep)
  if (!steps.length) return null
  const finished = steps.filter((step) => step.status !== "pending").length
  const groups: { phase: Phase; steps: Step[] }[] = []
  for (const step of steps) {
    const last = groups[groups.length - 1]
    if (last && last.phase === step.phase) last.steps.push(step)
    else groups.push({ phase: step.phase, steps: [step] })
  }

  return (
    <section className="mt-3 rounded-lg border border-dashed bg-background/50 p-3">
      <div className="flex items-center justify-between gap-3">
        <h4 className="text-[11px] font-semibold tracking-[0.12em] text-muted-foreground uppercase">
          Response playbook · {finished}/{steps.length} done
        </h4>
        <Progress
          value={(finished / steps.length) * 100}
          className="h-1.5 max-w-40 [&>[data-slot=progress-indicator]]:bg-emerald-500"
        />
      </div>
      {groups.map((group) => (
        <div key={group.phase} className="mt-2.5">
          <p className="mb-1 text-[10.5px] font-semibold tracking-[0.12em] text-muted-foreground uppercase">
            {PHASES.indexOf(group.phase) + 1} · {PHASE_LABEL[group.phase]}
          </p>
          <ul className="space-y-0.5">
            {group.steps.map((step) => (
              <StepRow key={step.id} step={step} incident={incident} onChanged={onChanged} />
            ))}
          </ul>
        </div>
      ))}
    </section>
  )
}

function StepRow({ step, incident, onChanged }: { step: Step; incident: Incident; onChanged: () => void }) {
  const done = step.status !== "pending"
  const available = !done && incident.status !== "closed"
  const mode = MODE[step.mode]
  const trail = done
    ? [step.by, clock(step.at), step.detail].filter(Boolean).join(" · ")
    : step.detail

  return (
    <li className="grid grid-cols-[18px_minmax(0,1fr)_auto] items-start gap-2 py-1 text-[13px]">
      {done ? (
        <CircleCheck className="mt-0.5 size-4 text-emerald-400" />
      ) : (
        <Circle className="mt-0.5 size-4 text-muted-foreground" />
      )}
      <div className="min-w-0">
        <span className={cn(done && "text-foreground/70")}>{step.title}</span>
        <Badge variant="outline" className={cn("ml-2 h-4 px-1.5 text-[9.5px] font-bold tracking-wider uppercase", mode.className)}>
          {mode.text}
        </Badge>
        {trail ? <p className="mt-0.5 text-xs break-words text-muted-foreground">{trail}</p> : null}
      </div>
      <div className="flex justify-end">
        {step.mode === "manual" && step.id !== "release" ? (
          <ActionControl
            available={available}
            label={
              <>
                <Check /> Mark done
              </>
            }
            workingLabel="Confirming"
            doneLabel="Confirmed in"
            errorLabel="Refused after"
            size="xs"
            run={() => api.stepDone(incident.id, step.id)}
            onSettled={onChanged}
          />
        ) : null}
        {step.mode === "action" ? (
          <ActionControl
            available={available}
            label={
              <>
                <Play /> Run
              </>
            }
            workingLabel={RUN_LABEL[step.id] ?? "Running"}
            size="xs"
            run={() => api.stepRun(incident.id, step.id)}
            onSettled={onChanged}
          />
        ) : null}
      </div>
    </li>
  )
}
