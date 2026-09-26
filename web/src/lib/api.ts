// Types and calls for the Mirage control plane (FastAPI, same origin).

export type Severity = "LOW" | "MEDIUM" | "HIGH"
export type Role = "workstation" | "server" | "crown_jewel"
export type Phase = "contain" | "preserve" | "scope" | "eradicate" | "recover"
export type StepMode = "auto" | "approval" | "action" | "manual"

export interface Host {
  name: string
  role: Role
  owner: string
  team: string
  os: string
  status: "online" | "isolated"
  updated_at: number
  release_blockers: number
}

export interface Step {
  id: string
  phase: Phase
  title: string
  mode: StepMode
  required: boolean
  status: "pending" | "done" | "n/a"
  at: number | null
  by: string | null
  detail: string
}

export interface Source {
  ip: string | null
  zone: string
  name: string
}

export interface Attempt {
  ts: number
  what: string
  ip: string | null
  ua: string
  late: boolean
}

export interface TimelineEntry {
  ts: number
  stage: "stolen" | "used"
  severity: Severity
  text: string
  count?: number
  last_ts?: number
}

export interface Reader {
  process: string
  pid: number
  user: string
  computer?: string
  ts: number
}

export interface IncidentSummary {
  token_kind: "aws" | "api"
  display: string
  identity: string
  path: string
  template_label: string
  scope: string
  technique: string
  owner: string
  role: Role
  source: Source | null
  reader: Reader | null
  attempts: Attempt[]
  timeline: TimelineEntry[]
  why?: string
  contained?: { ts: number; by: string; result: string }
  evidence?: { ts: number; by: string; sha256: string; artifacts: number; path: string | null }
}

export interface Incident {
  id: string
  placement_id: string
  host: string
  bucket: "benign" | "threat"
  opened_at: number
  updated_at: number
  stage: "stolen" | "used"
  severity: Severity
  classification: string
  label: string
  attribution: "confirmed" | "planted-location"
  action: string
  status: "open" | "contained" | "closed"
  event_count: number
  breaker_tripped: number
  summary: IncidentSummary
  tasks: Step[]
}

export interface Decoy {
  id: string
  host: string
  path: string
  label: string
  scope: string
  technique: string
  kind: "aws" | "api"
  display: string
  identity: string
  colocated: string[]
  deployed_at: number
}

export interface Health {
  pipeline_ok: boolean
  starting: boolean
  last_selftest: number | null
  stale_after: number
  sensors: Record<string, { last: number; ok: boolean }>
  now: number
}

export interface Breaker {
  open: boolean
  tripped_at: number | null
  recent_auto: number
  limit: number
  window_minutes: number
}

export interface Campaign {
  ip: string
  name: string
  hosts: string[]
}

export interface MirageState {
  org: { name?: string; slug?: string; internal_domain?: string }
  health: Health
  breaker: Breaker
  hosts: Host[]
  campaigns: Campaign[]
  incidents: Incident[]
  decoys: Decoy[]
  stats: {
    decoys: number
    events: number
    open_incidents: number
    unknown_credentials?: number
    benign_reads?: number
  }
  coverage: {
    built: { id: string; label: string }[]
    roadmap: { id: string; label: string }[]
  }
}

export interface ActionResult {
  ok: boolean
  error?: string
  missing?: { incident: string; step: string; title: string }[]
}

export async function fetchState(): Promise<MirageState> {
  const res = await fetch("/api/state", { cache: "no-store" })
  if (!res.ok) throw new Error(`The control plane answered ${res.status}`)
  return (await res.json()) as MirageState
}

async function act(path: string, body: Record<string, unknown> = {}): Promise<ActionResult> {
  let res: Response
  try {
    res = await fetch(path, {
      method: "POST",
      // The custom header forces a CORS preflight, so other sites can't press these buttons.
      headers: { "x-mirage-action": "1", "content-type": "application/json" },
      body: JSON.stringify(body),
    })
  } catch {
    return { ok: false, error: "The control plane is unreachable." }
  }
  let data: Record<string, unknown> = {}
  try {
    data = (await res.json()) as Record<string, unknown>
  } catch {
    /* empty or non-JSON body */
  }
  if (!res.ok || data.ok === false) {
    return {
      ok: false,
      error: typeof data.error === "string" ? data.error : `Request failed (${res.status})`,
      missing: Array.isArray(data.missing) ? (data.missing as ActionResult["missing"]) : undefined,
    }
  }
  return { ok: true }
}

const enc = encodeURIComponent

export const api = {
  approve: (incidentId: string) => act(`/api/incidents/${enc(incidentId)}/approve`),
  release: (host: string) => act(`/api/hosts/${enc(host)}/release`),
  stepDone: (incidentId: string, stepId: string) => act(`/api/incidents/${enc(incidentId)}/steps/${enc(stepId)}/done`),
  stepRun: (incidentId: string, stepId: string) => act(`/api/incidents/${enc(incidentId)}/steps/${enc(stepId)}/run`),
  resetBreaker: () => act("/api/breaker/reset"),
}

export const reportUrl = (incidentId: string) => `/api/incidents/${enc(incidentId)}/report`
