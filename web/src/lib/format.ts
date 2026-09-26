import type { Incident, Role } from "@/lib/api"

export const clock = (ts?: number | null) =>
  ts ? new Date(ts * 1000).toLocaleTimeString([], { hour12: false }) : ""

export const ago = (seconds: number) => {
  const s = Math.max(0, Math.round(seconds))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  return `${Math.floor(s / 3600)}h ago`
}

export const ROLE_LABEL: Record<Role, string> = {
  workstation: "Workstation",
  server: "Server",
  crown_jewel: "Crown jewel",
}

type Tone = "contain" | "approve" | "neutral"

export const ACTION_LABEL: Record<string, { text: string; tone: Tone }> = {
  auto_contain: { text: "Auto-contained", tone: "contain" },
  approved_contained: { text: "Contained (approved)", tone: "contain" },
  already_contained: { text: "Host already contained", tone: "neutral" },
  approval_required: { text: "Approval required", tone: "approve" },
  page: { text: "Paged", tone: "neutral" },
  ticket: { text: "Ticket", tone: "neutral" },
}

export function incidentTitle(incident: Incident) {
  if (incident.bucket === "benign") return `Harmless trigger on ${incident.host}: known scanner`
  if (incident.stage === "stolen") return `Decoy file read on ${incident.host}`
  const kind = incident.summary.token_kind === "aws" ? "AWS key" : "API key"
  return `Decoy ${kind} used, planted on ${incident.host}`
}
