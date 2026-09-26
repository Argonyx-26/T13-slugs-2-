import type { Severity } from "@/lib/api"

// Tailwind finds these class names in this file, so they must stay whole strings.
export const SEVERITY_BADGE: Record<Severity, string> = {
  HIGH: "border-red-500/40 bg-red-500/10 text-red-400",
  MEDIUM: "border-amber-500/40 bg-amber-500/10 text-amber-400",
  LOW: "border-sky-500/40 bg-sky-500/10 text-sky-400",
}

export const SEVERITY_EDGE: Record<Severity, string> = {
  HIGH: "border-l-red-500",
  MEDIUM: "border-l-amber-500",
  LOW: "border-l-sky-500",
}

export const ACTION_TONE = {
  contain: "border-transparent bg-red-500 text-red-950",
  approve: "border-transparent bg-amber-400 text-amber-950",
  neutral: "border-border bg-secondary text-secondary-foreground",
} as const

export const STAGE_DOT: Record<string, string> = {
  stolen: "bg-amber-400",
  used: "bg-red-500",
  tested: "bg-sky-400",
}

export const STAGE_TEXT: Record<string, string> = {
  stolen: "text-amber-400",
  used: "text-red-400",
  tested: "text-sky-400",
}
