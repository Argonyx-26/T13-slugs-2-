import { useRef, useState, type ComponentProps, type ReactNode } from "react"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import LatticeLoader, { type LatticeStatus } from "@/components/ui/lattice-loader"
import type { ActionResult } from "@/lib/api"
import { cn } from "@/lib/utils"

type ButtonProps = ComponentProps<typeof Button>

interface ActionControlProps {
  label: ReactNode
  /** Shown next to the running lattice, e.g. "Replacing decoy". */
  workingLabel: string
  doneLabel?: string
  errorLabel?: string
  run: () => Promise<ActionResult>
  /** Whether the button is offered at all. The loader still finishes if this turns false mid-action. */
  available?: boolean
  onSettled?: () => void
  variant?: ButtonProps["variant"]
  size?: ButtonProps["size"]
  className?: string
  title?: string
  /** How long the check or cross stays up before the control settles. */
  holdMs?: number
}

const shortTitle = (title: string) => title.split(":")[0].split(" (")[0]

/**
 * A button whose request is shown as a LatticeLoader: the lattice runs while the control
 * plane works, then freezes into a check ("Done in 0.4s") or a cross with the reason.
 */
export function ActionControl({
  label,
  workingLabel,
  doneLabel = "Done in",
  errorLabel = "Failed after",
  run,
  available = true,
  onSettled,
  variant = "outline",
  size = "sm",
  className,
  title,
  holdMs = 1600,
}: ActionControlProps) {
  const [phase, setPhase] = useState<"idle" | LatticeStatus>("idle")
  const busy = useRef(false)

  async function start() {
    if (busy.current) return
    busy.current = true
    setPhase("working")
    const startedAt = performance.now()
    const result = await run()
    // Keep the lattice on screen long enough to be read instead of flickering.
    const wait = 450 - (performance.now() - startedAt)
    if (wait > 0) await new Promise((resolve) => window.setTimeout(resolve, wait))
    setPhase(result.ok ? "done" : "error")
    if (!result.ok) {
      const missing = [...new Set((result.missing ?? []).map((m) => shortTitle(m.title)))]
      toast.error(result.error ?? "That didn't work.", {
        description: missing.length ? `Still open: ${missing.join(" · ")}` : undefined,
      })
    }
    window.setTimeout(() => {
      setPhase("idle")
      busy.current = false
      onSettled?.()
    }, holdMs)
  }

  if (phase !== "idle") {
    return (
      <LatticeLoader
        status={phase}
        label={workingLabel}
        doneLabel={doneLabel}
        errorLabel={errorLabel}
        cellSize={4}
        gap={1.5}
        fontSize={12.5}
        step={70}
        className={cn("min-h-7 px-1", className)}
      />
    )
  }
  if (!available) return null
  return (
    <Button variant={variant} size={size} className={className} title={title} onClick={() => void start()}>
      {label}
    </Button>
  )
}
