import { cn } from "@/lib/utils"

/** A 3x3 lattice with a hollow centre: the same geometry as the loader's "orbit" pattern. */
export function BrandMark({ className }: { className?: string }) {
  const cells = [0, 1, 2, 3, 5, 6, 7, 8]
  return (
    <svg viewBox="0 0 22 22" aria-hidden="true" className={cn("size-5", className)}>
      {cells.map((i) => (
        <circle
          key={i}
          cx={3 + (i % 3) * 8}
          cy={3 + Math.floor(i / 3) * 8}
          r={2.6}
          className={i === 2 || i === 6 ? "fill-red-400" : "fill-current"}
          opacity={i === 2 || i === 6 ? 1 : 0.85}
        />
      ))}
    </svg>
  )
}

export function Brand({ org, compact = false }: { org?: string; compact?: boolean }) {
  return (
    <span className="flex items-center gap-2.5">
      <BrandMark className={compact ? "size-4" : "size-5"} />
      <span className="flex items-baseline gap-2">
        <span className={cn("font-bold tracking-[0.18em] whitespace-nowrap", compact ? "text-xs" : "text-sm sm:text-[15px]")}>
          MIRAGE ENGINE
        </span>
        {org && !compact ? <span className="hidden text-xs text-muted-foreground sm:inline">{org}</span> : null}
      </span>
    </span>
  )
}
