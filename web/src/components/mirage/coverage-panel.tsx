import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import type { MirageState } from "@/lib/api"

export function CoveragePanel({ coverage, stats }: Pick<MirageState, "coverage" | "stats">) {
  const cells: [number, string][] = [
    [stats.decoys ?? 0, "decoys deployed"],
    [stats.events ?? 0, "decoy events"],
    [stats.unknown_credentials ?? 0, "unknown credentials ignored"],
    [stats.benign_reads ?? 0, "routine reads suppressed"],
  ]
  return (
    <Card className="h-fit gap-0 py-0">
      <CardHeader className="border-b py-3">
        <CardTitle className="text-xs font-semibold tracking-[0.14em] text-muted-foreground uppercase">Coverage</CardTitle>
        <CardAction className="text-xs tracking-wide text-muted-foreground uppercase">MITRE ATT&amp;CK</CardAction>
      </CardHeader>
      <CardContent className="py-3">
        <div className="flex flex-wrap gap-1.5">
          {coverage.built.map((item) => (
            <span key={item.id} className="rounded-md border border-emerald-500/45 bg-emerald-500/10 px-2 py-1 text-xs">
              <b className="mr-1.5 font-mono font-semibold">{item.id}</b>
              {item.label}
            </span>
          ))}
        </div>
        <p className="mt-4 mb-2 text-[11px] font-semibold tracking-[0.12em] text-muted-foreground uppercase">Roadmap</p>
        <div className="flex flex-wrap gap-1.5">
          {coverage.roadmap.map((item) => (
            <span key={item.id} className="rounded-md border border-dashed px-2 py-1 text-xs text-muted-foreground">
              <b className="mr-1.5 font-mono font-semibold">{item.id}</b>
              {item.label}
            </span>
          ))}
        </div>
        <div className="mt-4 grid grid-cols-2 gap-2">
          {cells.map(([value, label]) => (
            <div key={label} className="rounded-lg border bg-muted/30 px-3 py-2">
              <div className="text-xl font-bold tabular-nums">{value}</div>
              <div className="text-[11.5px] text-muted-foreground">{label}</div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
