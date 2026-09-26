import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import type { Decoy } from "@/lib/api"

export function RegistryTable({ decoys }: { decoys: Decoy[] }) {
  return (
    <Card className="gap-0 py-0">
      <CardHeader className="border-b py-3">
        <CardTitle className="text-xs font-semibold tracking-[0.14em] text-muted-foreground uppercase">Decoy registry</CardTitle>
        <CardAction className="text-xs tracking-wide text-muted-foreground uppercase">One unique decoy per location</CardAction>
      </CardHeader>
      <CardContent className="px-2 py-2">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Host</TableHead>
              <TableHead>Decoy file</TableHead>
              <TableHead>Key</TableHead>
              <TableHead>Scope</TableHead>
              <TableHead>Technique</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {decoys.map((decoy) => (
              <TableRow key={decoy.id}>
                <TableCell className="align-top font-mono text-xs">{decoy.host}</TableCell>
                <TableCell className="align-top whitespace-normal">
                  <span className="font-mono text-xs">{decoy.path}</span>
                  <p className="text-[11.5px] text-muted-foreground">
                    {decoy.label}
                    {decoy.colocated.length ? ` · next to real secrets: ${decoy.colocated.join("; ")}` : ""}
                  </p>
                </TableCell>
                <TableCell className="align-top font-mono text-xs">
                  {decoy.display}
                  <p className="text-[11px] text-muted-foreground">{decoy.identity}</p>
                </TableCell>
                <TableCell className="align-top text-xs">{decoy.scope}</TableCell>
                <TableCell className="align-top font-mono text-xs">{decoy.technique}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}
