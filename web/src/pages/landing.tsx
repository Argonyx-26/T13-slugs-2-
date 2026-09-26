import {
  Archive,
  ArrowRight,
  Eraser,
  FileSearch,
  Fingerprint,
  Funnel,
  HeartPulse,
  KeyRound,
  MapPin,
  PlugZap,
  RadioTower,
  RotateCcw,
  ScanSearch,
  ShieldCheck,
  ShieldHalf,
  TriangleAlert,
  Unplug,
  type LucideIcon,
} from "lucide-react"
import type { ReactNode } from "react"

import { LivePreview } from "@/components/mirage/live-preview"
import { SiteHeader } from "@/components/mirage/site-header"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ContainerScroll } from "@/components/ui/container-scroll-animation"
import LatticeLoader from "@/components/ui/lattice-loader"
import { useMirage } from "@/hooks/use-mirage"
import { useRoute } from "@/hooks/use-route"
import type { MirageState } from "@/lib/api"

interface Point {
  icon: LucideIcon
  title: string
  text: string
}

const TRAP_STEPS: Point[] = [
  {
    icon: KeyRound,
    title: "Plant",
    text: "One unique fake key per location: ~/.aws/credentials, old .env backups, scripts on file shares, IT docs. Backdated and named in the company's own style.",
  },
  {
    icon: FileSearch,
    title: "Harvest",
    text: "An intruder sweeps the machine for secrets, the way every credential-stealing tool does, and takes the decoy along with everything else.",
  },
  {
    icon: RadioTower,
    title: "Call home",
    text: "The decoy points at a service Mirage controls. The first time anyone tries it, Mirage knows, and the key itself says which file it came from.",
  },
  {
    icon: ShieldCheck,
    title: "Respond",
    text: "Harmless scanners are recognised. Workstations are contained automatically, servers wait for a person, and every step is logged.",
  },
]

const DIFFERENCES: Point[] = [
  {
    icon: MapPin,
    title: "Exact attribution",
    text: "Every decoy is unique, so a key maps to one host and one file. With read auditing on, Mirage also names the process and user that opened it.",
  },
  {
    icon: Funnel,
    title: "Harmless-trigger triage",
    text: "A known scanner must match on source IP and user-agent. The same user-agent from anywhere else is flagged as possible spoofing.",
  },
  {
    icon: ShieldHalf,
    title: "Guarded response",
    text: "Automatic containment only where attribution is solid. A circuit breaker stops attackers from firing decoys to isolate your own machines.",
  },
  {
    icon: RotateCcw,
    title: "Fix the real damage",
    text: "The attacker took the whole file. Mirage lists the real secrets stored next to the decoy, and rotating them is part of the playbook.",
  },
  {
    icon: HeartPulse,
    title: "No silent failure",
    text: "A self-test token travels the whole pipeline every few seconds. If it stops coming back, that is an alert.",
  },
  {
    icon: Fingerprint,
    title: "No shared fingerprint",
    text: "Self-hosted, with names in your own style. Keys from free public canary services can be recognised offline; these can't be matched that way.",
  },
]

const PHASES: Point[] = [
  { icon: Unplug, title: "Contain", text: "Isolate the host, block the attacker's address, and revoke the owner's sessions." },
  { icon: Archive, title: "Preserve", text: "Capture memory, processes and connections with a SHA-256, before anything is cleaned." },
  { icon: ScanSearch, title: "Scope", text: "Hunt for the same attacker on other hosts. One attacker on many hosts raises a campaign warning." },
  { icon: Eraser, title: "Eradicate", text: "Rotate the real secrets, replace the burned decoy, and reimage (only once evidence exists)." },
  { icon: PlugZap, title: "Recover", text: "Release is refused until the required steps are done. Forcing it needs a written reason." },
]

const LIMITS = [
  "AWS is emulated in the demo, because real CloudTrail alerts take 2–30 minutes. Production uses zero-permission keys in a dedicated account.",
  "The six hosts are folders on one laptop, and loopback addresses stand in for real networks.",
  "Isolation, firewall blocks and session revocation go through simulated connectors. The evidence hashes and the audit trail are real.",
]

function Section({ eyebrow, title, children }: { eyebrow: string; title: string; children: ReactNode }) {
  return (
    <section className="mx-auto max-w-6xl px-4 py-14 md:py-20">
      <p className="text-xs font-semibold tracking-[0.2em] text-red-400 uppercase">{eyebrow}</p>
      <h2 className="mt-2 max-w-3xl text-2xl font-semibold text-balance md:text-4xl">{title}</h2>
      <div className="mt-8">{children}</div>
    </section>
  )
}

function HeroTitle({ state, error }: { state: MirageState | null; error: string | null }) {
  const watching = state ? `Watching ${state.stats.decoys} decoys across ${state.hosts.length} hosts` : "Connecting to the control plane"
  return (
    <div className="pb-16 md:pb-20">
      <div className="mb-8 flex justify-center">
        <LatticeLoader
          status={!state && error ? "error" : "working"}
          label={watching}
          errorLabel="Control plane offline"
          showTimer={false}
          fontSize={13}
          cellSize={5}
          className="rounded-full border bg-card px-3.5 py-2 text-muted-foreground"
        />
      </div>
      <h1 className="text-4xl font-semibold text-black dark:text-white">
        Decoy credentials <br />
        <span className="mt-1 bg-linear-to-b from-white to-white/55 bg-clip-text text-4xl leading-none font-bold text-transparent md:text-[6rem]">
          that call home
        </span>
      </h1>
      <p className="mx-auto mt-6 max-w-2xl text-base text-pretty text-muted-foreground md:text-lg">
        Mirage plants a unique fake key wherever attackers look for secrets. Nobody was ever given these keys, so the
        moment one is used, Mirage knows which machine and file it came from, and contains it when that's safe.
      </p>
    </div>
  )
}

export function LandingPage() {
  const { state, error, offset } = useMirage()
  const { navigate } = useRoute()
  const openDashboard = () => navigate("/dashboard")

  return (
    <div className="min-h-svh">
      <SiteHeader
        org={state?.org.name}
        right={
          <Button onClick={openDashboard}>
            Open the live dashboard <ArrowRight />
          </Button>
        }
      />

      <div className="flex flex-col overflow-hidden">
        <ContainerScroll titleComponent={<HeroTitle state={state} error={error} />}>
          <LivePreview state={state} error={error} offset={offset} />
        </ContainerScroll>
      </div>

      <Section eyebrow="How a trap fires" title="Four steps from a planted key to a contained machine">
        <ol className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {TRAP_STEPS.map((step, index) => (
            <li key={step.title}>
              <Card className="h-full">
                <CardHeader>
                  <span className="mb-2 flex items-center gap-2 text-xs font-semibold tracking-[0.14em] text-muted-foreground uppercase">
                    <step.icon className="size-4 text-red-400" /> Step {index + 1}
                  </span>
                  <CardTitle className="text-lg">{step.title}</CardTitle>
                  <CardDescription className="leading-relaxed">{step.text}</CardDescription>
                </CardHeader>
              </Card>
            </li>
          ))}
        </ol>
      </Section>

      <Section eyebrow="What's different" title="Other tools tell you a decoy fired. Mirage finishes the job.">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {DIFFERENCES.map((item) => (
            <Card key={item.title} className="h-full">
              <CardHeader>
                <item.icon className="mb-2 size-5 text-red-400" />
                <CardTitle>{item.title}</CardTitle>
                <CardDescription className="leading-relaxed">{item.text}</CardDescription>
              </CardHeader>
            </Card>
          ))}
        </div>
      </Section>

      <Section eyebrow="After the network is cut" title="Isolation is step one. The playbook enforces the rest.">
        <ol className="grid gap-3 md:grid-cols-5">
          {PHASES.map((phase, index) => (
            <li key={phase.title} className="rounded-xl border bg-card p-4">
              <span className="flex items-center gap-2 text-xs font-semibold tracking-[0.14em] text-muted-foreground uppercase">
                <phase.icon className="size-4 text-emerald-400" /> {index + 1}
              </span>
              <p className="mt-2 font-semibold">{phase.title}</p>
              <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{phase.text}</p>
            </li>
          ))}
        </ol>
      </Section>

      <Section eyebrow="Honest limits" title="What the demo simulates, said before anyone has to ask">
        <Card>
          <CardContent>
            <ul className="space-y-3">
              {LIMITS.map((limit) => (
                <li key={limit} className="flex gap-3 text-sm leading-relaxed">
                  <TriangleAlert className="mt-0.5 size-4 shrink-0 text-amber-400" />
                  <span>{limit}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </Section>

      <section className="mx-auto flex max-w-6xl flex-col items-center gap-5 px-4 pt-6 pb-24 text-center">
        <h2 className="text-2xl font-semibold md:text-4xl">See it catch someone</h2>
        <p className="max-w-xl text-muted-foreground">
          Run <code className="font-mono text-foreground">python demo/attacker_sim.py attacker</code> and watch the
          dashboard flash, contain the laptop, and list what to rotate.
        </p>
        <div className="flex flex-wrap justify-center gap-3">
          <Button size="lg" onClick={openDashboard}>
            Open the live dashboard <ArrowRight />
          </Button>
          <Button size="lg" variant="outline" asChild>
            <a href="/classic">Classic dashboard</a>
          </Button>
        </div>
      </section>

      <footer className="border-t py-6 text-center text-xs text-muted-foreground">
        Mirage Engine · decoy credentials that call home
      </footer>
    </div>
  )
}
