import type { ReactNode } from "react"

import { Brand } from "@/components/mirage/brand"
import { Link, useRoute } from "@/hooks/use-route"
import { cn } from "@/lib/utils"

const NAV = [
  { href: "/", label: "Overview" },
  { href: "/dashboard", label: "Dashboard" },
]

export function SiteHeader({ org, right }: { org?: string; right?: ReactNode }) {
  const { path } = useRoute()
  return (
    <header className="sticky top-0 z-40 border-b bg-background/85 backdrop-blur-md">
      <div className="mx-auto flex max-w-[1500px] flex-wrap items-center justify-between gap-3 px-4 py-3 lg:px-5">
        <div className="flex items-center gap-5">
          <Link href="/" aria-label="Mirage Engine home">
            <Brand org={org} />
          </Link>
          <nav className="flex items-center gap-1 text-sm">
            {NAV.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                aria-current={path === item.href ? "page" : undefined}
                className={cn(
                  "rounded-md px-2.5 py-1 transition-colors",
                  path === item.href ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground"
                )}
              >
                {item.label}
              </Link>
            ))}
          </nav>
        </div>
        {right}
      </div>
    </header>
  )
}
