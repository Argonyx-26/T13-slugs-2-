import { lazy, Suspense } from "react"

import LatticeLoader from "@/components/ui/lattice-loader"
import { useRoute } from "@/hooks/use-route"

// Each page is its own chunk: the dashboard never downloads the landing page's scroll animation.
const LandingPage = lazy(() => import("@/pages/landing").then((m) => ({ default: m.LandingPage })))
const DashboardPage = lazy(() => import("@/pages/dashboard").then((m) => ({ default: m.DashboardPage })))

function PageLoading() {
  return (
    <div className="grid min-h-svh place-items-center">
      <LatticeLoader label="Loading" cellSize={8} gap={3} fontSize={16} />
    </div>
  )
}

export default function App() {
  const { path } = useRoute()
  return (
    <Suspense fallback={<PageLoading />}>{path.startsWith("/dashboard") ? <DashboardPage /> : <LandingPage />}</Suspense>
  )
}
