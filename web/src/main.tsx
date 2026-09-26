import { StrictMode } from "react"
import { createRoot } from "react-dom/client"

import "./index.css"
import App from "./App.tsx"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import { RouterProvider } from "@/hooks/use-route"

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RouterProvider>
      <TooltipProvider delayDuration={150}>
        <App />
        <Toaster theme="dark" position="top-center" richColors closeButton />
      </TooltipProvider>
    </RouterProvider>
  </StrictMode>
)
