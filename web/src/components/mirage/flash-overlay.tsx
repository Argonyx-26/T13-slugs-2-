/** A red flash across the screen for each new HIGH incident (skipped for reduced motion). */
export function FlashOverlay({ pulse }: { pulse: number }) {
  if (!pulse) return null
  return <div key={pulse} aria-hidden="true" className="mirage-flash pointer-events-none fixed inset-0 z-50" />
}
