import { createContext, useCallback, useContext, useEffect, useState, type AnchorHTMLAttributes, type ReactNode } from "react"

// Two pages don't need a router library: the History API is enough.
interface RouterValue {
  path: string
  navigate: (to: string) => void
}

const RouterContext = createContext<RouterValue>({ path: "/", navigate: () => {} })

export function RouterProvider({ children }: { children: ReactNode }) {
  const [path, setPath] = useState(() => window.location.pathname)

  useEffect(() => {
    const onPop = () => setPath(window.location.pathname)
    window.addEventListener("popstate", onPop)
    return () => window.removeEventListener("popstate", onPop)
  }, [])

  const navigate = useCallback((to: string) => {
    if (to !== window.location.pathname) {
      window.history.pushState({}, "", to)
      setPath(to)
    }
    window.scrollTo({ top: 0 })
  }, [])

  return <RouterContext.Provider value={{ path, navigate }}>{children}</RouterContext.Provider>
}

// eslint-disable-next-line react-refresh/only-export-components
export const useRoute = () => useContext(RouterContext)

/** An <a> that switches pages without a reload (modifier-clicks still open a new tab). */
export function Link({ href = "/", onClick, ...props }: AnchorHTMLAttributes<HTMLAnchorElement>) {
  const { navigate } = useRoute()
  return (
    <a
      href={href}
      onClick={(event) => {
        onClick?.(event)
        if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return
        event.preventDefault()
        navigate(href)
      }}
      {...props}
    />
  )
}
