// The lists the sidebar counts and the list screens show: loaded once, reloaded after a change.
import { createContext, useContext, type ReactNode } from 'react'
import { useApp, useLoad } from './context'
import type { Descriptor, VariableDescriptor } from './lib/types'

interface Lists {
  secrets: ReturnType<typeof useLoad<Descriptor[]>>
  variables: ReturnType<typeof useLoad<VariableDescriptor[]>>
}

const ListsContext = createContext<Lists | null>(null)

export function ListsProvider({ children }: { children: ReactNode }) {
  const { api } = useApp()
  const secrets = useLoad(() => api.get<Descriptor[]>('/v1/secrets').then((r) => r.data), [api])
  const variables = useLoad(() => api.get<VariableDescriptor[]>('/v1/variables').then((r) => r.data), [api])
  return <ListsContext.Provider value={{ secrets, variables }}>{children}</ListsContext.Provider>
}

export function useLists(): Lists {
  const l = useContext(ListsContext)
  if (!l) throw new Error('outside the lists')
  return l
}
