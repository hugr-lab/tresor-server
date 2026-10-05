// The console's routes, inside its frame.
import { Navigate, Route, Routes } from 'react-router-dom'
import { useLists, ListsProvider } from './lists'
import { Shell } from './components/Shell'
import { Secrets } from './screens/Secrets'
import { SecretDetail } from './screens/SecretDetail'
import { SecretEditor } from './screens/SecretEditor'
import { VariableEditor, Variables } from './screens/Variables'
import { Access, RefsCheck, Service } from './screens/Admin'

function Framed() {
  const { secrets, variables } = useLists()
  return (
    <Shell counts={{ secrets: secrets.data?.length, variables: variables.data?.length }}>
      <Routes>
        <Route path="/secrets" element={<Secrets />} />
        <Route path="/secrets/new" element={<SecretEditor mode="create" />} />
        <Route path="/secrets/:name" element={<SecretDetail />} />
        <Route path="/secrets/:name/edit" element={<SecretEditor mode="replace" />} />
        <Route path="/variables" element={<Variables />} />
        <Route path="/variables/new" element={<VariableEditor mode="create" />} />
        <Route path="/variables/:name" element={<Variables />} />
        <Route path="/variables/:name/edit" element={<VariableEditor mode="replace" />} />
        <Route path="/access" element={<Access />} />
        <Route path="/refs" element={<RefsCheck />} />
        <Route path="/service" element={<Service />} />
        <Route path="*" element={<Navigate to="/secrets" replace />} />
      </Routes>
    </Shell>
  )
}

export function App() {
  return (
    <ListsProvider>
      <Framed />
    </ListsProvider>
  )
}
