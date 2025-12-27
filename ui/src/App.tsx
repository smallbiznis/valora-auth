import ErrorPage from './pages/Error'
import Login from './pages/Login'

function App() {
  const path = window.location.pathname

  if (path === '/' || path === '/login') {
    return <Login />
  }

  if (path === '/error') {
    return <ErrorPage />
  }

  return (
    <div className="min-h-screen bg-bg-primary text-text-primary">
      <div className="mx-auto flex min-h-screen w-full max-w-lg flex-col justify-center px-6 py-12">
        <div className="rounded-3xl border border-border-subtle bg-surface-primary/90 p-8 shadow-2xl shadow-black/20 backdrop-blur">
          <h1 className="text-2xl font-semibold">Page not found</h1>
          <p className="mt-3 text-sm text-text-muted">
            The page you are looking for does not exist.
          </p>
          <a
            className="mt-6 inline-flex items-center rounded-xl border border-border-subtle px-4 py-2 text-sm text-text-primary transition hover:border-brand-primary"
            href="/login"
          >
            Go to login
          </a>
        </div>
      </div>
    </div>
  )
}

export default App
