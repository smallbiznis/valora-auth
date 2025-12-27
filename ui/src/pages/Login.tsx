import { useMemo, useState } from 'react'
import { postJSON } from '../api'

type LoginResponse = {
  access_token: string
  refresh_token?: string
  token_type: string
  expires_in: number
}

function resolveClientId(): string | null {
  const params = new URLSearchParams(window.location.search)
  const direct = params.get('client_id')
  if (direct) {
    return direct
  }
  const returnTo = params.get('return_to')
  if (!returnTo) {
    return null
  }
  try {
    const url = new URL(returnTo, window.location.origin)
    return url.searchParams.get('client_id')
  } catch {
    return null
  }
}

function resolveReturnTo(): string {
  const params = new URLSearchParams(window.location.search)
  return params.get('return_to') || '/'
}

export default function Login() {
  const clientId = useMemo(() => resolveClientId(), [])
  const returnTo = useMemo(() => resolveReturnTo(), [])

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)

    if (!clientId) {
      setError('Missing client_id. Please retry from the OAuth authorize flow.')
      return
    }

    setSubmitting(true)
    try {
      // UI never stores tokens; the backend sets HttpOnly session cookies.
      await postJSON<LoginResponse>('/auth/password/login', {
        email,
        password,
        client_id: clientId,
        scope: 'openid email profile',
      })
      window.location.href = returnTo
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-bg-primary via-bg-primary to-bg-secondary text-text-primary">
      <div className="mx-auto flex min-h-screen w-full max-w-lg flex-col justify-center px-6 py-12">
        <div className="rounded-3xl border border-border-subtle bg-surface-primary/90 p-8 shadow-2xl shadow-black/20 backdrop-blur">
          <div className="space-y-2">
            <h1 className="text-3xl font-semibold tracking-tight">Sign in</h1>
            <p className="text-sm text-text-muted">
              Use your Valora Cloud credentials to continue.
            </p>
          </div>

          <form className="mt-8 space-y-4" onSubmit={onSubmit}>
            <label className="block space-y-2 text-sm">
              <span className="text-text-muted">Email</span>
              <input
                className="w-full rounded-xl border border-border-subtle bg-bg-primary px-4 py-3 text-base outline-none ring-0 transition focus:border-brand-primary focus:ring-2 focus:ring-brand-primary/40"
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(event) => setEmail(event.target.value)}
              />
            </label>

            <label className="block space-y-2 text-sm">
              <span className="text-text-muted">Password</span>
              <input
                className="w-full rounded-xl border border-border-subtle bg-bg-primary px-4 py-3 text-base outline-none ring-0 transition focus:border-brand-primary focus:ring-2 focus:ring-brand-primary/40"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </label>

            {error ? (
              <div className="rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200">
                {error}
              </div>
            ) : null}

            <button
              className="w-full rounded-xl bg-brand-primary px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-brand-primary/30 transition hover:bg-brand-primary/90 disabled:cursor-not-allowed disabled:opacity-70"
              type="submit"
              disabled={submitting}
            >
              {submitting ? 'Signing in...' : 'Sign in'}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
