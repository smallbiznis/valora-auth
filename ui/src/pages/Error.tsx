export default function ErrorPage() {
  const params = new URLSearchParams(window.location.search)
  const message =
    params.get('error_description') ||
    params.get('error') ||
    'Something went wrong.'

  return (
    <div className="min-h-screen bg-bg-primary text-text-primary">
      <div className="mx-auto flex min-h-screen w-full max-w-lg flex-col justify-center px-6 py-12">
        <div className="rounded-3xl border border-border-subtle bg-surface-primary/90 p-8 shadow-2xl shadow-black/20 backdrop-blur">
          <h1 className="text-2xl font-semibold">Error</h1>
          <p className="mt-3 text-sm text-text-muted">{message}</p>
          <a
            className="mt-6 inline-flex items-center rounded-xl border border-border-subtle px-4 py-2 text-sm text-text-primary transition hover:border-brand-primary"
            href="/login"
          >
            Back to login
          </a>
        </div>
      </div>
    </div>
  )
}
