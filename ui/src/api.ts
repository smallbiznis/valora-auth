export type APIError = {
  error?: string
  error_description?: string
}

export async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    credentials: 'include',
  })

  const payload = (await response.json().catch(() => ({}))) as T & APIError
  if (!response.ok) {
    const message =
      payload.error_description || payload.error || response.statusText
    throw new Error(message)
  }

  return payload as T
}
