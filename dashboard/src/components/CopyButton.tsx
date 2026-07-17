import { useState } from 'react'

export function CopyButton({
  value,
  label = 'Copy request ID',
}: {
  value: string
  label?: string
}) {
  const [message, setMessage] = useState('')

  async function copy() {
    try {
      await navigator.clipboard.writeText(value)
      setMessage('Copied')
    } catch {
      setMessage('Copy failed')
    }
  }

  return (
    <span className="copy-control">
      <button
        className="icon-button"
        type="button"
        aria-label={label}
        title={label}
        onClick={copy}
      >
        Copy
      </button>
      <span className="sr-only" aria-live="polite">
        {message}
      </span>
    </span>
  )
}
