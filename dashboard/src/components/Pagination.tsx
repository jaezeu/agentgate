export function Pagination({
  offset,
  limit,
  hasMore,
  onPage,
}: {
  offset: number
  limit: number
  hasMore: boolean
  onPage(offset: number): void
}) {
  const start = offset + 1
  const end = offset + limit

  return (
    <nav className="pagination" aria-label="Results pages">
      <button
        className="button"
        type="button"
        disabled={offset === 0}
        onClick={() => onPage(Math.max(0, offset - limit))}
      >
        Previous
      </button>
      <span aria-live="polite">
        Showing positions {start}-{end}
      </span>
      <button
        className="button"
        type="button"
        disabled={!hasMore}
        onClick={() => onPage(offset + limit)}
      >
        Next
      </button>
    </nav>
  )
}
