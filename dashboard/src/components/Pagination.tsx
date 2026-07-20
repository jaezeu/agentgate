export function Pagination({
  offset,
  limit,
  count,
  hasMore,
  onPage,
}: {
  offset: number
  limit: number
  count: number
  hasMore: boolean
  onPage(offset: number): void
}) {
  const start = offset + 1
  const end = offset + count

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
        {count === 0
          ? 'No results on this page'
          : `Showing positions ${start}-${end}`}
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
