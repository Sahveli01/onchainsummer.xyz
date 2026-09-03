/**
 * Best-effort, in-process sliding-window rate limiter for API routes.
 *
 * The Reservoir proxy spends the deployment's `RESERVOIR_API_KEY` quota on every
 * request it forwards, and an origin check cannot bound that: `Origin`, `Referer`
 * and `Host` are all supplied by the caller, so any non-browser client can present
 * whatever values the allowlist wants to see. A request budget is the only control
 * that applies to scripted callers as well as browsers.
 *
 * Limitation, stated plainly: the counters live in process memory, so each
 * serverless instance enforces its own budget and a horizontally scaled deployment
 * multiplies the effective limit by the instance count. A shared store (Redis,
 * Upstash, or the platform's own rate limiter) is the right home for a hard
 * guarantee. This is a floor, not a ceiling.
 */

/** Distinct client keys tracked before the table is pruned. */
const MAX_TRACKED_KEYS = 5_000

const buckets = new Map<string, number[]>()

/**
 * Derives a client key from proxy headers.
 *
 * These headers are attacker-controlled unless a trusted proxy overwrites them.
 * Vercel and most managed platforms do overwrite `x-forwarded-for`; behind
 * anything that does not, the limiter degrades to one shared bucket rather than
 * failing open per request.
 */
export const clientKey = (request: Request): string => {
  const forwardedFor = request.headers.get('x-forwarded-for')
  if (forwardedFor) {
    // The left-most entry is the original client as recorded by the first proxy.
    const first = forwardedFor.split(',')[0]?.trim()
    if (first) {
      return first
    }
  }
  return request.headers.get('x-real-ip')?.trim() || 'unknown'
}

/**
 * Records a request against `key` and reports whether it is within budget.
 *
 * @param key Client identifier, typically from {@link clientKey}.
 * @param maxRequests Requests permitted per window.
 * @param windowMs Window length in milliseconds.
 * @returns `true` when the request is within budget, `false` when it should be
 * rejected.
 */
export const withinRateLimit = (
  key: string,
  maxRequests: number,
  windowMs: number
): boolean => {
  const now = Date.now()
  const cutoff = now - windowMs

  if (buckets.size > MAX_TRACKED_KEYS) {
    // Unbounded growth is itself a denial-of-service vector, so keys whose entire
    // history has aged out are dropped before a new one is admitted. Deletions are
    // deferred into `stale` so the map is not mutated while it is walked.
    const stale: string[] = []
    buckets.forEach((timestamps, candidate) => {
      const live = timestamps.filter((timestamp) => timestamp > cutoff)
      if (live.length === 0) {
        stale.push(candidate)
      } else {
        buckets.set(candidate, live)
      }
    })
    stale.forEach((candidate) => buckets.delete(candidate))
  }

  const recent = (buckets.get(key) ?? []).filter(
    (timestamp) => timestamp > cutoff
  )
  if (recent.length >= maxRequests) {
    buckets.set(key, recent)
    return false
  }

  recent.push(now)
  buckets.set(key, recent)
  return true
}