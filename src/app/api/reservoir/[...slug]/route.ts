import { NextResponse } from 'next/server'
import { clientKey, withinRateLimit } from '@/utils/apiRateLimit'

// A proxy API endpoint to redirect all requests to `/api/reservoir/*` to
// https://api-base.reservoir.tools/{endpoint}/{query-string}
// and attach the `x-api-key` header to the request. This way the
// Reservoir API key is not exposed to the client.
//
// Five defects were fixed here:
//
// 1. **Fails open when unconfigured.** `allowedDomains` was `null` whenever
//    `ALLOWED_API_DOMAINS` was unset, and the origin check was wrapped in
//    `if (allowedDomains && ...)`. With no configuration the endpoint was an open,
//    authenticated proxy: any site on the internet could spend this deployment's
//    `RESERVOIR_API_KEY` quota. It now defaults to same-origin.
//
// 2. **Home-grown host parsing.** Origins were reduced with
//    `/^(?:https?:\/\/)?(?:www\d?\.)?(.[^/]+)/i`, which keeps userinfo and ports,
//    strips a `www.` prefix from both sides of the comparison, and accepts a bare
//    host with no scheme. Comparison is now against the exact WHATWG origin.
//
// 3. **Upstream bytes served as HTML from this origin.** An `image/*` response was
//    returned with `content-type: text/html`, which turns any upstream-hosted
//    payload into stored XSS on this site's own origin. The upstream media type is
//    now echoed, restricted to an image allowlist, with `nosniff`.
//
// 4. **Corrupted image bodies.** `Buffer.from(data)` was handed the result of
//    `response.text()`, so binary bodies were UTF-8 decoded and re-encoded. Binary
//    responses are now read with `arrayBuffer()`.
//
// 5. **Upstream error bodies echoed to the client.** `throw data` followed by
//    `NextResponse.json(error, { status: 400 })` returned the upstream payload
//    verbatim and collapsed every failure to 400. Errors are now logged
//    server-side and answered with a generic body and the upstream status.

const UPSTREAM_ORIGIN = 'https://api-base.reservoir.tools'

/** Request budget per client, per window, for this proxy. */
const RATE_LIMIT_MAX_REQUESTS = 120
const RATE_LIMIT_WINDOW_MS = 60_000

/** Upper bound on the path depth forwarded upstream. */
const MAX_SLUG_SEGMENTS = 12

/**
 * Media types that may be returned to the browser with the upstream's own
 * `content-type`. Anything outside this set is served as an opaque download so a
 * document can never be rendered on this origin.
 */
const PASSTHROUGH_MEDIA_TYPES = [
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'image/avif',
]

/** Request headers forwarded to the upstream API unchanged. */
const FORWARDED_HEADERS = ['x-rkc-version', 'x-rkui-version']

/**
 * Normalises one `ALLOWED_API_DOMAINS` entry to a WHATWG origin.
 *
 * Entries may be written as `example.com`, `https://example.com` or
 * `https://example.com/path`; all three yield `https://example.com`. An entry that
 * cannot be parsed is dropped rather than being treated as a literal host, so a
 * typo cannot silently widen the allowlist.
 */
const toOrigin = (entry: string): string | null => {
  const trimmed = entry.trim()
  if (!trimmed) {
    return null
  }

  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  try {
    return new URL(candidate).origin
  } catch {
    return null
  }
}

const allowedOrigins = (process.env.ALLOWED_API_DOMAINS ?? '')
  .split(',')
  .map(toOrigin)
  .filter((origin): origin is string => origin !== null)

/**
 * Decides whether a request's browser origin may use this proxy.
 *
 * Honest statement of what this can and cannot do: `Origin`, `Referer` and `Host`
 * are all supplied by the caller. Checking them stops a *browser* on an unrelated
 * site from spending this deployment's API quota, because browsers set `Origin`
 * themselves and will not let page script forge it. It does not stop a scripted
 * client, which can send any header it likes — {@link withinRateLimit} is the
 * control that applies there.
 *
 * With `ALLOWED_API_DOMAINS` set, only those origins pass. With it unset the proxy
 * is same-origin: a request carrying no `Origin` header (same-origin fetch,
 * server-side render, or a non-browser client) passes, and a cross-origin request
 * is rejected. The previous behaviour with no configuration was to allow
 * everything.
 */
const isOriginAllowed = (req: Request): boolean => {
  const origin = req.headers.get('origin')

  if (!origin) {
    // Not a cross-origin browser request. Same-origin `fetch` from this app omits
    // the header, as do server-to-server callers.
    return true
  }

  let requestOrigin: string
  try {
    requestOrigin = new URL(origin).origin
  } catch {
    return false
  }

  if (allowedOrigins.length > 0) {
    return allowedOrigins.includes(requestOrigin)
  }

  // Unconfigured: compare against the host this request was addressed to.
  const host = req.headers.get('host')
  if (!host) {
    return false
  }
  const forwardedProto = req.headers.get('x-forwarded-proto')?.split(',')[0]?.trim()
  const scheme = forwardedProto === 'http' || forwardedProto === 'https' ? forwardedProto : 'https'
  try {
    return new URL(`${scheme}://${host}`).origin === requestOrigin
  } catch {
    return false
  }
}

/**
 * Builds the upstream path from the catch-all slug.
 *
 * Segments are bounded in number and rejected if they contain a path separator, a
 * dot-segment, or a character that would terminate the path — `?` or `#` would let
 * a caller append query parameters or a fragment to the upstream URL. Segments that
 * pass are joined verbatim: Next.js has already percent-decoded them, and
 * re-encoding would corrupt endpoints whose paths legitimately contain reserved
 * characters.
 */
const resolveEndpoint = (slug: string | string[]): string | null => {
  const segments = typeof slug === 'string' ? [slug] : slug ?? []

  if (segments.length === 0 || segments.length > MAX_SLUG_SEGMENTS) {
    return null
  }

  for (const segment of segments) {
    if (
      typeof segment !== 'string' ||
      segment.length === 0 ||
      segment === '.' ||
      segment === '..' ||
      segment.includes('/') ||
      segment.includes('\\') ||
      segment.includes('?') ||
      segment.includes('#')
    ) {
      return null
    }
  }

  return segments.join('/')
}

const proxy = async (
  req: Request,
  { params }: { params: { slug: string | string[] } }
) => {
  const { method, headers: reqHeaders } = req

  if (!isOriginAllowed(req)) {
    return NextResponse.json({ error: 'Access forbidden' }, { status: 403 })
  }

  if (
    !withinRateLimit(clientKey(req), RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MS)
  ) {
    return NextResponse.json(
      { error: 'Too many requests' },
      { status: 429, headers: { 'retry-after': '60' } }
    )
  }

  const endpoint = resolveEndpoint(params.slug)
  if (endpoint === null) {
    return NextResponse.json({ error: 'Invalid endpoint' }, { status: 400 })
  }

  const url = new URL(`${UPSTREAM_ORIGIN}/${endpoint}`)

  // Preserved from the original implementation: the `redirect/` family is answered
  // with a redirect to the upstream URL rather than being proxied, and the query
  // string is deliberately not carried over.
  if (endpoint.includes('redirect/')) {
    return NextResponse.redirect(url.href)
  }

  const searchParams = new URL(req.url).searchParams
  searchParams.forEach((value, key) => {
    url.searchParams.append(key, value)
  })

  try {
    const headers = new Headers({
      Referrer:
        reqHeaders.get('origin') ||
        reqHeaders.get('referer') ||
        reqHeaders.get('host') ||
        '',
    })

    if (process.env.RESERVOIR_API_KEY) {
      headers.set('x-api-key', process.env.RESERVOIR_API_KEY)
    }

    FORWARDED_HEADERS.forEach((name) => {
      const value = reqHeaders.get(name)
      if (value) {
        headers.set(name, value)
      }
    })

    const options: RequestInit = { method, headers }

    if (method !== 'GET' && method !== 'HEAD') {
      // Read the body as text and forward it unchanged. The previous
      // implementation called `req.json()`, which rejected any non-JSON body and
      // surfaced the parse failure as a 400 carrying the parser's message.
      const rawBody = await req.text()
      if (rawBody.length > 0) {
        headers.set('Content-Type', reqHeaders.get('content-type') ?? 'application/json')
        options.body = rawBody
      }
    }

    const response = await fetch(url.href, options)
    const contentType = response.headers.get('content-type') ?? ''

    if (!response.ok) {
      // The upstream body is logged, never returned: it carries request
      // identifiers and upstream diagnostics, and echoing it also let a caller
      // distinguish upstream failure modes. The status is preserved so clients can
      // still retry sensibly, instead of every failure becoming a 400.
      const detail = await response.text().catch(() => '')
      console.error(
        `Reservoir proxy upstream error ${response.status} for /${endpoint}: ${detail.slice(0, 512)}`
      )
      return NextResponse.json(
        { error: 'Upstream request failed' },
        { status: response.status >= 400 && response.status <= 599 ? response.status : 502 }
      )
    }

    if (contentType.includes('application/json')) {
      return NextResponse.json(await response.json())
    }

    // Binary and non-JSON bodies. Read as bytes — decoding through `text()` and
    // re-encoding, as the previous implementation did, corrupts every byte outside
    // ASCII — and never relabel the payload as a document.
    const mediaType = contentType.split(';')[0]?.trim().toLowerCase() ?? ''
    const isPassthrough = PASSTHROUGH_MEDIA_TYPES.includes(mediaType)

    return new NextResponse(await response.arrayBuffer(), {
      status: 200,
      headers: {
        'content-type': isPassthrough ? mediaType : 'application/octet-stream',
        // Defence in depth: without `nosniff` a browser may still sniff a
        // mislabelled body back into HTML and execute it on this origin.
        'x-content-type-options': 'nosniff',
        'content-disposition': isPassthrough ? 'inline' : 'attachment',
      },
    })
  } catch (error) {
    console.error(`Reservoir proxy request failed for /${endpoint}:`, error)
    return NextResponse.json({ error: 'Upstream request failed' }, { status: 502 })
  }
}

export const GET = proxy
export const POST = proxy
export const PUT = proxy
