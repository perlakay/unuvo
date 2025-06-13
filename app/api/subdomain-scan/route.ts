import { type NextRequest, NextResponse } from "next/server"

// Ultra-fast subdomain discovery - minimal checks, immediate results
async function discoverSubdomains(domain: string) {
  const results: any[] = []

  // Add main domain immediately
  results.push({
    subdomain: domain,
    status: "Main Domain",
    ip: "Primary",
    technologies: [],
  })

  // Common subdomains to check
  const commonSubdomains = [
    "www",
    "mail",
    "webmail",
    "api",
    "dev",
    "test",
    "staging",
    "blog",
    "shop",
    "support",
    "admin",
    "portal",
    "secure",
    "vpn",
    "remote",
    "cdn",
    "media",
    "static",
    "app",
    "m",
    "mobile",
    "beta",
    "ns1",
    "ns2",
    "mx",
  ]

  // Check common subdomains in parallel
  const promises = commonSubdomains.map(async (prefix) => {
    const subdomain = `${prefix}.${domain}`
    try {
      const response = await fetch(`https://dns.google/resolve?name=${subdomain}&type=A`, {
        signal: AbortSignal.timeout(1500), // Very short timeout
      })

      if (response.ok) {
        const data = await response.json()
        if (data.Answer && data.Answer.length > 0) {
          return {
            subdomain,
            status: "Found",
            ip: data.Answer[0].data,
            technologies: [],
          }
        }
      }
    } catch (error) {
      // Ignore errors for speed
    }
    return null
  })

  // Wait for all DNS lookups with a timeout
  const dnsResults = await Promise.allSettled(promises)
  for (const result of dnsResults) {
    if (result.status === "fulfilled" && result.value) {
      results.push(result.value)
    }
  }

  // Try to get certificate transparency data (but don't wait too long)
  try {
    const ctPromise = fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
      signal: AbortSignal.timeout(5000), // Short timeout
    })
      .then(async (response) => {
        if (response.ok) {
          const data = await response.json()
          // Only process a limited number of results
          const limitedData = data.slice(0, 20)

          for (const entry of limitedData) {
            const nameValue = entry.name_value || ""
            for (const subdomain of nameValue.split("\n")) {
              const cleanSubdomain = subdomain.trim().toLowerCase()
              const finalSubdomain = cleanSubdomain.replace(/^\*\./, "")

              if (
                (finalSubdomain.endsWith(`.${domain}`) || finalSubdomain === domain) &&
                !finalSubdomain.includes("*") &&
                !results.some((r) => r.subdomain === finalSubdomain)
              ) {
                results.push({
                  subdomain: finalSubdomain,
                  status: "Found (CT)",
                  ip: "Not Checked",
                  technologies: [],
                })
              }
            }
          }
        }
      })
      .catch(() => {
        // Ignore CT errors
      })

    // Only wait for 5 seconds max
    await Promise.race([ctPromise, new Promise((resolve) => setTimeout(resolve, 5000))])
  } catch (error) {
    // Ignore CT errors completely
  }

  return results
}

// Simple storage with automatic cleanup
const scanStore = new Map<
  string,
  {
    progress: number
    results: any[]
    completed: boolean
    error?: string
    timestamp: number
  }
>()

// Clean up old scans every 5 minutes
setInterval(
  () => {
    const now = Date.now()
    for (const [key, value] of scanStore.entries()) {
      // Remove entries older than 30 minutes
      if (now - value.timestamp > 30 * 60 * 1000) {
        scanStore.delete(key)
      }
    }
  },
  5 * 60 * 1000,
)

export async function POST(request: NextRequest) {
  try {
    const { url } = await request.json()

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    const domain = new URL(url).hostname
    const scanId = `${domain}-${Date.now()}`

    console.log(`Starting guaranteed-fast subdomain discovery for ${domain}`)

    // Set initial state
    scanStore.set(scanId, {
      progress: 0,
      results: [],
      completed: false,
      timestamp: Date.now(),
    })

    // Start discovery in background
    setTimeout(async () => {
      try {
        // Update to 10% immediately
        scanStore.set(scanId, {
          progress: 10,
          results: [{ subdomain: domain, status: "Main Domain", ip: "Primary" }],
          completed: false,
          timestamp: Date.now(),
        })

        // Start the actual scan
        const results = await discoverSubdomains(domain)

        // Update to 100% with results
        scanStore.set(scanId, {
          progress: 100,
          results,
          completed: true,
          timestamp: Date.now(),
        })

        console.log(`Discovery complete: ${results.length} subdomains`)
      } catch (error) {
        console.error("Discovery failed:", error)

        // Even on error, return what we have and mark as complete
        const currentState = scanStore.get(scanId)
        scanStore.set(scanId, {
          progress: 100,
          results: currentState?.results || [{ subdomain: domain, status: "Main Domain", ip: "Primary" }],
          completed: true,
          error: "Scan completed with some errors",
          timestamp: Date.now(),
        })
      }
    }, 0)

    // Simulate progress updates in the background
    let progress = 0
    const progressInterval = setInterval(() => {
      const scan = scanStore.get(scanId)
      if (!scan || scan.completed) {
        clearInterval(progressInterval)
        return
      }

      // Increment progress by 5-15% each time
      progress += Math.floor(Math.random() * 10) + 5
      if (progress > 95) progress = 95 // Never reach 100% until actually done

      scanStore.set(scanId, {
        ...scan,
        progress,
        timestamp: Date.now(),
      })
    }, 1000) // Update every second

    // Set a guaranteed completion timeout
    setTimeout(() => {
      const scan = scanStore.get(scanId)
      if (scan && !scan.completed) {
        console.log("Forcing scan completion after timeout")
        scanStore.set(scanId, {
          ...scan,
          progress: 100,
          completed: true,
          timestamp: Date.now(),
        })
        clearInterval(progressInterval)
      }
    }, 15000) // Force completion after 15 seconds max

    return NextResponse.json({
      success: true,
      scanId,
      message: "Guaranteed-fast subdomain discovery started",
    })
  } catch (error) {
    console.error("Failed to start scan:", error)
    return NextResponse.json({ error: "Failed to start scan" }, { status: 500 })
  }
}

export async function GET(request: NextRequest) {
  try {
    const url = new URL(request.url)
    const scanId = url.searchParams.get("scanId")

    if (!scanId) {
      return NextResponse.json({ error: "scanId required" }, { status: 400 })
    }

    const scanData = scanStore.get(scanId)
    if (!scanData) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 })
    }

    return NextResponse.json({
      success: true,
      progress: scanData.progress,
      results: scanData.results,
      completed: scanData.completed,
      error: scanData.error,
      total: scanData.results.length,
    })
  } catch (error) {
    return NextResponse.json({ error: "Failed to get status" }, { status: 500 })
  }
}
