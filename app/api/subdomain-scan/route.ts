import { type NextRequest, NextResponse } from "next/server"

// Fast subdomain discovery - no delays, parallel processing
async function discoverSubdomains(domain: string, progressCallback?: (progress: number, found: any[]) => void) {
  const results: any[] = []

  // Focused, high-value wordlist (top 50 most common)
  const subdomains = [
    "www",
    "mail",
    "webmail",
    "admin",
    "api",
    "dev",
    "test",
    "staging",
    "beta",
    "demo",
    "blog",
    "shop",
    "support",
    "ftp",
    "cpanel",
    "panel",
    "portal",
    "login",
    "secure",
    "cdn",
    "static",
    "assets",
    "media",
    "img",
    "m",
    "mobile",
    "app",
    "vpn",
    "remote",
    "email",
    "smtp",
    "pop",
    "imap",
    "ns",
    "ns1",
    "ns2",
    "dns",
    "mx",
    "exchange",
    "autodiscover",
    "sso",
    "auth",
    "oauth",
    "git",
    "jenkins",
    "ci",
    "build",
    "monitor",
    "status",
    "health",
    "backup",
    "old",
    "new",
  ]

  console.log(`Fast subdomain discovery for ${domain} - checking ${subdomains.length} subdomains`)

  if (progressCallback) progressCallback(5, results)

  // Phase 1: Fast parallel DNS resolution using Google DNS API
  const batchSize = 10 // Process 10 at a time
  for (let i = 0; i < subdomains.length; i += batchSize) {
    const batch = subdomains.slice(i, i + batchSize)

    const promises = batch.map(async (sub) => {
      const subdomain = `${sub}.${domain}`
      try {
        const response = await fetch(`https://dns.google/resolve?name=${subdomain}&type=A`, {
          signal: AbortSignal.timeout(3000),
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
        // DNS resolution failed - subdomain doesn't exist
      }
      return null
    })

    const batchResults = await Promise.allSettled(promises)
    const validResults = batchResults
      .filter((result) => result.status === "fulfilled" && result.value !== null)
      .map((result) => (result as PromiseFulfilledResult<any>).value)

    results.push(...validResults)

    // Update progress
    const progress = Math.min(60, 5 + Math.floor(((i + batchSize) / subdomains.length) * 55))
    if (progressCallback) {
      progressCallback(progress, [...results])
    }
  }

  // Phase 2: Quick Certificate Transparency check
  if (progressCallback) progressCallback(65, results)

  try {
    const ctResponse = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, { signal: AbortSignal.timeout(5000) })

    if (ctResponse.ok) {
      const ctData = await ctResponse.json()
      const foundSubdomains = new Set(results.map((r) => r.subdomain))

      // Only process first 30 CT results for speed
      for (const cert of ctData.slice(0, 30)) {
        if (cert.name_value) {
          const names = cert.name_value.split("\n")
          for (const name of names) {
            const cleanName = name.trim().toLowerCase()
            if (
              cleanName.endsWith(`.${domain}`) &&
              !cleanName.includes("*") &&
              !foundSubdomains.has(cleanName) &&
              cleanName !== domain
            ) {
              results.push({
                subdomain: cleanName,
                status: "Found (CT)",
                ip: "Unknown",
                technologies: [],
              })
              foundSubdomains.add(cleanName)
            }
          }
        }
      }
    }
  } catch (error) {
    console.log("CT check skipped")
  }

  // Phase 3: Quick HTTP verification (parallel, no delays)
  if (progressCallback) progressCallback(75, results)

  const verificationBatchSize = 15
  for (let i = 0; i < results.length; i += verificationBatchSize) {
    const batch = results.slice(i, i + verificationBatchSize)

    const verifyPromises = batch.map(async (result) => {
      try {
        // Quick HTTPS check
        const httpsResponse = await fetch(`https://${result.subdomain}`, {
          method: "HEAD",
          signal: AbortSignal.timeout(2000), // Very short timeout
        })

        if (httpsResponse.ok) {
          result.status = "Active (HTTPS)"
          result.technologies = getQuickTech(httpsResponse.headers)
          return result
        }
      } catch (httpsError) {
        // Try HTTP quickly
        try {
          const httpResponse = await fetch(`http://${result.subdomain}`, {
            method: "HEAD",
            signal: AbortSignal.timeout(2000),
          })

          if (httpResponse.ok) {
            result.status = "Active (HTTP)"
            result.technologies = getQuickTech(httpResponse.headers)
          } else {
            result.status = "DNS Only"
          }
        } catch (httpError) {
          result.status = "DNS Only"
        }
      }
      return result
    })

    await Promise.allSettled(verifyPromises)

    // Update progress
    const progress = Math.min(95, 75 + Math.floor(((i + verificationBatchSize) / results.length) * 20))
    if (progressCallback) {
      progressCallback(progress, [...results])
    }
  }

  if (progressCallback) progressCallback(100, results)
  console.log(`Fast discovery complete: ${results.length} subdomains found`)
  return results
}

// Quick technology detection
function getQuickTech(headers: Headers): string[] {
  const tech: string[] = []
  const server = headers.get("server")?.toLowerCase() || ""

  if (server.includes("nginx")) tech.push("nginx")
  if (server.includes("apache")) tech.push("apache")
  if (server.includes("cloudflare")) tech.push("cloudflare")
  if (headers.get("cf-ray")) tech.push("cloudflare")
  if (headers.get("x-powered-by")?.toLowerCase().includes("php")) tech.push("php")

  return tech
}

// Simple in-memory storage
const scanStore = new Map<
  string,
  {
    progress: number
    results: any[]
    completed: boolean
    error?: string
  }
>()

export async function POST(request: NextRequest) {
  try {
    const { url } = await request.json()

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    const domain = new URL(url).hostname
    const scanId = `${domain}-${Date.now()}`

    console.log(`Starting FAST subdomain scan for ${domain}`)

    // Initialize
    scanStore.set(scanId, {
      progress: 0,
      results: [],
      completed: false,
    })

    // Start fast discovery
    discoverSubdomains(domain, (progress, results) => {
      scanStore.set(scanId, {
        progress,
        results,
        completed: progress >= 100,
      })
    })
      .then((finalResults) => {
        scanStore.set(scanId, {
          progress: 100,
          results: finalResults,
          completed: true,
        })
        console.log(`FAST scan complete: ${finalResults.length} subdomains`)
      })
      .catch((error) => {
        console.error("Fast scan failed:", error)
        scanStore.set(scanId, {
          progress: 0,
          results: [],
          completed: true,
          error: error.message,
        })
      })

    return NextResponse.json({
      success: true,
      scanId,
      message: "Fast subdomain scan started",
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
    console.error("Failed to get scan status:", error)
    return NextResponse.json({ error: "Failed to get status" }, { status: 500 })
  }
}
