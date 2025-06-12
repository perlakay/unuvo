import { type NextRequest, NextResponse } from "next/server"

// Simple but effective subdomain discovery
async function discoverSubdomains(domain: string, progressCallback?: (progress: number, found: any[]) => void) {
  const results: any[] = []
  let progress = 0

  // High-value subdomain list based on real-world data
  const subdomains = [
    "www",
    "mail",
    "webmail",
    "email",
    "admin",
    "administrator",
    "panel",
    "cpanel",
    "api",
    "dev",
    "test",
    "staging",
    "beta",
    "demo",
    "blog",
    "shop",
    "store",
    "support",
    "help",
    "ftp",
    "sftp",
    "ssh",
    "vpn",
    "remote",
    "secure",
    "portal",
    "login",
    "auth",
    "sso",
    "cdn",
    "static",
    "assets",
    "media",
    "img",
    "images",
    "upload",
    "download",
    "files",
    "docs",
    "m",
    "mobile",
    "app",
    "apps",
    "status",
    "monitor",
    "health",
    "analytics",
    "stats",
    "db",
    "database",
    "backup",
    "old",
    "new",
    "v1",
    "v2",
    "us",
    "eu",
    "uk",
  ]

  console.log(`Starting subdomain discovery for ${domain}`)

  // Phase 1: DNS enumeration
  if (progressCallback) progressCallback(10, results)

  for (let i = 0; i < subdomains.length; i++) {
    const subdomain = `${subdomains[i]}.${domain}`

    try {
      // Try to resolve the subdomain
      const response = await fetch(`https://dns.google/resolve?name=${subdomain}&type=A`, {
        signal: AbortSignal.timeout(5000),
      })

      if (response.ok) {
        const data = await response.json()
        if (data.Answer && data.Answer.length > 0) {
          const ip = data.Answer[0].data
          results.push({
            subdomain,
            status: "Found",
            ip,
            technologies: [],
          })
          console.log(`Found subdomain: ${subdomain} -> ${ip}`)
        }
      }
    } catch (error) {
      // Subdomain doesn't exist
    }

    // Update progress
    const newProgress = 10 + Math.floor((i / subdomains.length) * 40)
    if (progressCallback && newProgress > progress) {
      progressCallback(newProgress, [...results])
      progress = newProgress
    }

    // Small delay to avoid rate limiting
    await new Promise((resolve) => setTimeout(resolve, 100))
  }

  // Phase 2: Certificate Transparency check
  if (progressCallback) progressCallback(60, results)

  try {
    console.log(`Checking Certificate Transparency for ${domain}`)
    const ctResponse = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
      signal: AbortSignal.timeout(10000),
    })

    if (ctResponse.ok) {
      const ctData = await ctResponse.json()
      const foundSubdomains = new Set(results.map((r) => r.subdomain))

      for (const cert of ctData.slice(0, 50)) {
        // Limit to first 50 results
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
              console.log(`Found subdomain from CT: ${cleanName}`)
            }
          }
        }
      }
    }
  } catch (error) {
    console.log("Certificate Transparency check failed:", error)
  }

  // Phase 3: Verify subdomains
  if (progressCallback) progressCallback(70, results)

  for (let i = 0; i < results.length; i++) {
    const result = results[i]
    try {
      // Try HTTPS first
      const httpsResponse = await fetch(`https://${result.subdomain}`, {
        method: "HEAD",
        signal: AbortSignal.timeout(5000),
      })

      if (httpsResponse.ok) {
        result.status = "Active (HTTPS)"
        result.technologies = detectTechnologies(httpsResponse.headers)
      }
    } catch (httpsError) {
      try {
        // Try HTTP
        const httpResponse = await fetch(`http://${result.subdomain}`, {
          method: "HEAD",
          signal: AbortSignal.timeout(5000),
        })

        if (httpResponse.ok) {
          result.status = "Active (HTTP)"
          result.technologies = detectTechnologies(httpResponse.headers)
        } else {
          result.status = "DNS Only"
        }
      } catch (httpError) {
        result.status = "DNS Only"
      }
    }

    // Update progress
    const newProgress = 70 + Math.floor(((i + 1) / results.length) * 25)
    if (progressCallback) {
      progressCallback(newProgress, [...results])
    }

    // Small delay
    await new Promise((resolve) => setTimeout(resolve, 200))
  }

  if (progressCallback) progressCallback(100, results)
  console.log(`Subdomain discovery complete. Found ${results.length} subdomains`)
  return results
}

function detectTechnologies(headers: Headers): string[] {
  const technologies: string[] = []

  const server = headers.get("server")
  if (server) {
    if (server.toLowerCase().includes("nginx")) technologies.push("nginx")
    if (server.toLowerCase().includes("apache")) technologies.push("apache")
    if (server.toLowerCase().includes("cloudflare")) technologies.push("cloudflare")
  }

  if (headers.get("cf-ray")) technologies.push("cloudflare")
  if (headers.get("x-powered-by")?.toLowerCase().includes("php")) technologies.push("php")

  return technologies
}

// In-memory storage for scan results
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

    console.log(`Starting subdomain scan for ${domain} with ID: ${scanId}`)

    // Initialize scan
    scanStore.set(scanId, {
      progress: 0,
      results: [],
      completed: false,
    })

    // Start the scan in background
    discoverSubdomains(domain, (progress, results) => {
      scanStore.set(scanId, {
        progress,
        results,
        completed: progress >= 100,
      })
      console.log(`Scan ${scanId} progress: ${progress}%, found: ${results.length}`)
    })
      .then((finalResults) => {
        scanStore.set(scanId, {
          progress: 100,
          results: finalResults,
          completed: true,
        })
        console.log(`Scan ${scanId} completed with ${finalResults.length} results`)
      })
      .catch((error) => {
        console.error(`Scan ${scanId} failed:`, error)
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
      message: "Subdomain scan started",
    })
  } catch (error) {
    console.error("Failed to start subdomain scan:", error)
    return NextResponse.json({ error: "Failed to start scan" }, { status: 500 })
  }
}

export async function GET(request: NextRequest) {
  try {
    const url = new URL(request.url)
    const scanId = url.searchParams.get("scanId")

    if (!scanId) {
      return NextResponse.json({ error: "scanId parameter required" }, { status: 400 })
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
    return NextResponse.json({ error: "Failed to get scan status" }, { status: 500 })
  }
}
