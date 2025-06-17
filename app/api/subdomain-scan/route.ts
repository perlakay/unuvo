import { type NextRequest, NextResponse } from "next/server"

// Real subdomain discovery with actual verification
async function discoverSubdomains(domain: string, progressCallback?: (progress: number, found: any[]) => void) {
  const results: any[] = []

  // Add main domain immediately
  results.push({
    subdomain: domain,
    status: "Main Domain",
    ip: "Primary",
    technologies: [],
  })

  if (progressCallback) progressCallback(10, [...results])

  // Common subdomains to actually check
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

  console.log(`Starting real DNS verification for ${domain}`)

  // PHASE 1: Real DNS verification
  const verifiedSubdomains: any[] = []

  for (let i = 0; i < commonSubdomains.length; i++) {
    const prefix = commonSubdomains[i]
    const subdomain = `${prefix}.${domain}`

    try {
      // Use Google's DNS-over-HTTPS API for real verification
      const response = await fetch(`https://dns.google/resolve?name=${subdomain}&type=A`, {
        signal: AbortSignal.timeout(3000),
      })

      if (response.ok) {
        const data = await response.json()
        if (data.Answer && data.Answer.length > 0) {
          const ip = data.Answer[0].data
          verifiedSubdomains.push({
            subdomain,
            status: "Active (DNS)",
            ip: ip,
            technologies: [],
          })
          console.log(`✓ Found active subdomain: ${subdomain} -> ${ip}`)
        }
      }
    } catch (error) {
      // DNS lookup failed - subdomain doesn't exist
      console.log(`✗ No DNS record for: ${subdomain}`)
    }

    // Update progress
    const progress = 10 + Math.floor((i / commonSubdomains.length) * 40)
    if (progressCallback) progressCallback(progress, [...results, ...verifiedSubdomains])

    // Small delay to avoid rate limiting
    await new Promise((resolve) => setTimeout(resolve, 100))
  }

  // Add verified subdomains to results
  results.push(...verifiedSubdomains)

  if (progressCallback) progressCallback(60, [...results])

  // PHASE 2: Certificate Transparency check (for additional discovery)
  try {
    console.log(`Checking certificate transparency for ${domain}`)
    const ctResponse = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
      signal: AbortSignal.timeout(8000),
    })

    if (ctResponse.ok) {
      const ctData = await ctResponse.json()
      console.log(`Found ${ctData.length} certificate entries`)

      const ctSubdomains = new Set<string>()

      // Process certificate data
      for (const entry of ctData.slice(0, 50)) {
        // Limit to first 50 entries
        const nameValue = entry.name_value || ""
        for (const name of nameValue.split("\n")) {
          const cleanName = name.trim().toLowerCase()
          const finalName = cleanName.replace(/^\*\./, "")

          if (
            (finalName.endsWith(`.${domain}`) || finalName === domain) &&
            !finalName.includes("*") &&
            !results.some((r) => r.subdomain === finalName) &&
            finalName !== domain // Don't duplicate main domain
          ) {
            ctSubdomains.add(finalName)
          }
        }
      }

      // Verify CT-discovered subdomains
      const ctArray = Array.from(ctSubdomains).slice(0, 10) // Limit verification
      for (let i = 0; i < ctArray.length; i++) {
        const subdomain = ctArray[i]

        try {
          const response = await fetch(`https://dns.google/resolve?name=${subdomain}&type=A`, {
            signal: AbortSignal.timeout(2000),
          })

          if (response.ok) {
            const data = await response.json()
            if (data.Answer && data.Answer.length > 0) {
              results.push({
                subdomain,
                status: "Active (CT)",
                ip: data.Answer[0].data,
                technologies: [],
              })
              console.log(`✓ Verified CT subdomain: ${subdomain}`)
            } else {
              // Found in CT but no current DNS record
              results.push({
                subdomain,
                status: "Found in CT (No DNS)",
                ip: "No current record",
                technologies: [],
              })
              console.log(`⚠ CT subdomain without DNS: ${subdomain}`)
            }
          }
        } catch (error) {
          // CT subdomain verification failed
          console.log(`✗ CT subdomain verification failed: ${subdomain}`)
        }

        // Update progress
        const progress = 60 + Math.floor((i / ctArray.length) * 35)
        if (progressCallback) progressCallback(progress, [...results])

        await new Promise((resolve) => setTimeout(resolve, 200))
      }
    }
  } catch (error) {
    console.log("Certificate transparency check failed:", error)
  }

  if (progressCallback) progressCallback(100, results)

  console.log(`Real subdomain discovery complete: ${results.length} total results`)
  console.log(`Active subdomains found: ${results.filter((r) => r.status.includes("Active")).length}`)

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

    console.log(`Starting REAL subdomain discovery for ${domain}`)

    // Set initial state
    scanStore.set(scanId, {
      progress: 0,
      results: [],
      completed: false,
      timestamp: Date.now(),
    })

    // Start real discovery in background
    setTimeout(async () => {
      try {
        const results = await discoverSubdomains(domain, (progress, currentResults) => {
          scanStore.set(scanId, {
            progress,
            results: currentResults,
            completed: progress >= 100,
            timestamp: Date.now(),
          })
        })

        // Final update
        scanStore.set(scanId, {
          progress: 100,
          results,
          completed: true,
          timestamp: Date.now(),
        })

        console.log(`Real discovery complete: ${results.length} subdomains found`)
      } catch (error) {
        console.error("Real discovery failed:", error)
        const currentState = scanStore.get(scanId)
        scanStore.set(scanId, {
          progress: 100,
          results: currentState?.results || [{ subdomain: domain, status: "Main Domain", ip: "Primary" }],
          completed: true,
          error: "Scan completed with errors",
          timestamp: Date.now(),
        })
      }
    }, 0)

    // Guaranteed completion timeout (30 seconds for real scanning)
    setTimeout(() => {
      const scan = scanStore.get(scanId)
      if (scan && !scan.completed) {
        console.log("Forcing scan completion after 30 second timeout")
        scanStore.set(scanId, {
          ...scan,
          progress: 100,
          completed: true,
          timestamp: Date.now(),
        })
      }
    }, 30000)

    return NextResponse.json({
      success: true,
      scanId,
      message: "Real subdomain discovery started",
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
