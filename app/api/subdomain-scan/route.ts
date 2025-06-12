import { type NextRequest, NextResponse } from "next/server"
import dns from "dns"
import { promisify } from "util"

const dnsLookup = promisify(dns.lookup)
const dnsResolve = promisify(dns.resolve)

// Optimized subdomain discovery with focused wordlist
async function discoverSubdomains(domain: string, progressCallback?: (progress: number, found: any[]) => void) {
  const subdomains = new Set<string>()
  const results: any[] = []
  let discoveryProgress = 0

  // Add the main domain
  subdomains.add(domain)

  // Focused high-value subdomain wordlist (top 100 most common)
  const commonPrefixes = [
    // Essential web services
    "www",
    "mail",
    "webmail",
    "email",
    "smtp",
    "pop",
    "imap",
    "mx",
    "exchange",
    "autodiscover",

    // Admin and management
    "admin",
    "administrator",
    "panel",
    "cpanel",
    "control",
    "dashboard",
    "portal",
    "login",
    "auth",
    "sso",

    // Development environments
    "dev",
    "test",
    "stage",
    "staging",
    "uat",
    "demo",
    "beta",
    "alpha",
    "preview",
    "sandbox",

    // API and services
    "api",
    "api1",
    "api2",
    "api-v1",
    "api-v2",
    "rest",
    "graphql",
    "service",
    "services",
    "ws",

    // Content delivery
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

    // Mobile and apps
    "m",
    "mobile",
    "app",
    "apps",
    "touch",
    "wap",

    // Business functions
    "blog",
    "news",
    "shop",
    "store",
    "support",
    "help",
    "faq",
    "wiki",

    // Infrastructure
    "ftp",
    "sftp",
    "ssh",
    "vpn",
    "remote",
    "proxy",
    "gateway",
    "lb",
    "cache",

    // Monitoring and tools
    "monitor",
    "status",
    "health",
    "metrics",
    "analytics",
    "stats",
    "log",
    "logs",

    // Regional/versioning
    "us",
    "eu",
    "uk",
    "de",
    "fr",
    "ca",
    "au",
    "v1",
    "v2",
    "old",
    "new",

    // Database and backend
    "db",
    "database",
    "sql",
    "redis",
    "search",
    "backup",

    // Security
    "secure",
    "ssl",
    "cert",
    "firewall",
    "security",

    // Additional common ones
    "www2",
    "mail2",
    "ns",
    "ns1",
    "ns2",
    "dns",
    "git",
    "jenkins",
    "ci",
    "build",
  ]

  // Update progress
  if (progressCallback) {
    progressCallback(5, results)
    discoveryProgress = 5
  }

  // Phase 1: Fast DNS enumeration
  console.log(`Starting DNS enumeration for ${domain} with ${commonPrefixes.length} prefixes`)
  const batchSize = 25 // Smaller batches for better progress updates
  for (let i = 0; i < commonPrefixes.length; i += batchSize) {
    const batch = commonPrefixes.slice(i, i + batchSize)

    const dnsPromises = batch.map(async (prefix) => {
      const subdomain = `${prefix}.${domain}`
      try {
        await dnsLookup(subdomain)
        subdomains.add(subdomain)
        return subdomain
      } catch (error) {
        return null
      }
    })

    await Promise.allSettled(dnsPromises)

    // Update progress more frequently
    const newProgress = Math.min(50, 5 + Math.floor((i / commonPrefixes.length) * 45))
    if (newProgress > discoveryProgress && progressCallback) {
      progressCallback(
        newProgress,
        Array.from(subdomains).map((s) => ({ subdomain: s, status: "Found" })),
      )
      discoveryProgress = newProgress
    }
  }

  // Phase 2: Certificate Transparency (with timeout)
  console.log(`Checking Certificate Transparency logs for ${domain}`)
  if (progressCallback) {
    progressCallback(
      55,
      Array.from(subdomains).map((s) => ({ subdomain: s, status: "Found" })),
    )
  }

  try {
    const ctResponse = await fetch(`https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`, {
      signal: AbortSignal.timeout(8000), // Reduced timeout
    })

    if (ctResponse.ok) {
      const ctData = await ctResponse.json()
      // Limit CT results to prevent slowdown
      const limitedData = ctData.slice(0, 100)

      for (const cert of limitedData) {
        if (cert.name_value) {
          const names = cert.name_value.split("\n")
          for (const name of names) {
            const cleanName = name.trim().toLowerCase()
            if (cleanName.endsWith(`.${domain}`) && !cleanName.includes("*") && cleanName !== domain) {
              subdomains.add(cleanName)
            }
          }
        }
      }
    }
  } catch (error) {
    console.log("CT log check skipped due to timeout")
  }

  // Phase 3: Quick DNS record check
  if (progressCallback) {
    progressCallback(
      65,
      Array.from(subdomains).map((s) => ({ subdomain: s, status: "Found" })),
    )
  }

  try {
    const [mxRecords, nsRecords] = await Promise.allSettled([dnsResolve(domain, "MX"), dnsResolve(domain, "NS")])

    if (mxRecords.status === "fulfilled") {
      for (const record of mxRecords.value) {
        if (record.exchange && record.exchange.endsWith(`.${domain}`)) {
          subdomains.add(record.exchange)
        }
      }
    }

    if (nsRecords.status === "fulfilled") {
      for (const record of nsRecords.value) {
        if (record.endsWith(`.${domain}`)) {
          subdomains.add(record)
        }
      }
    }
  } catch (error) {
    console.log("DNS record check failed")
  }

  // Phase 4: Fast verification (parallel with smaller timeout)
  console.log(`Verifying ${subdomains.size} discovered subdomains`)
  if (progressCallback) {
    progressCallback(
      70,
      Array.from(subdomains).map((s) => ({ subdomain: s, status: "Verifying" })),
    )
  }

  const subdomainArray = Array.from(subdomains)
  const verificationBatchSize = 10 // Process in smaller parallel batches

  for (let i = 0; i < subdomainArray.length; i += verificationBatchSize) {
    const batch = subdomainArray.slice(i, i + verificationBatchSize)

    const verificationPromises = batch.map(async (subdomain) => {
      try {
        let status = "Inactive"
        let technologies: string[] = []

        // Quick HTTPS check with short timeout
        try {
          const response = await fetch(`https://${subdomain}`, {
            method: "HEAD",
            signal: AbortSignal.timeout(3000), // Very short timeout
          })
          if (response.ok) {
            status = "Active (HTTPS)"
            technologies = detectTechnologies(response.headers)
          }
        } catch (httpsError) {
          // Quick HTTP fallback
          try {
            const response = await fetch(`http://${subdomain}`, {
              method: "HEAD",
              signal: AbortSignal.timeout(3000),
            })
            if (response.ok) {
              status = "Active (HTTP)"
              technologies = detectTechnologies(response.headers)
            }
          } catch (httpError) {
            // Just mark as DNS-only if it resolved earlier
            status = "DNS Only"
          }
        }

        return {
          subdomain,
          status,
          ip: await getIpAddress(subdomain),
          technologies,
        }
      } catch (error) {
        return {
          subdomain,
          status: "Error",
          ip: "Unknown",
          technologies: [],
        }
      }
    })

    const batchResults = await Promise.allSettled(verificationPromises)
    const validResults = batchResults
      .filter((result) => result.status === "fulfilled")
      .map((result) => (result as PromiseFulfilledResult<any>).value)

    results.push(...validResults)

    // Update progress
    const newProgress = Math.min(95, 70 + Math.floor(((i + batch.length) / subdomainArray.length) * 25))
    if (progressCallback) {
      progressCallback(newProgress, [...results])
    }
  }

  // Final progress update
  if (progressCallback) {
    progressCallback(100, results)
  }

  console.log(`Subdomain discovery complete. Found ${results.length} subdomains for ${domain}`)
  return results
}

// Helper function to get IP address (with timeout)
async function getIpAddress(hostname: string) {
  try {
    const { address } = await dnsLookup(hostname)
    return address
  } catch (error) {
    return "Unknown"
  }
}

// Simplified technology detection
function detectTechnologies(headers: Headers) {
  const technologies: string[] = []

  const server = headers.get("server")
  if (server) {
    const serverLower = server.toLowerCase()
    if (serverLower.includes("nginx")) technologies.push("nginx")
    if (serverLower.includes("apache")) technologies.push("apache")
    if (serverLower.includes("cloudflare")) technologies.push("cloudflare")
  }

  if (headers.get("cf-ray")) technologies.push("cloudflare")
  if (headers.get("x-fastly-request-id")) technologies.push("fastly")

  const poweredBy = headers.get("x-powered-by")
  if (poweredBy) {
    const poweredByLower = poweredBy.toLowerCase()
    if (poweredByLower.includes("php")) technologies.push("php")
    if (poweredByLower.includes("asp.net")) technologies.push("asp.net")
  }

  return technologies
}

// Store for progress and results
const progressStore = new Map<string, { progress: number; results: any[] }>()

export async function POST(request: NextRequest) {
  try {
    const { url } = await request.json()

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    const domain = new URL(url).hostname
    const requestId = `${domain}-${Date.now()}`

    // Store initial state
    progressStore.set(requestId, { progress: 0, results: [] })

    // Start subdomain discovery in the background
    discoverSubdomains(domain, (progress, results) => {
      progressStore.set(requestId, { progress, results })
    })
      .then((finalResults) => {
        progressStore.set(requestId, { progress: 100, results: finalResults })
      })
      .catch((error) => {
        console.error("Subdomain discovery error:", error)
        progressStore.set(requestId, { progress: -1, results: [] })
      })

    return NextResponse.json({
      success: true,
      message: "Subdomain discovery started",
      requestId,
      inProgress: true,
      progress: 0,
    })
  } catch (error) {
    console.error("Subdomain scan error:", error)
    return NextResponse.json({ error: "Failed to scan subdomains" }, { status: 500 })
  }
}

export async function GET(request: NextRequest) {
  const url = new URL(request.url)
  const requestId = url.searchParams.get("requestId")

  if (!requestId) {
    return NextResponse.json({ error: "Request ID is required" }, { status: 400 })
  }

  const stored = progressStore.get(requestId)
  if (!stored) {
    return NextResponse.json({ error: "Request not found" }, { status: 404 })
  }

  return NextResponse.json({
    success: true,
    requestId,
    progress: stored.progress,
    inProgress: stored.progress < 100 && stored.progress >= 0,
    subdomains: stored.results,
    total: stored.results.length,
    error: stored.progress === -1 ? "Subdomain discovery failed" : null,
  })
}
