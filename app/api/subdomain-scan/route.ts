import { type NextRequest, NextResponse } from "next/server"
import dns from "dns"
import { promisify } from "util"

const dnsLookup = promisify(dns.lookup)
const dnsResolve = promisify(dns.resolve)

// Subdomain discovery with enhanced methods
async function discoverSubdomains(domain: string, progressCallback?: (progress: number) => void) {
  const subdomains = new Set<string>()
  const results: any[] = []
  let discoveryProgress = 0

  // Add the main domain
  subdomains.add(domain)

  // Common subdomain prefixes - expanded list
  const commonPrefixes = [
    // Basic subdomains
    "www",
    "mail",
    "webmail",
    "email",
    "remote",
    "login",
    "admin",
    "administrator",
    "portal",
    "vpn",
    "secure",
    "shop",
    "store",
    "blog",
    "news",
    "support",
    "help",
    "api",
    "developer",
    "dev",
    "test",
    "testing",
    "stage",
    "staging",
    "prod",
    "production",
    "demo",
    "beta",
    "alpha",
    "sandbox",
    "uat",
    "qa",
    "internal",
    "intranet",
    "extranet",

    // Technical subdomains
    "cdn",
    "static",
    "assets",
    "media",
    "img",
    "images",
    "css",
    "js",
    "fonts",
    "download",
    "downloads",
    "upload",
    "uploads",
    "file",
    "files",
    "docs",
    "documentation",
    "git",
    "svn",
    "jenkins",
    "ci",
    "build",
    "jira",
    "confluence",
    "wiki",
    "redmine",
    "monitor",
    "monitoring",
    "status",
    "stats",
    "analytics",
    "track",
    "tracking",

    // Service-specific
    "m",
    "mobile",
    "app",
    "apps",
    "web",
    "wap",
    "ftp",
    "sftp",
    "ssh",
    "smtp",
    "pop",
    "pop3",
    "imap",
    "chat",
    "video",
    "stream",
    "streaming",
    "live",
    "forum",
    "community",
    "social",
    "auth",
    "sso",
    "ldap",
    "proxy",
    "gateway",

    // Versioning
    "v1",
    "v2",
    "v3",
    "api-v1",
    "api-v2",
    "api-v3",
    "2020",
    "2021",
    "2022",
    "2023",
    "2024",
    "old",
    "new",
    "legacy",
    "next",

    // Cloud and infrastructure
    "aws",
    "azure",
    "gcp",
    "cloud",
    "s3",
    "bucket",
    "storage",
    "db",
    "database",
    "sql",
    "mysql",
    "postgres",
    "redis",
    "mongo",
    "elasticsearch",
    "kibana",
    "graphql",
    "rest",
    "kafka",
    "queue",
    "worker",
    "cron",
    "task",

    // Regional
    "us",
    "eu",
    "asia",
    "uk",
    "de",
    "fr",
    "ca",
    "au",
    "jp",
    "cn",
    "east",
    "west",
    "north",
    "south",
    "central",

    // Common applications
    "wordpress",
    "wp",
    "drupal",
    "joomla",
    "magento",
    "shopify",
    "woocommerce",
    "cpanel",
    "whm",
    "webmail",
    "plesk",
    "dashboard",
    "panel",
    "console",

    // Security related
    "security",
    "sec",
    "cert",
    "certs",
    "certificate",
    "certificates",
    "soc",
    "audit",
    "compliance",
    "firewall",
    "waf",
    "ids",
    "ips",
    "vpn",
    "2fa",
    "mfa",
  ]

  // Update progress
  if (progressCallback) {
    progressCallback(5)
    discoveryProgress = 5
  }

  // Check common subdomains with DNS lookups (in batches to avoid overwhelming DNS servers)
  const batchSize = 20
  for (let i = 0; i < commonPrefixes.length; i += batchSize) {
    const batch = commonPrefixes.slice(i, i + batchSize)

    const dnsPromises = batch.map(async (prefix) => {
      const subdomain = `${prefix}.${domain}`
      try {
        // Try DNS lookup
        await dnsLookup(subdomain)
        subdomains.add(subdomain)
      } catch (error) {
        // Subdomain doesn't exist or is not accessible
      }
    })

    // Wait for batch to complete
    await Promise.allSettled(dnsPromises)

    // Update progress
    if (progressCallback) {
      const newProgress = Math.min(60, 5 + Math.floor((i / commonPrefixes.length) * 55))
      if (newProgress > discoveryProgress) {
        progressCallback(newProgress)
        discoveryProgress = newProgress
      }
    }
  }

  // Try to get MX records for the domain to find mail servers
  try {
    const mxRecords = await dnsResolve(domain, "MX")
    for (const record of mxRecords) {
      if (record.exchange.includes(domain)) {
        subdomains.add(record.exchange)
      }
    }
  } catch (error) {
    // No MX records or error
  }

  // Try to get NS records for the domain to find nameservers
  try {
    const nsRecords = await dnsResolve(domain, "NS")
    for (const record of nsRecords) {
      if (record.includes(domain)) {
        subdomains.add(record)
      }
    }
  } catch (error) {
    // No NS records or error
  }

  // Try to get TXT records which might reveal subdomains
  try {
    const txtRecords = await dnsResolve(domain, "TXT")
    for (const record of txtRecords) {
      // Look for SPF records which might mention mail servers
      if (record.includes("v=spf1") && record.includes("include:")) {
        const matches = record.match(/include:([a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+)/g)
        if (matches) {
          for (const match of matches) {
            const includeDomain = match.substring(8)
            if (includeDomain.includes(domain)) {
              subdomains.add(includeDomain)
            }
          }
        }
      }
    }
  } catch (error) {
    // No TXT records or error
  }

  // Update progress
  if (progressCallback) {
    progressCallback(70)
  }

  // Simulate certificate transparency log search
  // In a real implementation, this would query crt.sh or similar services
  try {
    // Simulate a request to certificate transparency logs
    const ctResponse = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, {
      signal: AbortSignal.timeout(10000),
    })

    if (ctResponse.ok) {
      const ctData = await ctResponse.json()

      // Extract unique subdomains from CT logs
      for (const cert of ctData) {
        if (cert.name_value) {
          // Handle both single domains and wildcards
          const names = cert.name_value.split("\n")
          for (const name of names) {
            if (name.endsWith(domain) && !name.includes("*")) {
              subdomains.add(name)
            }
          }
        }
      }
    }
  } catch (error) {
    console.error("CT log error:", error)
    // Failed to query CT logs
  }

  // Update progress
  if (progressCallback) {
    progressCallback(85)
  }

  // Check if subdomains are active by making HTTP requests
  let checkedCount = 0
  const subdomainArray = Array.from(subdomains)

  for (const subdomain of subdomainArray) {
    try {
      // Try HTTPS first
      const httpsUrl = `https://${subdomain}`
      const response = await fetch(httpsUrl, {
        method: "HEAD",
        signal: AbortSignal.timeout(5000),
      })

      results.push({
        subdomain,
        status: "Active",
        ip: await getIpAddress(subdomain),
        technologies: detectTechnologies(response.headers),
      })
    } catch (error) {
      try {
        // Try HTTP if HTTPS fails
        const httpUrl = `http://${subdomain}`
        const response = await fetch(httpUrl, {
          method: "HEAD",
          signal: AbortSignal.timeout(5000),
        })

        results.push({
          subdomain,
          status: "Active (HTTP)",
          ip: await getIpAddress(subdomain),
          technologies: detectTechnologies(response.headers),
        })
      } catch (error) {
        // Subdomain exists in DNS but web server is not responding
        results.push({
          subdomain,
          status: "Inactive",
          ip: await getIpAddress(subdomain),
          technologies: [],
        })
      }
    }

    // Update progress for each subdomain checked
    checkedCount++
    if (progressCallback) {
      const newProgress = Math.min(99, 85 + Math.floor((checkedCount / subdomainArray.length) * 14))
      progressCallback(newProgress)
    }
  }

  // Final progress update
  if (progressCallback) {
    progressCallback(100)
  }

  return results
}

// Helper function to get IP address
async function getIpAddress(hostname: string) {
  try {
    const { address } = await dnsLookup(hostname)
    return address
  } catch (error) {
    return "Unknown"
  }
}

// Helper function to detect technologies from headers
function detectTechnologies(headers: Headers) {
  const technologies: string[] = []

  // Check server header
  const server = headers.get("server")
  if (server) {
    if (server.toLowerCase().includes("nginx")) technologies.push("nginx")
    if (server.toLowerCase().includes("apache")) technologies.push("apache")
    if (server.toLowerCase().includes("microsoft-iis")) technologies.push("IIS")
  }

  // Check for Cloudflare
  if (headers.get("cf-ray") || headers.get("cf-cache-status")) {
    technologies.push("cloudflare")
  }

  // Check for other CDNs
  if (headers.get("x-fastly-request-id")) technologies.push("fastly")
  if (headers.get("x-akamai-transformed")) technologies.push("akamai")

  // Check for common frameworks
  if (headers.get("x-powered-by")) {
    const poweredBy = headers.get("x-powered-by")
    if (poweredBy?.toLowerCase().includes("php")) technologies.push("php")
    if (poweredBy?.toLowerCase().includes("asp.net")) technologies.push("asp.net")
    if (poweredBy?.toLowerCase().includes("express")) technologies.push("express")
  }

  return technologies
}

// Create a store for progress updates
const progressStore = new Map<string, number>()
const resultsStore = new Map<string, any[]>()

export async function POST(request: NextRequest) {
  try {
    const { url } = await request.json()

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    const domain = new URL(url).hostname
    const requestId = `${domain}-${Date.now()}`

    // Store initial progress
    progressStore.set(requestId, 0)
    resultsStore.set(requestId, [])

    // Start subdomain discovery in the background (don't await)
    discoverSubdomains(domain, (progress) => {
      progressStore.set(requestId, progress)
    })
      .then((results) => {
        // Store the final results
        resultsStore.set(requestId, results)
        progressStore.set(requestId, 100)
      })
      .catch((error) => {
        console.error("Subdomain discovery error:", error)
        progressStore.set(requestId, -1) // Error state
      })

    // Return immediately with the request ID
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

// Update the GET function to return both progress and results
export async function GET(request: NextRequest) {
  const url = new URL(request.url)
  const requestId = url.searchParams.get("requestId")

  if (!requestId) {
    return NextResponse.json({ error: "Request ID is required" }, { status: 400 })
  }

  const progress = progressStore.get(requestId) || 0
  const results = resultsStore.get(requestId) || []

  return NextResponse.json({
    success: true,
    requestId,
    progress,
    inProgress: progress < 100 && progress >= 0,
    subdomains: results,
    total: results.length,
    error: progress === -1 ? "Subdomain discovery failed" : null,
  })
}
