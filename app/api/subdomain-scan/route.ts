import { type NextRequest, NextResponse } from "next/server"
import dns from "dns"
import { promisify } from "util"

const dnsLookup = promisify(dns.lookup)
const dnsResolve = promisify(dns.resolve)

// Subdomain discovery with real DNS lookups
async function discoverSubdomains(domain: string) {
  const subdomains = new Set<string>()
  const results: any[] = []

  // Add the main domain
  subdomains.add(domain)

  // Common subdomain prefixes
  const commonPrefixes = [
    "www",
    "mail",
    "webmail",
    "api",
    "dev",
    "stage",
    "staging",
    "test",
    "testing",
    "blog",
    "shop",
    "store",
    "support",
    "help",
    "docs",
    "admin",
    "portal",
    "app",
    "mobile",
    "secure",
    "vpn",
    "ftp",
    "sftp",
    "ssh",
    "remote",
    "cdn",
    "static",
    "assets",
    "img",
    "images",
    "media",
    "files",
    "beta",
    "alpha",
    "demo",
    "sandbox",
    "preview",
    "old",
    "new",
    "v1",
    "v2",
    "api-v1",
    "api-v2",
    "gateway",
    "proxy",
  ]

  // Check common subdomains with DNS lookups
  const dnsPromises = commonPrefixes.map(async (prefix) => {
    const subdomain = `${prefix}.${domain}`
    try {
      // Try DNS lookup
      await dnsLookup(subdomain)
      subdomains.add(subdomain)
    } catch (error) {
      // Subdomain doesn't exist or is not accessible
    }
  })

  // Wait for all DNS lookups to complete
  await Promise.allSettled(dnsPromises)

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

  // Check if subdomains are active by making HTTP requests
  for (const subdomain of subdomains) {
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

export async function POST(request: NextRequest) {
  try {
    const { url } = await request.json()

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    const domain = new URL(url).hostname

    // Perform subdomain discovery
    const subdomains = await discoverSubdomains(domain)

    return NextResponse.json({
      success: true,
      subdomains,
      total: subdomains.length,
    })
  } catch (error) {
    console.error("Subdomain scan error:", error)
    return NextResponse.json({ error: "Failed to scan subdomains" }, { status: 500 })
  }
}
