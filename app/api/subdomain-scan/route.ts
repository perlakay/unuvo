import { type NextRequest, NextResponse } from "next/server"
import dns from "dns"
import { promisify } from "util"

const dnsLookup = promisify(dns.lookup)
const dnsResolve = promisify(dns.resolve)

// Enhanced subdomain discovery with comprehensive methods
async function discoverSubdomains(domain: string, progressCallback?: (progress: number, found: any[]) => void) {
  const subdomains = new Set<string>()
  const results: any[] = []
  let discoveryProgress = 0

  // Add the main domain
  subdomains.add(domain)

  // Comprehensive subdomain wordlist (500+ entries)
  const commonPrefixes = [
    // Basic web services
    "www",
    "www2",
    "www3",
    "web",
    "web1",
    "web2",
    "webmail",
    "mail",
    "email",
    "smtp",
    "pop",
    "pop3",
    "imap",
    "mx",
    "mx1",
    "mx2",
    "mx3",
    "exchange",
    "outlook",
    "owa",
    "autodiscover",
    "autoconfig",

    // Admin and management
    "admin",
    "administrator",
    "root",
    "manage",
    "management",
    "panel",
    "cpanel",
    "whm",
    "plesk",
    "directadmin",
    "control",
    "console",
    "dashboard",
    "portal",
    "gateway",
    "login",
    "auth",
    "sso",
    "ldap",
    "ad",

    // Development and testing
    "dev",
    "development",
    "test",
    "testing",
    "stage",
    "staging",
    "uat",
    "qa",
    "quality",
    "demo",
    "sandbox",
    "beta",
    "alpha",
    "preview",
    "pre",
    "preprod",
    "prod",
    "production",
    "live",
    "www-test",
    "test-www",

    // API and services
    "api",
    "api1",
    "api2",
    "api3",
    "api-v1",
    "api-v2",
    "api-v3",
    "rest",
    "graphql",
    "soap",
    "rpc",
    "service",
    "services",
    "microservice",
    "webhook",
    "ws",
    "wss",
    "socket",
    "realtime",

    // Content and media
    "cdn",
    "static",
    "assets",
    "media",
    "img",
    "images",
    "image",
    "pics",
    "pictures",
    "photo",
    "photos",
    "video",
    "videos",
    "stream",
    "streaming",
    "live",
    "broadcast",
    "upload",
    "uploads",
    "download",
    "downloads",
    "file",
    "files",
    "docs",
    "documents",
    "pdf",
    "content",
    "cms",
    "blog",
    "news",
    "press",

    // Mobile and apps
    "m",
    "mobile",
    "app",
    "apps",
    "ios",
    "android",
    "touch",
    "wap",
    "pda",
    "tablet",

    // E-commerce
    "shop",
    "store",
    "cart",
    "checkout",
    "payment",
    "pay",
    "billing",
    "invoice",
    "order",
    "orders",
    "catalog",
    "products",
    "inventory",
    "warehouse",
    "shipping",
    "tracking",

    // Support and help
    "support",
    "help",
    "helpdesk",
    "ticket",
    "tickets",
    "faq",
    "kb",
    "knowledgebase",
    "wiki",
    "docs",
    "documentation",
    "manual",
    "guide",
    "tutorial",
    "training",
    "learn",
    "academy",

    // Social and community
    "social",
    "community",
    "forum",
    "forums",
    "discussion",
    "chat",
    "talk",
    "voice",
    "video-chat",
    "meet",
    "meeting",
    "conference",
    "webinar",
    "events",
    "calendar",

    // Security and monitoring
    "secure",
    "security",
    "sec",
    "vpn",
    "ssl",
    "tls",
    "cert",
    "certs",
    "certificate",
    "certificates",
    "firewall",
    "waf",
    "ids",
    "ips",
    "siem",
    "log",
    "logs",
    "monitor",
    "monitoring",
    "metrics",
    "status",
    "health",
    "ping",
    "uptime",
    "nagios",
    "zabbix",
    "grafana",
    "kibana",
    "splunk",

    // Database and storage
    "db",
    "database",
    "sql",
    "mysql",
    "postgres",
    "postgresql",
    "oracle",
    "mssql",
    "mongo",
    "mongodb",
    "redis",
    "memcache",
    "elasticsearch",
    "solr",
    "search",
    "index",
    "data",
    "backup",
    "archive",
    "storage",
    "s3",
    "bucket",
    "vault",
    "repository",
    "repo",

    // Infrastructure and DevOps
    "jenkins",
    "ci",
    "cd",
    "build",
    "deploy",
    "deployment",
    "docker",
    "k8s",
    "kubernetes",
    "swarm",
    "cluster",
    "node",
    "worker",
    "master",
    "slave",
    "lb",
    "loadbalancer",
    "proxy",
    "reverse-proxy",
    "cache",
    "varnish",
    "nginx",
    "apache",
    "haproxy",
    "traefik",

    // Cloud and regions
    "cloud",
    "aws",
    "azure",
    "gcp",
    "digitalocean",
    "linode",
    "vultr",
    "heroku",
    "vercel",
    "netlify",
    "us",
    "usa",
    "eu",
    "europe",
    "asia",
    "apac",
    "uk",
    "de",
    "fr",
    "ca",
    "au",
    "jp",
    "cn",
    "in",
    "east",
    "west",
    "north",
    "south",
    "central",
    "1",
    "2",
    "3",
    "4",
    "5",

    // Versioning and environments
    "v1",
    "v2",
    "v3",
    "v4",
    "v5",
    "version1",
    "version2",
    "old",
    "new",
    "legacy",
    "next",
    "future",
    "2020",
    "2021",
    "2022",
    "2023",
    "2024",
    "2025",
    "current",
    "latest",
    "stable",
    "release",

    // Network and protocols
    "ftp",
    "sftp",
    "ssh",
    "telnet",
    "snmp",
    "ntp",
    "dns",
    "ns",
    "ns1",
    "ns2",
    "ns3",
    "ns4",
    "nameserver",
    "resolver",
    "whois",
    "rdp",
    "vnc",
    "remote",
    "terminal",

    // Applications and frameworks
    "wordpress",
    "wp",
    "drupal",
    "joomla",
    "magento",
    "shopify",
    "woocommerce",
    "prestashop",
    "laravel",
    "symfony",
    "django",
    "rails",
    "express",
    "react",
    "angular",
    "vue",
    "next",
    "nuxt",
    "gatsby",
    "hugo",
    "jekyll",
    "ghost",
    "discourse",
    "phpbb",
    "vbulletin",

    // Business functions
    "crm",
    "erp",
    "hr",
    "finance",
    "accounting",
    "sales",
    "marketing",
    "analytics",
    "stats",
    "reports",
    "reporting",
    "business",
    "corporate",
    "enterprise",
    "b2b",
    "b2c",
    "partner",
    "partners",
    "vendor",
    "vendors",
    "supplier",
    "suppliers",
    "client",
    "clients",
    "customer",
    "customers",
    "user",
    "users",
    "member",
    "members",
    "guest",
    "public",
    "private",
    "internal",
    "external",
    "intranet",
    "extranet",

    // Miscellaneous
    "temp",
    "tmp",
    "backup",
    "bak",
    "old",
    "archive",
    "staging2",
    "dev2",
    "test2",
    "beta2",
    "mirror",
    "replica",
    "clone",
    "copy",
    "sync",
    "rsync",
    "git",
    "svn",
    "cvs",
    "hg",
    "bzr",
    "redmine",
    "trac",
    "mantis",
    "bugzilla",
    "jira",
    "confluence",
    "sharepoint",
    "teams",
    "slack",
    "discord",
    "telegram",
    "whatsapp",
    "signal",
    "zoom",
    "skype",
    "gotomeeting",

    // Additional technical
    "queue",
    "worker",
    "job",
    "jobs",
    "task",
    "tasks",
    "cron",
    "scheduler",
    "timer",
    "batch",
    "process",
    "processor",
    "engine",
    "core",
    "kernel",
    "system",
    "sys",
    "os",
    "platform",
    "framework",
    "lib",
    "library",
    "module",
    "plugin",
    "addon",
    "extension",
    "widget",
    "component",
    "service-worker",
    "background",
    "daemon",
    "agent",
    "client",
    "server",

    // IoT and devices
    "iot",
    "device",
    "devices",
    "sensor",
    "sensors",
    "camera",
    "cameras",
    "printer",
    "printers",
    "scanner",
    "scanners",
    "router",
    "routers",
    "switch",
    "switches",
    "hub",
    "hubs",
    "gateway",
    "gateways",
    "bridge",
    "bridges",
    "relay",
    "relays",
    "beacon",
    "beacons",

    // Geographic and location
    "local",
    "localhost",
    "lan",
    "wan",
    "dmz",
    "office",
    "branch",
    "hq",
    "headquarters",
    "datacenter",
    "dc",
    "colo",
    "colocation",
    "rack",
    "server",
    "servers",
    "host",
    "hosts",
    "vm",
    "virtual",
    "container",
    "pod",
    "instance",
    "instances",
  ]

  // Update progress
  if (progressCallback) {
    progressCallback(5, results)
    discoveryProgress = 5
  }

  // Phase 1: DNS enumeration with comprehensive wordlist
  console.log(`Starting DNS enumeration for ${domain}`)
  const batchSize = 50 // Increased batch size for faster processing
  for (let i = 0; i < commonPrefixes.length; i += batchSize) {
    const batch = commonPrefixes.slice(i, i + batchSize)

    const dnsPromises = batch.map(async (prefix) => {
      const subdomain = `${prefix}.${domain}`
      try {
        await dnsLookup(subdomain)
        subdomains.add(subdomain)
        console.log(`Found subdomain: ${subdomain}`)
        return subdomain
      } catch (error) {
        return null
      }
    })

    const batchResults = await Promise.allSettled(dnsPromises)
    const foundInBatch = batchResults
      .filter((result) => result.status === "fulfilled" && result.value)
      .map((result) => (result as PromiseFulfilledResult<string>).value)

    // Update progress with found subdomains
    if (progressCallback && foundInBatch.length > 0) {
      const newProgress = Math.min(40, 5 + Math.floor((i / commonPrefixes.length) * 35))
      if (newProgress > discoveryProgress) {
        progressCallback(
          newProgress,
          Array.from(subdomains).map((s) => ({ subdomain: s, status: "Found" })),
        )
        discoveryProgress = newProgress
      }
    }
  }

  // Phase 2: Certificate Transparency Logs
  console.log(`Checking Certificate Transparency logs for ${domain}`)
  if (progressCallback) {
    progressCallback(
      45,
      Array.from(subdomains).map((s) => ({ subdomain: s, status: "Found" })),
    )
  }

  try {
    const ctResponse = await fetch(`https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`, {
      signal: AbortSignal.timeout(15000),
    })

    if (ctResponse.ok) {
      const ctData = await ctResponse.json()
      console.log(`Found ${ctData.length} certificates in CT logs`)

      for (const cert of ctData) {
        if (cert.name_value) {
          const names = cert.name_value.split("\n")
          for (const name of names) {
            const cleanName = name.trim().toLowerCase()
            if (cleanName.endsWith(`.${domain}`) && !cleanName.includes("*") && cleanName !== domain) {
              subdomains.add(cleanName)
              console.log(`Found subdomain from CT logs: ${cleanName}`)
            }
          }
        }
      }
    }
  } catch (error) {
    console.error("CT log error:", error)
  }

  // Phase 3: DNS record enumeration
  console.log(`Checking DNS records for ${domain}`)
  if (progressCallback) {
    progressCallback(
      55,
      Array.from(subdomains).map((s) => ({ subdomain: s, status: "Found" })),
    )
  }

  // Check MX records
  try {
    const mxRecords = await dnsResolve(domain, "MX")
    for (const record of mxRecords) {
      if (record.exchange && record.exchange.endsWith(`.${domain}`)) {
        subdomains.add(record.exchange)
        console.log(`Found subdomain from MX: ${record.exchange}`)
      }
    }
  } catch (error) {
    console.log("No MX records found")
  }

  // Check NS records
  try {
    const nsRecords = await dnsResolve(domain, "NS")
    for (const record of nsRecords) {
      if (record.endsWith(`.${domain}`)) {
        subdomains.add(record)
        console.log(`Found subdomain from NS: ${record}`)
      }
    }
  } catch (error) {
    console.log("No NS records found")
  }

  // Check TXT records for SPF and other mentions
  try {
    const txtRecords = await dnsResolve(domain, "TXT")
    for (const record of txtRecords) {
      // SPF records
      if (record.includes("v=spf1") && record.includes("include:")) {
        const matches = record.match(/include:([a-zA-Z0-9.-]+)/g)
        if (matches) {
          for (const match of matches) {
            const includeDomain = match.substring(8)
            if (includeDomain.endsWith(`.${domain}`)) {
              subdomains.add(includeDomain)
              console.log(`Found subdomain from SPF: ${includeDomain}`)
            }
          }
        }
      }
      // DMARC records
      if (record.includes("v=DMARC1")) {
        const matches = record.match(/rua=mailto:[^@]+@([a-zA-Z0-9.-]+)/g)
        if (matches) {
          for (const match of matches) {
            const reportDomain = match.split("@")[1]
            if (reportDomain.endsWith(`.${domain}`)) {
              subdomains.add(reportDomain)
              console.log(`Found subdomain from DMARC: ${reportDomain}`)
            }
          }
        }
      }
    }
  } catch (error) {
    console.log("No TXT records found")
  }

  // Phase 4: Verify subdomains and gather information
  console.log(`Verifying ${subdomains.size} discovered subdomains`)
  if (progressCallback) {
    progressCallback(
      65,
      Array.from(subdomains).map((s) => ({ subdomain: s, status: "Verifying" })),
    )
  }

  let checkedCount = 0
  const subdomainArray = Array.from(subdomains)

  for (const subdomain of subdomainArray) {
    try {
      let status = "Inactive"
      let technologies: string[] = []

      // Try HTTPS first
      try {
        const httpsUrl = `https://${subdomain}`
        const response = await fetch(httpsUrl, {
          method: "HEAD",
          signal: AbortSignal.timeout(8000),
        })

        if (response.ok) {
          status = "Active (HTTPS)"
          technologies = detectTechnologies(response.headers)
        }
      } catch (httpsError) {
        // Try HTTP if HTTPS fails
        try {
          const httpUrl = `http://${subdomain}`
          const response = await fetch(httpUrl, {
            method: "HEAD",
            signal: AbortSignal.timeout(8000),
          })

          if (response.ok) {
            status = "Active (HTTP)"
            technologies = detectTechnologies(response.headers)
          }
        } catch (httpError) {
          // Check if subdomain resolves in DNS but web server doesn't respond
          try {
            await dnsLookup(subdomain)
            status = "DNS Only"
          } catch (dnsError) {
            status = "Inactive"
          }
        }
      }

      const result = {
        subdomain,
        status,
        ip: await getIpAddress(subdomain),
        technologies,
      }

      results.push(result)
      console.log(`Verified: ${subdomain} - ${status}`)

      // Update progress with real-time results
      checkedCount++
      if (progressCallback) {
        const newProgress = Math.min(95, 65 + Math.floor((checkedCount / subdomainArray.length) * 30))
        progressCallback(newProgress, [...results])
      }
    } catch (error) {
      console.error(`Error checking ${subdomain}:`, error)
    }
  }

  // Final progress update
  if (progressCallback) {
    progressCallback(100, results)
  }

  console.log(`Subdomain discovery complete. Found ${results.length} subdomains for ${domain}`)
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

// Enhanced technology detection
function detectTechnologies(headers: Headers) {
  const technologies: string[] = []

  // Server detection
  const server = headers.get("server")
  if (server) {
    const serverLower = server.toLowerCase()
    if (serverLower.includes("nginx")) technologies.push("nginx")
    if (serverLower.includes("apache")) technologies.push("apache")
    if (serverLower.includes("microsoft-iis")) technologies.push("IIS")
    if (serverLower.includes("cloudflare")) technologies.push("cloudflare")
    if (serverLower.includes("litespeed")) technologies.push("litespeed")
    if (serverLower.includes("caddy")) technologies.push("caddy")
  }

  // CDN detection
  if (headers.get("cf-ray") || headers.get("cf-cache-status")) technologies.push("cloudflare")
  if (headers.get("x-fastly-request-id")) technologies.push("fastly")
  if (headers.get("x-akamai-transformed")) technologies.push("akamai")
  if (headers.get("x-amz-cf-id")) technologies.push("aws-cloudfront")
  if (headers.get("x-azure-ref")) technologies.push("azure-cdn")

  // Framework detection
  const poweredBy = headers.get("x-powered-by")
  if (poweredBy) {
    const poweredByLower = poweredBy.toLowerCase()
    if (poweredByLower.includes("php")) technologies.push("php")
    if (poweredByLower.includes("asp.net")) technologies.push("asp.net")
    if (poweredByLower.includes("express")) technologies.push("express")
    if (poweredByLower.includes("next.js")) technologies.push("next.js")
    if (poweredByLower.includes("vercel")) technologies.push("vercel")
  }

  // Security headers
  if (headers.get("strict-transport-security")) technologies.push("hsts")
  if (headers.get("content-security-policy")) technologies.push("csp")
  if (headers.get("x-frame-options")) technologies.push("x-frame-options")

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
