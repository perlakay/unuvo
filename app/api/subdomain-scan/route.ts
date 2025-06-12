import { type NextRequest, NextResponse } from "next/server"

// Passive subdomain discovery using DNS records and certificate transparency
async function discoverSubdomains(domain: string, progressCallback?: (progress: number, found: any[]) => void) {
  const subdomains = new Set<string>()
  subdomains.add(domain)

  console.log(`Passive subdomain discovery for ${domain} using DNS records and CT logs`)

  if (progressCallback) progressCallback(10, Array.from(subdomains))

  // Phase 1: Certificate Transparency Logs
  console.log(`Querying certificate transparency logs for ${domain}...`)
  try {
    const ctResponse = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
      signal: AbortSignal.timeout(15000),
    })

    if (ctResponse.ok) {
      const ctData = await ctResponse.json()
      console.log(`Found ${ctData.length} certificate entries`)

      for (const entry of ctData) {
        const nameValue = entry.name_value || ""
        for (const subdomain of nameValue.split("\n")) {
          const cleanSubdomain = subdomain.trim().toLowerCase()
          const finalSubdomain = cleanSubdomain.replace(/^\*\./, "")
          if ((finalSubdomain.endsWith(`.${domain}`) || finalSubdomain === domain) && !finalSubdomain.includes("*")) {
            subdomains.add(finalSubdomain)
          }
        }
      }
    }
  } catch (error) {
    console.log(`Warning: Certificate transparency query failed`)
  }

  if (progressCallback) progressCallback(40, Array.from(subdomains))

  // Phase 2: DNS Record Enumeration
  console.log(`Checking DNS records for subdomain hints...`)

  // Check TXT records
  try {
    const txtResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=TXT`, {
      signal: AbortSignal.timeout(5000),
    })
    if (txtResponse.ok) {
      const txtData = await txtResponse.json()
      if (txtData.Answer) {
        for (const record of txtData.Answer) {
          const txt = record.data.replace(/"/g, "")
          const domainPattern = new RegExp(`([a-zA-Z0-9][-a-zA-Z0-9]*\\.)+${domain.replace(".", "\\.")}`, "g")
          const matches = txt.match(domainPattern)
          if (matches) {
            for (const match of matches) {
              if (match.endsWith(`.${domain}`)) {
                subdomains.add(match)
              }
            }
          }
        }
      }
    }
  } catch (error) {
    console.log(`Warning: TXT record check failed`)
  }

  // Check MX records
  try {
    const mxResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=MX`, {
      signal: AbortSignal.timeout(5000),
    })
    if (mxResponse.ok) {
      const mxData = await mxResponse.json()
      if (mxData.Answer) {
        for (const record of mxData.Answer) {
          const mxParts = record.data.split(" ")
          const mx = mxParts[1]?.replace(/\.$/, "")
          if (mx && mx.endsWith(`.${domain}`)) {
            subdomains.add(mx)
          }
        }
      }
    }
  } catch (error) {
    console.log(`Warning: MX record check failed`)
  }

  // Check NS records
  try {
    const nsResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=NS`, {
      signal: AbortSignal.timeout(5000),
    })
    if (nsResponse.ok) {
      const nsData = await nsResponse.json()
      if (nsData.Answer) {
        for (const record of nsData.Answer) {
          const ns = record.data.replace(/\.$/, "")
          if (ns.endsWith(`.${domain}`)) {
            subdomains.add(ns)
          }
        }
      }
    }
  } catch (error) {
    console.log(`Warning: NS record check failed`)
  }

  if (progressCallback) progressCallback(70, Array.from(subdomains))

  // Phase 3: Common subdomain check
  console.log(`Checking common subdomain prefixes...`)
  const commonPrefixes = ["www", "mail", "webmail", "api", "dev", "stage", "blog", "shop", "support"]

  const commonChecks = commonPrefixes.map(async (prefix) => {
    const commonSubdomain = `${prefix}.${domain}`
    try {
      const response = await fetch(`https://dns.google/resolve?name=${commonSubdomain}&type=A`, {
        signal: AbortSignal.timeout(3000),
      })
      if (response.ok) {
        const data = await response.json()
        if (data.Answer && data.Answer.length > 0) {
          return commonSubdomain
        }
      }
    } catch (error) {
      // Subdomain doesn't exist
    }
    return null
  })

  const commonResults = await Promise.allSettled(commonChecks)
  for (const result of commonResults) {
    if (result.status === "fulfilled" && result.value) {
      subdomains.add(result.value)
    }
  }

  if (progressCallback) progressCallback(90, Array.from(subdomains))

  // Phase 4: Verification
  const results: any[] = []
  const subdomainArray = Array.from(subdomains).sort()

  console.log(`Verifying ${subdomainArray.length} discovered subdomains...`)

  const verificationPromises = subdomainArray.map(async (subdomain) => {
    try {
      const dnsResponse = await fetch(`https://dns.google/resolve?name=${subdomain}&type=A`, {
        signal: AbortSignal.timeout(2000),
      })

      if (dnsResponse.ok) {
        const dnsData = await dnsResponse.json()
        if (dnsData.Answer && dnsData.Answer.length > 0) {
          const ip = dnsData.Answer[0].data
          return {
            subdomain,
            status: "Active",
            ip,
            technologies: [],
          }
        }
      }

      return {
        subdomain,
        status: "DNS Only",
        ip: "Unknown",
        technologies: [],
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

  const verificationResults = await Promise.allSettled(verificationPromises)
  for (const result of verificationResults) {
    if (result.status === "fulfilled") {
      results.push(result.value)
    }
  }

  if (progressCallback) progressCallback(100, results)
  console.log(`Passive discovery complete: ${results.length} subdomains found`)
  return results
}

// Storage
const scanStore = new Map<string, { progress: number; results: any[]; completed: boolean; error?: string }>()

export async function POST(request: NextRequest) {
  try {
    const { url } = await request.json()

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    const domain = new URL(url).hostname
    const scanId = `${domain}-${Date.now()}`

    console.log(`Starting passive subdomain discovery for ${domain}`)

    scanStore.set(scanId, { progress: 0, results: [], completed: false })

    // Start discovery
    discoverSubdomains(domain, (progress, results) => {
      scanStore.set(scanId, { progress, results, completed: progress >= 100 })
    })
      .then((finalResults) => {
        scanStore.set(scanId, { progress: 100, results: finalResults, completed: true })
        console.log(`Discovery complete: ${finalResults.length} subdomains`)
      })
      .catch((error) => {
        console.error("Discovery failed:", error)
        scanStore.set(scanId, { progress: 0, results: [], completed: true, error: error.message })
      })

    return NextResponse.json({
      success: true,
      scanId,
      message: "Passive subdomain discovery started",
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
