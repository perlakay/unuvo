import { type NextRequest, NextResponse } from "next/server"

// Mock security scan function
async function performSecurityScan(url: string, token?: string) {
  // In a real implementation, this would call your Python backend
  // For now, we'll simulate a scan with mock data

  // Simulate processing time
  await new Promise((resolve) => setTimeout(resolve, 2000))

  // Generate mock scan results
  const vulnerabilities = [
    {
      id: 1,
      title: "Missing Content Security Policy",
      severity: "high",
      category: "Headers",
      description: "The application does not implement Content Security Policy headers.",
    },
    {
      id: 2,
      title: "Weak SSL/TLS Configuration",
      severity: "critical",
      category: "Encryption",
      description: "The server supports weak cipher suites and outdated TLS versions.",
    },
    {
      id: 3,
      title: "Missing X-Frame-Options Header",
      severity: "medium",
      category: "Headers",
      description: "The X-Frame-Options header is not set, allowing the page to be embedded in frames.",
    },
    {
      id: 4,
      title: "Information Disclosure",
      severity: "low",
      category: "Information",
      description: "Error pages reveal sensitive information about the server configuration.",
    },
    {
      id: 5,
      title: "CORS Misconfiguration",
      severity: "medium",
      category: "Configuration",
      description: "Cross-Origin Resource Sharing is misconfigured allowing unauthorized domains.",
    },
    {
      id: 6,
      title: "No Rate Limiting",
      severity: "medium",
      category: "API Security",
      description: "The API does not implement rate limiting, making it vulnerable to brute force attacks.",
    },
    {
      id: 7,
      title: "Insecure JWT Configuration",
      severity: "high",
      category: "Authentication",
      description: "JWT tokens use weak algorithms or have excessive lifetimes.",
    },
    {
      id: 8,
      title: "Missing HTTP Strict Transport Security",
      severity: "medium",
      category: "Headers",
      description: "HSTS header is not implemented, allowing potential downgrade attacks.",
    },
    {
      id: 9,
      title: "Server Information Disclosure",
      severity: "low",
      category: "Information",
      description: "Server headers reveal detailed version information.",
    },
    {
      id: 10,
      title: "Insecure Cookie Configuration",
      severity: "low",
      category: "Cookies",
      description: "Cookies are set without secure or httpOnly flags.",
    },
    {
      id: 11,
      title: "Outdated Dependencies",
      severity: "high",
      category: "Dependencies",
      description: "Several frontend libraries have known security vulnerabilities.",
    },
    {
      id: 12,
      title: "Exposed API Keys",
      severity: "critical",
      category: "Secrets",
      description: "API keys are exposed in client-side code.",
    },
  ]

  // Count vulnerabilities by severity
  const critical = vulnerabilities.filter((v) => v.severity === "critical").length
  const high = vulnerabilities.filter((v) => v.severity === "high").length
  const medium = vulnerabilities.filter((v) => v.severity === "medium").length
  const low = vulnerabilities.filter((v) => v.severity === "low").length

  // If JWT token was provided, analyze it
  if (token) {
    try {
      // Simple JWT analysis (in a real app, this would be more sophisticated)
      const parts = token.split(".")
      if (parts.length !== 3) {
        vulnerabilities.push({
          id: 13,
          title: "Malformed JWT Token",
          severity: "critical",
          category: "Authentication",
          description: "The provided JWT token is not properly formatted.",
        })
      } else {
        // Add a mock JWT finding
        vulnerabilities.push({
          id: 13,
          title: "JWT Using Weak Algorithm",
          severity: "high",
          category: "Authentication",
          description: "The JWT token uses a weak signing algorithm (HS256).",
        })
      }
    } catch (error) {
      console.error("Error analyzing JWT:", error)
    }
  }

  return {
    url,
    scanDate: new Date().toISOString(),
    securityScore: Math.floor(Math.random() * 40) + 40, // Random score between 40-80
    totalVulnerabilities: vulnerabilities.length,
    critical,
    high,
    medium,
    low,
    vulnerabilities,
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { url, token } = body

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    // Validate URL format
    try {
      new URL(url)
    } catch (error) {
      return NextResponse.json({ error: "Invalid URL format" }, { status: 400 })
    }

    // Perform security scan
    const scanResults = await performSecurityScan(url, token)

    // Return scan results
    return NextResponse.json({
      success: true,
      data: scanResults,
    })
  } catch (error) {
    console.error("Scan API error:", error)
    return NextResponse.json({ error: "Failed to process scan request" }, { status: 500 })
  }
}
