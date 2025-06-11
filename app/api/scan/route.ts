import { type NextRequest, NextResponse } from "next/server"

export async function POST(request: NextRequest) {
  try {
    const { url, token } = await request.json()

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    // Validate URL format
    try {
      new URL(url)
    } catch {
      return NextResponse.json({ error: "Invalid URL format" }, { status: 400 })
    }

    // Run security scan
    const scanResult = await performSecurityScan(url, token)

    return NextResponse.json({
      success: true,
      scanId: generateScanId(),
      data: scanResult,
    })
  } catch (error) {
    console.error("Scan error:", error)
    return NextResponse.json({ error: "Failed to perform security scan" }, { status: 500 })
  }
}

function generateScanId(): string {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
}

async function performSecurityScan(url: string, token?: string) {
  const vulnerabilities: any[] = []
  let vulnId = 1

  // SSL Security Check
  const sslIssues = await checkSSLSecurity(url)
  sslIssues.forEach((issue) => {
    vulnerabilities.push({
      id: vulnId++,
      title: issue.title,
      severity: issue.severity.toLowerCase(),
      category: "SSL/TLS",
      description: issue.details,
      impact: issue.impact,
      remediation: issue.mitigation,
    })
  })

  // Security Headers Check
  const headerIssues = await checkSecurityHeaders(url)
  headerIssues.forEach((issue) => {
    vulnerabilities.push({
      id: vulnId++,
      title: issue.title,
      severity: issue.severity.toLowerCase(),
      category: "Security Headers",
      description: issue.details,
      impact: issue.impact,
      remediation: issue.mitigation,
    })
  })

  // CORS Check
  const corsIssues = await checkCORS(url)
  corsIssues.forEach((issue) => {
    vulnerabilities.push({
      id: vulnId++,
      title: issue.title,
      severity: issue.severity.toLowerCase(),
      category: "CORS",
      description: issue.details,
      impact: issue.impact,
      remediation: issue.mitigation,
    })
  })

  // Rate Limiting Check
  const rateLimitIssues = await checkRateLimiting(url)
  rateLimitIssues.forEach((issue) => {
    vulnerabilities.push({
      id: vulnId++,
      title: issue.title,
      severity: issue.severity.toLowerCase(),
      category: "Rate Limiting",
      description: issue.details,
      impact: issue.impact,
      remediation: issue.mitigation,
    })
  })

  // JWT Analysis (if token provided)
  if (token) {
    const jwtIssues = analyzeJWTToken(token)
    jwtIssues.forEach((issue) => {
      vulnerabilities.push({
        id: vulnId++,
        title: issue.title,
        severity: issue.severity.toLowerCase(),
        category: "JWT",
        description: issue.details,
        impact: issue.impact,
        remediation: issue.mitigation,
      })
    })
  }

  // Calculate security metrics
  const critical = vulnerabilities.filter((v) => v.severity === "critical").length
  const high = vulnerabilities.filter((v) => v.severity === "high").length
  const medium = vulnerabilities.filter((v) => v.severity === "medium").length
  const low = vulnerabilities.filter((v) => v.severity === "low").length

  const totalVulns = vulnerabilities.length
  const weightedScore = critical * 25 + high * 15 + medium * 8 + low * 3
  const securityScore = totalVulns === 0 ? 100 : Math.max(0, 100 - weightedScore)

  return {
    url,
    scanDate: new Date().toISOString(),
    securityScore,
    totalVulnerabilities: totalVulns,
    critical,
    high,
    medium,
    low,
    vulnerabilities,
  }
}

async function checkSSLSecurity(url: string) {
  const issues: any[] = []

  try {
    const response = await fetch(url, {
      method: "HEAD",
      signal: AbortSignal.timeout(10000),
    })

    // Check if HTTPS is used
    if (!url.startsWith("https://")) {
      issues.push({
        title: "Insecure HTTP Connection",
        severity: "HIGH",
        details: "Website is not using HTTPS encryption",
        impact: "Data transmitted between client and server is not encrypted and can be intercepted",
        mitigation: "Implement HTTPS with a valid SSL/TLS certificate",
      })
    }
  } catch (error: any) {
    if (error.name === "TypeError" && error.message.includes("fetch")) {
      issues.push({
        title: "SSL/TLS Connection Issue",
        severity: "HIGH",
        details: "Unable to establish secure connection to the server",
        impact: "Potential SSL/TLS configuration problems that could affect security",
        mitigation: "Verify SSL certificate is valid and properly configured",
      })
    }
  }

  return issues
}

async function checkSecurityHeaders(url: string) {
  const issues: any[] = []

  try {
    const response = await fetch(url, {
      method: "HEAD",
      signal: AbortSignal.timeout(10000),
    })

    const headers = response.headers

    const securityHeaders = {
      "strict-transport-security": "Missing HSTS header - clients may connect over insecure HTTP",
      "x-content-type-options": "Missing protection against MIME-type sniffing attacks",
      "x-frame-options": "Missing clickjacking protection",
      "content-security-policy": "Missing CSP - vulnerable to XSS and injection attacks",
      "x-xss-protection": "Missing XSS protection header",
      "referrer-policy": "Missing referrer policy - may leak sensitive data",
    }

    for (const [header, description] of Object.entries(securityHeaders)) {
      if (!headers.has(header)) {
        issues.push({
          title: `Missing ${header
            .split("-")
            .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
            .join("-")} Header`,
          severity: "MEDIUM",
          details: description,
          impact: "Could lead to various security vulnerabilities",
          mitigation: `Add the ${header} header with appropriate security values`,
        })
      }
    }
  } catch (error) {
    issues.push({
      title: "Security Headers Check Failed",
      severity: "LOW",
      details: `Failed to check security headers: ${error}`,
      impact: "Unable to verify security header configuration",
      mitigation: "Ensure the URL is accessible and properly configured",
    })
  }

  return issues
}

async function checkCORS(url: string) {
  const issues: any[] = []
  const testOrigins = ["https://evil.com", "null"]

  for (const origin of testOrigins) {
    try {
      const response = await fetch(url, {
        method: "OPTIONS",
        headers: { Origin: origin },
        signal: AbortSignal.timeout(5000),
      })

      const allowOrigin = response.headers.get("access-control-allow-origin")
      const allowCredentials = response.headers.get("access-control-allow-credentials")

      if (allowOrigin === "*") {
        issues.push({
          title: "CORS Wildcard Configuration",
          severity: allowCredentials ? "CRITICAL" : "HIGH",
          details: "Server allows requests from any origin (*)",
          impact: "Enables cross-origin attacks from any domain",
          mitigation: "Explicitly whitelist trusted origins instead of using wildcard",
        })
        break
      } else if (allowOrigin === origin) {
        issues.push({
          title: "CORS Origin Reflection",
          severity: "HIGH",
          details: `Server reflects ${origin} in Access-Control-Allow-Origin header`,
          impact: "Enables cross-origin attacks from arbitrary domains",
          mitigation: "Implement strict origin whitelist validation",
        })
        break
      }
    } catch (error) {
      // Continue with next origin
    }
  }

  return issues
}

async function checkRateLimiting(url: string) {
  const issues: any[] = []

  try {
    // Make multiple rapid requests
    const requests = Array(3)
      .fill(null)
      .map(() =>
        fetch(url, {
          method: "HEAD",
          signal: AbortSignal.timeout(5000),
        }),
      )

    const responses = await Promise.all(requests)
    const hasRateLimit = responses.some((resp) => resp.status === 429)

    if (!hasRateLimit) {
      issues.push({
        title: "Missing Rate Limiting",
        severity: "MEDIUM",
        details: "No rate limiting detected on multiple rapid requests",
        impact: "Vulnerable to brute force attacks and denial of service",
        mitigation: "Implement rate limiting with 429 status codes for excessive requests",
      })
    }
  } catch (error) {
    issues.push({
      title: "Rate Limiting Check Failed",
      severity: "LOW",
      details: `Failed to test rate limiting: ${error}`,
      impact: "Unable to verify rate limiting configuration",
      mitigation: "Ensure the URL is accessible for testing",
    })
  }

  return issues
}

function analyzeJWTToken(token: string) {
  const issues: any[] = []

  try {
    // Basic JWT structure validation
    const parts = token.split(".")
    if (parts.length !== 3) {
      issues.push({
        title: "Invalid JWT Structure",
        severity: "HIGH",
        details: "JWT token does not have the required 3 parts (header.payload.signature)",
        impact: "Malformed token could indicate security issues",
        mitigation: "Ensure JWT tokens follow the standard format",
      })
      return issues
    }

    // Decode header and payload (without verification)
    const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")))
    const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")))

    // Check algorithm
    if (header.alg === "none") {
      issues.push({
        title: "JWT Algorithm 'none'",
        severity: "CRITICAL",
        details: "Token uses 'none' algorithm which bypasses signature verification",
        impact: "Attackers can forge valid tokens without knowing the secret key",
        mitigation: "Use strong algorithms like RS256 or ES256, never accept 'none'",
      })
    }

    // Check expiration
    if (!payload.exp) {
      issues.push({
        title: "Missing Token Expiration",
        severity: "MEDIUM",
        details: "JWT token does not include an expiration time (exp claim)",
        impact: "Token remains valid indefinitely if compromised",
        mitigation: "Add reasonable expiration time using 'exp' claim",
      })
    } else {
      const now = Math.floor(Date.now() / 1000)
      if (payload.exp < now) {
        issues.push({
          title: "Expired JWT Token",
          severity: "LOW",
          details: "JWT token has expired",
          impact: "Expired tokens should not be accepted",
          mitigation: "Implement proper token refresh mechanisms",
        })
      }
    }
  } catch (error) {
    issues.push({
      title: "JWT Analysis Failed",
      severity: "LOW",
      details: `Failed to analyze JWT token: ${error}`,
      impact: "Unable to verify JWT security configuration",
      mitigation: "Ensure valid JWT token format",
    })
  }

  return issues
}
