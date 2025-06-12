import { type NextRequest, NextResponse } from "next/server"

// Enhanced security scan function with real checks
async function performSecurityScan(url: string, token?: string, mode: "web" | "api" = "web") {
  // Validate URL
  let targetUrl: URL
  try {
    targetUrl = new URL(url)
  } catch (error) {
    throw new Error("Invalid URL format")
  }

  const vulnerabilities: any[] = []
  let vulnId = 1

  // Perform actual security checks
  if (mode === "web") {
    // Web-specific vulnerabilities
    const sslVulns = await checkSSLSecurity(url)
    sslVulns.forEach((vuln) => {
      vulnerabilities.push({
        id: vulnId++,
        title: vuln.title,
        severity: vuln.severity.toLowerCase(),
        category: "SSL/TLS",
        description: vuln.description,
        impact: vuln.impact,
        remediation: vuln.remediation,
      })
    })

    const headerVulns = await checkSecurityHeaders(url)
    headerVulns.forEach((vuln) => {
      vulnerabilities.push({
        id: vulnId++,
        title: vuln.title,
        severity: vuln.severity.toLowerCase(),
        category: "Security Headers",
        description: vuln.description,
        impact: vuln.impact,
        remediation: vuln.remediation,
      })
    })

    const cookieVulns = await checkCookieSecurity(url)
    cookieVulns.forEach((vuln) => {
      vulnerabilities.push({
        id: vulnId++,
        title: vuln.title,
        severity: vuln.severity.toLowerCase(),
        category: "Cookie Security",
        description: vuln.description,
        impact: vuln.impact,
        remediation: vuln.remediation,
      })
    })

    const infoVulns = await checkInformationDisclosure(url)
    infoVulns.forEach((vuln) => {
      vulnerabilities.push({
        id: vulnId++,
        title: vuln.title,
        severity: vuln.severity.toLowerCase(),
        category: "Information Disclosure",
        description: vuln.description,
        impact: vuln.impact,
        remediation: vuln.remediation,
      })
    })

    // Calculate security metrics
    const critical = vulnerabilities.filter((v) => v.severity === "critical").length
    const high = vulnerabilities.filter((v) => v.severity === "high").length
    const medium = vulnerabilities.filter((v) => v.severity === "medium").length
    const low = vulnerabilities.filter((v) => v.severity === "low").length

    // Calculate security score based on vulnerabilities
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
  } else {
    // API-specific vulnerabilities
    const apiVulns = await checkAPISecurityIssues(url)
    apiVulns.forEach((vuln) => {
      vulnerabilities.push({
        id: vulnId++,
        title: vuln.title,
        severity: vuln.severity.toLowerCase(),
        category: vuln.category,
        description: vuln.description,
        impact: vuln.impact,
        remediation: vuln.remediation,
      })
    })

    const authVulns = await checkAPIAuthentication(url, token)
    authVulns.forEach((vuln) => {
      vulnerabilities.push({
        id: vulnId++,
        title: vuln.title,
        severity: vuln.severity.toLowerCase(),
        category: "Authentication",
        description: vuln.description,
        impact: vuln.impact,
        remediation: vuln.remediation,
      })
    })

    // JWT Analysis (if token provided)
    if (token) {
      const jwtVulns = analyzeJWTToken(token)
      jwtVulns.forEach((vuln) => {
        vulnerabilities.push({
          id: vulnId++,
          title: vuln.title,
          severity: vuln.severity.toLowerCase(),
          category: "JWT Security",
          description: vuln.description,
          impact: vuln.impact,
          remediation: vuln.remediation,
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
}

async function checkSSLSecurity(url: string) {
  const issues: any[] = []

  try {
    // Check if using HTTPS
    if (!url.startsWith("https://")) {
      issues.push({
        title: "Insecure HTTP Connection",
        severity: "HIGH",
        description: "Website is not using HTTPS encryption, making data transmission vulnerable to interception",
        impact: "Sensitive data transmitted over HTTP can be intercepted by attackers",
        remediation: "Implement HTTPS with a valid SSL/TLS certificate and redirect all HTTP traffic to HTTPS",
      })
      return issues // No need to check SSL if not using HTTPS
    }

    const response = await fetch(url, {
      method: "HEAD",
      signal: AbortSignal.timeout(10000),
    })

    // Check for certificate transparency
    const ctHeader = response.headers.get("expect-ct")
    if (!ctHeader) {
      issues.push({
        title: "Missing Certificate Transparency",
        severity: "MEDIUM",
        description: "The site does not implement Certificate Transparency, which helps detect misissued certificates",
        impact: "Malicious certificates may be harder to detect",
        remediation: "Implement the Expect-CT header with appropriate policy",
      })
    }

    // Check for HSTS
    const hstsHeader = response.headers.get("strict-transport-security")
    if (!hstsHeader) {
      issues.push({
        title: "Missing HSTS Header",
        severity: "HIGH",
        description: "HTTP Strict Transport Security header is not implemented",
        impact: "Vulnerable to protocol downgrade attacks and cookie hijacking",
        remediation: "Implement HSTS header with appropriate max-age directive",
      })
    } else if (!hstsHeader.includes("includeSubDomains")) {
      issues.push({
        title: "Incomplete HSTS Configuration",
        severity: "MEDIUM",
        description: "HSTS header does not include subdomains, leaving them vulnerable",
        impact: "Subdomains remain vulnerable to protocol downgrade attacks",
        remediation: "Add 'includeSubDomains' directive to HSTS header",
      })
    }
  } catch (error: any) {
    if (error.name === "TypeError" && error.message.includes("fetch")) {
      issues.push({
        title: "SSL/TLS Connection Failure",
        severity: "CRITICAL",
        description: "Unable to establish secure SSL/TLS connection to the server",
        impact: "Potential certificate issues or server misconfiguration",
        remediation: "Verify SSL/TLS certificate installation and configuration",
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

    // Check for Content-Security-Policy
    if (!headers.get("content-security-policy")) {
      issues.push({
        title: "Missing Content Security Policy",
        severity: "HIGH",
        description: "The application does not implement Content Security Policy headers",
        impact: "Vulnerable to XSS attacks and code injection",
        remediation: "Implement a strict Content Security Policy header to prevent XSS attacks",
      })
    }

    // Check for X-Frame-Options
    if (!headers.get("x-frame-options")) {
      issues.push({
        title: "Missing X-Frame-Options Header",
        severity: "MEDIUM",
        description: "The X-Frame-Options header is not set, allowing the page to be embedded in frames",
        impact: "Vulnerable to clickjacking attacks",
        remediation: "Set X-Frame-Options header to DENY or SAMEORIGIN",
      })
    }

    // Check for X-Content-Type-Options
    if (!headers.get("x-content-type-options")) {
      issues.push({
        title: "Missing X-Content-Type-Options Header",
        severity: "MEDIUM",
        description: "The X-Content-Type-Options header is not set, allowing MIME type sniffing",
        impact: "Browsers may interpret files as a different content-type",
        remediation: "Set X-Content-Type-Options header to 'nosniff'",
      })
    }

    // Check for X-XSS-Protection
    if (!headers.get("x-xss-protection")) {
      issues.push({
        title: "Missing X-XSS-Protection Header",
        severity: "LOW",
        description: "The X-XSS-Protection header is not set",
        impact: "Some browsers' built-in XSS protection may not be activated",
        remediation: "Set X-XSS-Protection header to '1; mode=block'",
      })
    }

    // Check for Referrer-Policy
    if (!headers.get("referrer-policy")) {
      issues.push({
        title: "Missing Referrer-Policy Header",
        severity: "LOW",
        description: "The Referrer-Policy header is not set",
        impact: "Referrer information may be leaked when navigating to external sites",
        remediation: "Set Referrer-Policy header to a restrictive policy like 'same-origin'",
      })
    }

    // Check for Feature-Policy/Permissions-Policy
    if (!headers.get("permissions-policy") && !headers.get("feature-policy")) {
      issues.push({
        title: "Missing Permissions-Policy Header",
        severity: "LOW",
        description: "Neither Permissions-Policy nor Feature-Policy headers are set",
        impact: "Browser features may be used without restriction",
        remediation: "Implement Permissions-Policy header to restrict browser feature usage",
      })
    }

    // Check for information disclosure in headers
    const serverHeader = headers.get("server")
    if (serverHeader && (serverHeader.includes("/") || /\d/.test(serverHeader))) {
      issues.push({
        title: "Server Version Disclosure",
        severity: "LOW",
        description: `Server header reveals version information: ${serverHeader}`,
        impact: "Attackers can identify specific vulnerabilities in server software",
        remediation: "Configure server to hide version information in response headers",
      })
    }

    // Check for X-Powered-By
    const poweredByHeader = headers.get("x-powered-by")
    if (poweredByHeader) {
      issues.push({
        title: "X-Powered-By Disclosure",
        severity: "LOW",
        description: `X-Powered-By header reveals technology stack: ${poweredByHeader}`,
        impact: "Attackers can identify specific technologies and target known vulnerabilities",
        remediation: "Remove or obfuscate the X-Powered-By header",
      })
    }
  } catch (error) {
    issues.push({
      title: "Security Headers Check Failed",
      severity: "LOW",
      description: `Failed to check security headers: ${error}`,
      impact: "Unable to verify header security",
      remediation: "Ensure the server is accessible and responding to requests",
    })
  }

  return issues
}

async function checkCookieSecurity(url: string) {
  const issues: any[] = []

  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(10000),
    })

    // Check for cookies
    const setCookieHeaders = response.headers.getAll ? response.headers.getAll("set-cookie") : []

    if (setCookieHeaders.length > 0) {
      // Check each cookie
      for (const cookieHeader of setCookieHeaders) {
        if (!cookieHeader.includes("Secure")) {
          issues.push({
            title: "Insecure Cookie Configuration",
            severity: "MEDIUM",
            description: "Cookies are set without the Secure flag",
            impact: "Session cookies can be intercepted over insecure connections",
            remediation: "Set the Secure flag on all cookies",
          })
          break // Only report once
        }
      }

      for (const cookieHeader of setCookieHeaders) {
        if (!cookieHeader.includes("HttpOnly")) {
          issues.push({
            title: "Missing HttpOnly Cookie Flag",
            severity: "MEDIUM",
            description: "Cookies are set without the HttpOnly flag",
            impact: "Cookies can be accessed via JavaScript, increasing XSS risk",
            remediation: "Set the HttpOnly flag on all cookies containing sensitive data",
          })
          break // Only report once
        }
      }

      for (const cookieHeader of setCookieHeaders) {
        if (!cookieHeader.includes("SameSite")) {
          issues.push({
            title: "Missing SameSite Cookie Attribute",
            severity: "MEDIUM",
            description: "Cookies are set without the SameSite attribute",
            impact: "Vulnerable to cross-site request forgery (CSRF) attacks",
            remediation: "Set the SameSite attribute to 'Strict' or 'Lax' on all cookies",
          })
          break // Only report once
        }
      }
    }
  } catch (error) {
    // No cookies or error checking
  }

  return issues
}

async function checkInformationDisclosure(url: string) {
  const issues: any[] = []
  const baseUrl = new URL(url).origin

  try {
    // Check robots.txt
    try {
      const robotsResponse = await fetch(`${baseUrl}/robots.txt`, {
        signal: AbortSignal.timeout(5000),
      })

      if (robotsResponse.ok) {
        const robotsText = await robotsResponse.text()
        if (robotsText.includes("admin") || robotsText.includes("private")) {
          issues.push({
            title: "Sensitive Paths in Robots.txt",
            severity: "LOW",
            description: "robots.txt file reveals sensitive directory paths",
            impact: "Potential information disclosure of admin or private areas",
            remediation: "Review robots.txt and remove references to sensitive paths",
          })
        }
      }
    } catch (error) {
      // Robots.txt not found or error - this is normal
    }

    // Check for common sensitive files
    const sensitiveFiles = [".env", "config.php", "wp-config.php", ".git/config"]
    for (const file of sensitiveFiles) {
      try {
        const fileResponse = await fetch(`${baseUrl}/${file}`, {
          method: "HEAD",
          signal: AbortSignal.timeout(3000),
        })
        if (fileResponse.ok) {
          issues.push({
            title: `Exposed Sensitive File: ${file}`,
            severity: "CRITICAL",
            description: `Sensitive configuration file ${file} is publicly accessible`,
            impact: "Critical security information may be exposed",
            remediation: "Block access to configuration files via web server configuration",
          })
        }
      } catch (error) {
        // File not accessible (good)
      }
    }

    // Check for error disclosure
    try {
      const errorResponse = await fetch(`${baseUrl}/nonexistentpage12345`, {
        signal: AbortSignal.timeout(5000),
      })

      const errorText = await errorResponse.text()
      if (
        errorText.includes("SQL syntax") ||
        errorText.includes("ODBC") ||
        errorText.includes("stack trace") ||
        errorText.includes("at /var/www/") ||
        errorText.includes("Exception in thread")
      ) {
        issues.push({
          title: "Error Message Information Disclosure",
          severity: "MEDIUM",
          description: "Detailed error messages are exposed to users",
          impact: "Technical details may help attackers identify vulnerabilities",
          remediation: "Configure custom error pages and disable detailed error reporting in production",
        })
      }
    } catch (error) {
      // Error page check failed
    }
  } catch (error) {
    // Error checking information disclosure
  }

  return issues
}

async function checkAPISecurityIssues(url: string) {
  const issues: any[] = []
  const baseUrl = new URL(url).origin

  // Check for common API security issues
  try {
    // Check for CORS misconfiguration
    const corsResponse = await fetch(url, {
      method: "OPTIONS",
      headers: {
        Origin: "https://evil-site.com",
        "Access-Control-Request-Method": "GET",
      },
      signal: AbortSignal.timeout(5000),
    })

    const allowOrigin = corsResponse.headers.get("access-control-allow-origin")
    if (allowOrigin === "*" || allowOrigin === "https://evil-site.com") {
      issues.push({
        title: "Overly Permissive CORS Policy",
        severity: "HIGH",
        category: "API Security",
        description: "API implements an overly permissive CORS policy",
        impact: "May allow malicious websites to make authenticated requests to the API",
        remediation: "Restrict CORS to specific trusted origins only",
      })
    }

    // Check for common API endpoints
    const commonEndpoints = ["/api", "/api/v1", "/api/users", "/api/auth", "/graphql"]
    for (const endpoint of commonEndpoints) {
      try {
        const endpointResponse = await fetch(`${baseUrl}${endpoint}`, {
          method: "GET",
          signal: AbortSignal.timeout(3000),
        })

        if (endpointResponse.ok) {
          const contentType = endpointResponse.headers.get("content-type")
          if (contentType && (contentType.includes("json") || contentType.includes("graphql"))) {
            issues.push({
              title: `Exposed API Endpoint: ${endpoint}`,
              severity: "MEDIUM",
              category: "API Security",
              description: `API endpoint ${endpoint} is accessible without authentication`,
              impact: "Unauthenticated access to API endpoints may expose sensitive data",
              remediation: "Implement proper authentication for all API endpoints",
            })
          }
        }
      } catch (error) {
        // Endpoint not accessible
      }
    }

    // Check for GraphQL introspection
    try {
      const graphqlEndpoints = ["/graphql", "/api/graphql"]
      for (const endpoint of graphqlEndpoints) {
        const introspectionQuery = {
          query: `{
            __schema {
              queryType { name }
            }
          }`,
        }

        const graphqlResponse = await fetch(`${baseUrl}${endpoint}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(introspectionQuery),
          signal: AbortSignal.timeout(5000),
        })

        if (graphqlResponse.ok) {
          const responseData = await graphqlResponse.json()
          if (responseData && responseData.data && responseData.data.__schema) {
            issues.push({
              title: "GraphQL Introspection Enabled",
              severity: "MEDIUM",
              category: "API Security",
              description: "GraphQL introspection is enabled in production",
              impact: "Attackers can query the API schema to discover all available queries and mutations",
              remediation: "Disable introspection in production environments",
            })
          }
        }
      }
    } catch (error) {
      // GraphQL check failed
    }
  } catch (error) {
    // API security check failed
  }

  return issues
}

async function checkAPIAuthentication(url: string, token?: string) {
  const issues: any[] = []
  const baseUrl = new URL(url).origin

  // Check for authentication issues
  try {
    // Check if API requires authentication
    const endpoints = ["/api/users", "/api/data", "/api/private"]
    let authRequired = false

    for (const endpoint of endpoints) {
      try {
        // Try without auth
        const noAuthResponse = await fetch(`${baseUrl}${endpoint}`, {
          signal: AbortSignal.timeout(3000),
        })

        // Try with auth if token provided
        if (token) {
          const authResponse = await fetch(`${baseUrl}${endpoint}`, {
            headers: {
              Authorization: `Bearer ${token}`,
            },
            signal: AbortSignal.timeout(3000),
          })

          // If auth response is different (better) than no auth, authentication is working
          if (noAuthResponse.status === 401 && authResponse.status === 200) {
            authRequired = true
          }

          // If both succeed, authentication might be optional
          if (noAuthResponse.status === 200 && authResponse.status === 200) {
            issues.push({
              title: "Optional Authentication",
              severity: "MEDIUM",
              category: "Authentication",
              description: `Endpoint ${endpoint} accessible with or without authentication`,
              impact: "Sensitive endpoints may be accessible without proper authentication",
              remediation: "Enforce authentication for all sensitive API endpoints",
            })
          }
        }

        // If no auth required but endpoint returns data
        if (noAuthResponse.status === 200) {
          const contentType = noAuthResponse.headers.get("content-type")
          if (contentType && contentType.includes("json")) {
            issues.push({
              title: "Missing Authentication Requirements",
              severity: "HIGH",
              category: "Authentication",
              description: `API endpoint ${endpoint} accessible without authentication`,
              impact: "Unauthorized access to potentially sensitive API endpoints",
              remediation: "Implement proper authentication for all API endpoints",
            })
          }
        }
      } catch (error) {
        // Endpoint not accessible
      }
    }

    if (!authRequired && !token) {
      issues.push({
        title: "Authentication Mechanism Unknown",
        severity: "LOW",
        category: "Authentication",
        description: "Unable to determine if API requires authentication",
        impact: "Authentication requirements unclear",
        remediation: "Provide authentication token for complete API security assessment",
      })
    }
  } catch (error) {
    // Authentication check failed
  }

  return issues
}

function analyzeJWTToken(token: string) {
  const issues: any[] = []

  try {
    const parts = token.split(".")
    if (parts.length !== 3) {
      issues.push({
        title: "Malformed JWT Token",
        severity: "CRITICAL",
        description: "JWT token does not have the required 3 parts (header.payload.signature)",
        impact: "Invalid token structure indicates implementation issues",
        remediation: "Ensure JWT tokens follow the standard three-part structure",
      })
      return issues
    }

    // Decode header and payload
    const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")))
    const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")))

    // Check algorithm
    if (header.alg === "none") {
      issues.push({
        title: "JWT Algorithm 'none'",
        severity: "CRITICAL",
        description: "Token uses 'none' algorithm which bypasses signature verification",
        impact: "Tokens can be forged without cryptographic verification",
        remediation: "Use strong cryptographic algorithms like RS256 or HS256",
      })
    }

    if (header.alg === "HS256") {
      issues.push({
        title: "Weak JWT Algorithm",
        severity: "MEDIUM",
        description: "Token uses HS256 algorithm which may be vulnerable to brute force attacks",
        impact: "Shared secret may be compromised through brute force",
        remediation: "Consider using RS256 for better security in distributed systems",
      })
    }

    // Check expiration
    if (!payload.exp) {
      issues.push({
        title: "Missing Token Expiration",
        severity: "HIGH",
        description: "JWT token does not include an expiration time (exp claim)",
        impact: "Tokens remain valid indefinitely if compromised",
        remediation: "Always include expiration time in JWT tokens",
      })
    } else {
      const expDate = new Date(payload.exp * 1000)
      const now = new Date()
      if (expDate < now) {
        issues.push({
          title: "Expired JWT Token",
          severity: "MEDIUM",
          description: `JWT token expired on ${expDate.toISOString()}`,
          impact: "Using expired tokens may indicate improper token management",
          remediation: "Implement proper token refresh mechanisms",
        })
      }

      // Check for very long expiration
      const oneYearFromNow = new Date()
      oneYearFromNow.setFullYear(oneYearFromNow.getFullYear() + 1)
      if (expDate > oneYearFromNow) {
        issues.push({
          title: "Excessive JWT Expiration Time",
          severity: "MEDIUM",
          description: "JWT token has an expiration time more than one year in the future",
          impact: "Long-lived tokens increase the risk of compromise",
          remediation: "Use shorter expiration times and implement refresh tokens",
        })
      }
    }

    // Check for sensitive data in payload
    const sensitiveFields = ["password", "secret", "key", "token", "apiKey", "api_key"]
    for (const field of sensitiveFields) {
      if (payload[field]) {
        issues.push({
          title: "Sensitive Data in JWT Payload",
          severity: "HIGH",
          description: `JWT payload contains sensitive field: ${field}`,
          impact: "Sensitive information exposed in client-accessible token",
          remediation: "Remove sensitive data from JWT payload and store securely on server",
        })
      }
    }
  } catch (error) {
    issues.push({
      title: "JWT Analysis Failed",
      severity: "LOW",
      description: `Failed to analyze JWT token: ${error}`,
      impact: "Unable to verify token security",
      remediation: "Ensure JWT token is properly formatted and encoded",
    })
  }

  return issues
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { url, token, mode = "web" } = body

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    // Validate URL format
    try {
      new URL(url)
    } catch (error) {
      return NextResponse.json({ error: "Invalid URL format" }, { status: 400 })
    }

    // Perform security scan based on type
    const scanResults = await performSecurityScan(url, token, mode)

    return NextResponse.json({
      success: true,
      data: scanResults,
    })
  } catch (error) {
    console.error("Scan API error:", error)
    return NextResponse.json({ error: "Failed to process scan request" }, { status: 500 })
  }
}
