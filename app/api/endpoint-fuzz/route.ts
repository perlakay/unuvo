import { type NextRequest, NextResponse } from "next/server"

// API endpoint fuzzing with real requests
async function fuzzEndpoints(baseUrl: string) {
  const endpoints: any[] = []
  const baseUrlObj = new URL(baseUrl)
  const origin = baseUrlObj.origin

  // Smart wordlist for API endpoints
  const apiPaths = [
    // Common API paths
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/rest",
    "/rest/v1",
    "/rest/v2",
    "/graphql",
    "/gql",

    // Authentication endpoints
    "/auth",
    "/auth/login",
    "/auth/logout",
    "/auth/register",
    "/login",
    "/logout",
    "/signin",
    "/signup",
    "/register",
    "/oauth",
    "/oauth/token",
    "/oauth/authorize",
    "/token",
    "/refresh",
    "/verify",

    // User management
    "/users",
    "/user",
    "/profile",
    "/account",
    "/accounts",
    "/admin",
    "/admin/users",
    "/admin/dashboard",
    "/dashboard",
    "/panel",
    "/control",

    // Data endpoints
    "/data",
    "/export",
    "/import",
    "/backup",
    "/restore",
    "/search",
    "/query",
    "/filter",
    "/upload",
    "/download",
    "/files",
    "/documents",

    // Status and monitoring
    "/status",
    "/health",
    "/ping",
    "/version",
    "/info",
    "/metrics",
    "/stats",
    "/analytics",
    "/logs",
    "/debug",
    "/test",
    "/dev",

    // Common resources
    "/products",
    "/items",
    "/orders",
    "/payments",
    "/customers",
    "/clients",
    "/contacts",
    "/settings",
    "/config",
    "/configuration",
    "/notifications",
    "/messages",
    "/alerts",

    // Documentation
    "/docs",
    "/documentation",
    "/help",
    "/support",
    "/swagger",
    "/openapi",
    "/api-docs",

    // Security-related
    "/.env",
    "/.git",
    "/config.php",
    "/wp-config.php",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known",
    "/security.txt",
    "/.htaccess",
  ]

  const httpMethods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"]

  // Fuzz endpoints with real requests
  const fuzzPromises = apiPaths.map(async (path) => {
    // Try GET/HEAD first as it's less intrusive
    try {
      const startTime = Date.now()
      const response = await fetch(`${origin}${path}`, {
        method: "HEAD",
        signal: AbortSignal.timeout(5000),
      })
      const endTime = Date.now()

      const endpoint = {
        endpoint: path,
        method: "HEAD",
        status: response.status,
        responseTime: endTime - startTime,
        contentLength: Number.parseInt(response.headers.get("content-length") || "0"),
        vulnerabilities: [],
      }

      // Check for potential vulnerabilities based on response
      if (response.status === 200 && path.includes("admin")) {
        endpoint.vulnerabilities.push("Exposed Admin Panel")
      }

      if (response.status === 200 && (path.includes(".env") || path.includes("config"))) {
        endpoint.vulnerabilities.push("Sensitive File Exposure")
      }

      if (response.status === 500) {
        endpoint.vulnerabilities.push("Internal Server Error")
      }

      // Only include interesting responses
      if (response.status !== 404) {
        endpoints.push(endpoint)
      }

      // If HEAD works, try other methods for API endpoints
      if (
        (response.status === 200 || response.status === 204) &&
        (path.startsWith("/api") || path.startsWith("/rest") || path.includes("graphql"))
      ) {
        // Try OPTIONS to see allowed methods
        try {
          const optionsResponse = await fetch(`${origin}${path}`, {
            method: "OPTIONS",
            signal: AbortSignal.timeout(3000),
          })

          const allowedMethods =
            optionsResponse.headers.get("allow") || optionsResponse.headers.get("access-control-allow-methods") || ""

          // If OPTIONS reveals allowed methods, add them
          if (allowedMethods) {
            const methods = allowedMethods.split(",").map((m) => m.trim())
            for (const method of methods) {
              if (method !== "HEAD" && method !== "OPTIONS" && httpMethods.includes(method)) {
                endpoints.push({
                  endpoint: path,
                  method,
                  status: 200, // Assumed since it's in allowed methods
                  responseTime: 0,
                  contentLength: 0,
                  vulnerabilities: [],
                })
              }
            }
          }
        } catch (error) {
          // OPTIONS request failed
        }
      }
    } catch (error) {
      // Endpoint not accessible or timeout
    }
  })

  // Wait for all fuzzing to complete
  await Promise.allSettled(fuzzPromises)

  // Sort by status code and response time
  endpoints.sort((a, b) => {
    if (a.status !== b.status) return a.status - b.status
    return a.responseTime - b.responseTime
  })

  return endpoints
}

export async function POST(request: NextRequest) {
  try {
    const { url } = await request.json()

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    // Perform endpoint fuzzing
    const endpoints = await fuzzEndpoints(url)

    return NextResponse.json({
      success: true,
      endpoints,
      total: endpoints.length,
    })
  } catch (error) {
    console.error("Endpoint fuzzing error:", error)
    return NextResponse.json({ error: "Failed to fuzz endpoints" }, { status: 500 })
  }
}
