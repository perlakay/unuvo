import { type NextRequest, NextResponse } from "next/server"

// This endpoint is now handled by the main subdomain-scan GET endpoint
// Redirect to that endpoint for consistency
export async function GET(request: NextRequest) {
  const url = new URL(request.url)
  const requestId = url.searchParams.get("requestId")

  if (!requestId) {
    return NextResponse.json({ error: "Request ID is required" }, { status: 400 })
  }

  // Redirect to the main subdomain-scan endpoint
  const redirectUrl = new URL("/api/subdomain-scan", request.url)
  redirectUrl.searchParams.set("requestId", requestId)

  return Response.redirect(redirectUrl.toString(), 302)
}
