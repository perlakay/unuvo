"use client"

import { useSearchParams } from "next/navigation"
import { Suspense, useEffect, useState } from "react"
import {
  ArrowLeft,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Globe,
  Clock,
  Target,
  TrendingUp,
  Scan,
  Download,
  Zap,
  Code,
} from "lucide-react"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

interface Vulnerability {
  id: number
  title: string
  severity: string
  category: string
  description: string
  impact?: string
  remediation?: string
}

interface EndpointResult {
  endpoint: string
  method: string
  status: number
  responseTime: number
  contentLength?: number
  vulnerabilities?: string[]
}

interface APIScanResult {
  url: string
  scanDate: string
  securityScore: number
  totalVulnerabilities: number
  critical: number
  high: number
  medium: number
  low: number
  vulnerabilities: Vulnerability[]
  endpoints?: EndpointResult[]
}

function APIDashboardContent() {
  const searchParams = useSearchParams()
  const scannedUrl = searchParams.get("url") || ""

  const [scanResults, setScanResults] = useState<APIScanResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [endpointFuzzing, setEndpointFuzzing] = useState(false)
  const [endpointResults, setEndpointResults] = useState<EndpointResult[]>([])

  useEffect(() => {
    const fetchScanResults = async () => {
      setLoading(true)
      setError("")

      try {
        const storedResult = localStorage.getItem("scanResults")
        if (storedResult) {
          const results = JSON.parse(storedResult)
          setScanResults(results)
          if (results.endpoints) {
            setEndpointResults(results.endpoints)
          }
          setLoading(false)
          return
        }
        setError("No scan results found")
      } catch (err) {
        console.error("Error loading scan results:", err)
        setError("Failed to load scan results")
      } finally {
        setLoading(false)
      }
    }

    fetchScanResults()
  }, [scannedUrl])

  const handleEndpointFuzzing = async () => {
    if (!scanResults) return

    setEndpointFuzzing(true)
    try {
      const response = await fetch("/api/endpoint-fuzz", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: scanResults.url }),
      })

      const data = await response.json()
      if (data.success) {
        setEndpointResults(data.endpoints)
      }
    } catch (error) {
      console.error("Endpoint fuzzing failed:", error)
    } finally {
      setEndpointFuzzing(false)
    }
  }

  const handleExportReport = () => {
    if (!scanResults) return

    const report = {
      scanType: "API Security Scan",
      scanInfo: {
        url: scanResults.url,
        scanDate: scanResults.scanDate,
        securityScore: scanResults.securityScore,
        totalVulnerabilities: scanResults.totalVulnerabilities,
      },
      summary: {
        critical: scanResults.critical,
        high: scanResults.high,
        medium: scanResults.medium,
        low: scanResults.low,
      },
      vulnerabilities: scanResults.vulnerabilities,
      endpoints: endpointResults,
      generatedAt: new Date().toISOString(),
    }

    const dataStr = JSON.stringify(report, null, 2)
    const dataUri = "data:application/json;charset=utf-8," + encodeURIComponent(dataStr)
    const exportFileDefaultName = `api-security-report-${new URL(scanResults.url).hostname}-${new Date().toISOString().split("T")[0]}.json`

    const linkElement = document.createElement("a")
    linkElement.setAttribute("href", dataUri)
    linkElement.setAttribute("download", exportFileDefaultName)
    linkElement.click()
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-gradient-to-r from-red-500 to-red-600"
      case "high":
        return "bg-gradient-to-r from-orange-500 to-red-500"
      case "medium":
        return "bg-gradient-to-r from-yellow-500 to-orange-500"
      case "low":
        return "bg-gradient-to-r from-blue-500 to-cyan-500"
      default:
        return "bg-gradient-to-r from-gray-500 to-gray-600"
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "critical":
        return <XCircle className="h-5 w-5" />
      case "high":
        return <AlertTriangle className="h-5 w-5" />
      case "medium":
        return <Info className="h-5 w-5" />
      case "low":
        return <CheckCircle className="h-5 w-5" />
      default:
        return <Info className="h-5 w-5" />
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-400"
    if (score >= 60) return "text-yellow-400"
    return "text-red-400"
  }

  const getScoreGradient = (score: number) => {
    if (score >= 80) return "from-green-500 to-emerald-500"
    if (score >= 60) return "from-yellow-500 to-orange-500"
    return "from-red-500 to-pink-500"
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-center">
          <Scan className="h-12 w-12 text-cyan-400 animate-spin mx-auto mb-4" />
          <div className="text-white text-xl">Loading API security analysis...</div>
        </div>
      </div>
    )
  }

  if (error || !scanResults) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-center">
          <XCircle className="h-12 w-12 text-red-400 mx-auto mb-4" />
          <div className="text-white text-xl mb-4">{error || "Scan results not found"}</div>
          <Link href="/">
            <Button variant="outline" className="bg-black/40 border-white/20 text-white hover:bg-white/10">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Scanner
            </Button>
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-black relative overflow-hidden">
      {/* Animated background */}
      <div className="absolute inset-0 bg-gradient-to-br from-cyan-900/10 via-black to-purple-900/10" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_70%_20%,rgba(34,211,238,0.05),transparent_50%)]" />

      <div className="relative z-10 container mx-auto px-4 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-12">
          <div className="flex items-center space-x-6">
            <Link href="/">
              <Button
                variant="outline"
                size="sm"
                className="bg-black/40 border-white/20 text-white hover:bg-white/10 backdrop-blur-sm"
              >
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back to Scanner
              </Button>
            </Link>
            <div>
              <h1 className="text-4xl font-black text-white mb-2 tracking-tight">
                <span className="bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                  API SECURITY ANALYSIS
                </span>
              </h1>
              <div className="flex items-center text-gray-400 space-x-6">
                <div className="flex items-center">
                  <Code className="h-4 w-4 mr-2" />
                  <span className="text-sm">API Security Scan</span>
                </div>
                <div className="flex items-center">
                  <Globe className="h-4 w-4 mr-2" />
                  <span className="font-mono text-sm">{scanResults.url}</span>
                </div>
                <div className="flex items-center">
                  <Clock className="h-4 w-4 mr-2" />
                  <span className="text-sm">{new Date(scanResults.scanDate).toLocaleString()}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Overview Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
          <Card className="bg-black/40 backdrop-blur-xl border border-white/10 hover:border-cyan-500/30 transition-all duration-300">
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <p className="text-sm font-medium text-gray-400 uppercase tracking-wider">Security Score</p>
                  <p className={`text-4xl font-black ${getScoreColor(scanResults.securityScore)} mt-2`}>
                    {scanResults.securityScore}
                  </p>
                </div>
                <div className={`p-3 rounded-xl bg-gradient-to-br ${getScoreGradient(scanResults.securityScore)}/20`}>
                  <TrendingUp className={`h-8 w-8 ${getScoreColor(scanResults.securityScore)}`} />
                </div>
              </div>
              <Progress value={scanResults.securityScore} className="h-2 bg-gray-800" />
            </CardContent>
          </Card>

          <Card className="bg-black/40 backdrop-blur-xl border border-white/10 hover:border-orange-500/30 transition-all duration-300">
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <p className="text-sm font-medium text-gray-400 uppercase tracking-wider">Total Threats</p>
                  <p className="text-4xl font-black text-white mt-2">{scanResults.totalVulnerabilities}</p>
                </div>
                <div className="p-3 rounded-xl bg-gradient-to-br from-orange-500/20 to-red-500/20">
                  <Target className="h-8 w-8 text-orange-400" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-black/40 backdrop-blur-xl border border-white/10 hover:border-red-500/30 transition-all duration-300">
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <p className="text-sm font-medium text-gray-400 uppercase tracking-wider">Critical</p>
                  <p className="text-4xl font-black text-red-400 mt-2">{scanResults.critical}</p>
                </div>
                <div className="p-3 rounded-xl bg-gradient-to-br from-red-500/20 to-pink-500/20">
                  <XCircle className="h-8 w-8 text-red-400" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-black/40 backdrop-blur-xl border border-white/10 hover:border-orange-500/30 transition-all duration-300">
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <p className="text-sm font-medium text-gray-400 uppercase tracking-wider">Endpoints</p>
                  <p className="text-4xl font-black text-orange-400 mt-2">{endpointResults.length}</p>
                </div>
                <div className="p-3 rounded-xl bg-gradient-to-br from-orange-500/20 to-yellow-500/20">
                  <Zap className="h-8 w-8 text-orange-400" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* API Endpoint Fuzzing & Export */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
          <Card className="lg:col-span-2 bg-black/40 backdrop-blur-xl border border-white/10">
            <CardHeader>
              <CardTitle className="text-2xl font-bold text-white">API Endpoint Discovery</CardTitle>
              <CardDescription className="text-gray-400">
                Discover hidden API endpoints using smart wordlists and fuzzing
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* API Endpoint Fuzzing - Coming Soon */}
              <div className="p-4 rounded-xl bg-gradient-to-r from-orange-500/10 to-red-500/10 border border-orange-500/20 relative overflow-hidden">
                <div className="absolute top-0 right-0 bg-gradient-to-l from-orange-500/30 to-red-500/30 text-white px-3 py-1 text-xs font-bold uppercase tracking-wider">
                  Coming Soon
                </div>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-3">
                    <Zap className="h-6 w-6 text-orange-400" />
                    <div>
                      <h3 className="font-semibold text-white">Smart Endpoint Fuzzing</h3>
                      <p className="text-sm text-gray-400">Discover hidden API endpoints using intelligent wordlists</p>
                    </div>
                  </div>
                  <Button
                    disabled
                    className="bg-orange-600/20 border border-orange-500/30 text-orange-300 opacity-70 cursor-not-allowed"
                  >
                    <Zap className="h-4 w-4 mr-2" />
                    Launching Soon
                  </Button>
                </div>
                <div className="mt-4 p-3 bg-black/30 rounded-lg border border-orange-500/10">
                  <p className="text-sm text-gray-400">
                    Our advanced API endpoint fuzzing tool is currently in development. This feature will allow you to
                    discover hidden API endpoints, test for vulnerabilities, and analyze authentication mechanisms.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-black/40 backdrop-blur-xl border border-white/10">
            <CardHeader>
              <CardTitle className="text-xl font-bold text-white">Export Report</CardTitle>
              <CardDescription className="text-gray-400">Download comprehensive API security analysis</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button
                onClick={handleExportReport}
                className="w-full justify-start bg-gradient-to-r from-cyan-600/20 to-purple-600/20 border border-cyan-500/30 text-white hover:from-cyan-600/30 hover:to-purple-600/30 backdrop-blur-sm"
              >
                <Download className="h-4 w-4 mr-3" />
                Download API Report
              </Button>
              <div className="text-xs text-gray-500 mt-2">
                Exports comprehensive JSON report including API vulnerabilities, endpoint discoveries, and security
                assessments.
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Threat Distribution */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-12">
          <Card className="bg-black/40 backdrop-blur-xl border border-white/10">
            <CardContent className="p-6">
              <div className="flex items-center justify-between p-4 rounded-xl bg-gradient-to-r from-red-500/10 to-red-600/10 border border-red-500/20">
                <div className="flex items-center space-x-4">
                  <div className="w-3 h-3 bg-gradient-to-r from-red-500 to-red-600 rounded-full"></div>
                  <span className="font-semibold text-white">CRITICAL</span>
                </div>
                <span className="text-3xl font-black text-red-400">{scanResults.critical}</span>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-black/40 backdrop-blur-xl border border-white/10">
            <CardContent className="p-6">
              <div className="flex items-center justify-between p-4 rounded-xl bg-gradient-to-r from-orange-500/10 to-red-500/10 border border-orange-500/20">
                <div className="flex items-center space-x-4">
                  <div className="w-3 h-3 bg-gradient-to-r from-orange-500 to-red-500 rounded-full"></div>
                  <span className="font-semibold text-white">HIGH</span>
                </div>
                <span className="text-3xl font-black text-orange-400">{scanResults.high}</span>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-black/40 backdrop-blur-xl border border-white/10">
            <CardContent className="p-6">
              <div className="flex items-center justify-between p-4 rounded-xl bg-gradient-to-r from-yellow-500/10 to-orange-500/10 border border-yellow-500/20">
                <div className="flex items-center space-x-4">
                  <div className="w-3 h-3 bg-gradient-to-r from-yellow-500 to-orange-500 rounded-full"></div>
                  <span className="font-semibold text-white">MEDIUM</span>
                </div>
                <span className="text-3xl font-black text-yellow-400">{scanResults.medium}</span>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-black/40 backdrop-blur-xl border border-white/10">
            <CardContent className="p-6">
              <div className="flex items-center justify-between p-4 rounded-xl bg-gradient-to-r from-blue-500/10 to-cyan-500/10 border border-blue-500/20">
                <div className="flex items-center space-x-4">
                  <div className="w-3 h-3 bg-gradient-to-r from-blue-500 to-cyan-500 rounded-full"></div>
                  <span className="font-semibold text-white">LOW</span>
                </div>
                <span className="text-3xl font-black text-blue-400">{scanResults.low}</span>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Detailed Vulnerabilities */}
        <Card className="bg-black/40 backdrop-blur-xl border border-white/10">
          <CardHeader>
            <CardTitle className="text-2xl font-bold text-white">API Security Vulnerabilities</CardTitle>
            <CardDescription className="text-gray-400">Detailed API security analysis and findings</CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="all" className="w-full">
              <TabsList className="grid w-full grid-cols-5 bg-black/60 border border-white/10">
                <TabsTrigger value="all" className="data-[state=active]:bg-white/10 text-gray-300">
                  All ({scanResults.totalVulnerabilities})
                </TabsTrigger>
                <TabsTrigger value="critical" className="data-[state=active]:bg-red-500/20 text-gray-300">
                  Critical ({scanResults.critical})
                </TabsTrigger>
                <TabsTrigger value="high" className="data-[state=active]:bg-orange-500/20 text-gray-300">
                  High ({scanResults.high})
                </TabsTrigger>
                <TabsTrigger value="medium" className="data-[state=active]:bg-yellow-500/20 text-gray-300">
                  Medium ({scanResults.medium})
                </TabsTrigger>
                <TabsTrigger value="low" className="data-[state=active]:bg-blue-500/20 text-gray-300">
                  Low ({scanResults.low})
                </TabsTrigger>
              </TabsList>

              {["all", "critical", "high", "medium", "low"].map((severity) => (
                <TabsContent key={severity} value={severity} className="space-y-6 mt-8">
                  {scanResults.vulnerabilities
                    .filter((vuln) => severity === "all" || vuln.severity === severity)
                    .map((vuln) => (
                      <Card
                        key={vuln.id}
                        className={`bg-black/60 backdrop-blur-xl border-l-4 border-l-${
                          vuln.severity === "critical"
                            ? "red"
                            : vuln.severity === "high"
                              ? "orange"
                              : vuln.severity === "medium"
                                ? "yellow"
                                : "blue"
                        }-500 border-t border-r border-b border-white/10`}
                      >
                        <CardContent className="p-6">
                          <div className="flex items-start justify-between mb-6">
                            <div className="flex items-center space-x-4">
                              <div
                                className={`p-2 rounded-lg bg-${
                                  vuln.severity === "critical"
                                    ? "red"
                                    : vuln.severity === "high"
                                      ? "orange"
                                      : vuln.severity === "medium"
                                        ? "yellow"
                                        : "blue"
                                }-500/20`}
                              >
                                {getSeverityIcon(vuln.severity)}
                              </div>
                              <div>
                                <h3 className="font-bold text-xl text-white mb-2">{vuln.title}</h3>
                                <div className="flex items-center space-x-3">
                                  <Badge
                                    className={`${getSeverityColor(vuln.severity)} text-white font-semibold px-3 py-1`}
                                  >
                                    {vuln.severity.toUpperCase()}
                                  </Badge>
                                  <Badge variant="outline" className="border-white/20 text-gray-300 px-3 py-1">
                                    {vuln.category}
                                  </Badge>
                                </div>
                              </div>
                            </div>
                          </div>

                          <div className="space-y-4">
                            <div className="p-4 rounded-xl bg-white/5 border border-white/10">
                              <h4 className="font-semibold text-white mb-2 uppercase tracking-wider text-sm">
                                Description
                              </h4>
                              <p className="text-gray-300 leading-relaxed">{vuln.description}</p>
                            </div>

                            {vuln.impact && (
                              <div className="p-4 rounded-xl bg-red-500/5 border border-red-500/20">
                                <h4 className="font-semibold text-red-400 mb-2 uppercase tracking-wider text-sm">
                                  Impact
                                </h4>
                                <p className="text-gray-300 leading-relaxed">{vuln.impact}</p>
                              </div>
                            )}

                            {vuln.remediation && (
                              <div className="p-4 rounded-xl bg-green-500/5 border border-green-500/20">
                                <h4 className="font-semibold text-green-400 mb-2 uppercase tracking-wider text-sm">
                                  Remediation
                                </h4>
                                <p className="text-gray-300 leading-relaxed">{vuln.remediation}</p>
                              </div>
                            )}
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  {scanResults.vulnerabilities.filter((vuln) => severity === "all" || vuln.severity === severity)
                    .length === 0 && (
                    <div className="text-center py-12">
                      <CheckCircle className="h-16 w-16 text-green-400 mx-auto mb-4" />
                      <h3 className="text-xl font-semibold text-white mb-2">
                        No {severity === "all" ? "" : severity} vulnerabilities found
                      </h3>
                      <p className="text-gray-400">
                        {severity === "all"
                          ? "Your API appears to be secure!"
                          : `No ${severity} severity issues detected.`}
                      </p>
                    </div>
                  )}
                </TabsContent>
              ))}
            </Tabs>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

export default function APIDashboardPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-black flex items-center justify-center">
          <div className="text-white">Loading API security analysis...</div>
        </div>
      }
    >
      <APIDashboardContent />
    </Suspense>
  )
}
