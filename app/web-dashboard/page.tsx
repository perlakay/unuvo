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
  Search,
  Shield,
  Loader2,
} from "lucide-react"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { toast } from "@/components/ui/use-toast"

interface Vulnerability {
  id: number
  title: string
  severity: string
  category: string
  description: string
  impact?: string
  remediation?: string
}

interface SubdomainResult {
  subdomain: string
  status: string
  ip?: string
  technologies?: string[]
}

interface WebScanResult {
  url: string
  scanDate: string
  securityScore: number
  totalVulnerabilities: number
  critical: number
  high: number
  medium: number
  low: number
  vulnerabilities: Vulnerability[]
  subdomains?: SubdomainResult[]
}

function WebDashboardContent() {
  const searchParams = useSearchParams()
  const scannedUrl = searchParams.get("url") || ""

  const [scanResults, setScanResults] = useState<WebScanResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [subdomainScanning, setSubdomainScanning] = useState(false)
  const [subdomainResults, setSubdomainResults] = useState<SubdomainResult[]>([])
  const [subdomainProgress, setSubdomainProgress] = useState(0)
  const [subdomainScanId, setSubdomainScanId] = useState<string | null>(null)
  const [subdomainDialogOpen, setSubdomainDialogOpen] = useState(false)
  const [hasScannedSubdomains, setHasScannedSubdomains] = useState(false)

  useEffect(() => {
    const fetchScanResults = async () => {
      setLoading(true)
      setError("")

      try {
        const storedResult = localStorage.getItem("scanResults")
        if (storedResult) {
          const results = JSON.parse(storedResult)
          setScanResults(results)
          if (results.subdomains && results.subdomains.length > 0) {
            setSubdomainResults(results.subdomains)
            setHasScannedSubdomains(true)
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

  // Poll for subdomain scan progress
  useEffect(() => {
    if (!subdomainScanId || !subdomainScanning) return

    console.log(`Starting polling for scan ID: ${subdomainScanId}`)

    const pollInterval = setInterval(async () => {
      try {
        console.log(`Polling scan status for: ${subdomainScanId}`)
        const response = await fetch(`/api/subdomain-scan?scanId=${subdomainScanId}`)
        const data = await response.json()

        console.log("Poll response:", data)

        if (data.success) {
          setSubdomainProgress(data.progress)

          // Update results in real-time
          if (data.results && data.results.length > 0) {
            setSubdomainResults(data.results)
            console.log(`Updated results: ${data.results.length} subdomains found`)
          }

          // Check if scan is complete
          if (data.completed) {
            console.log("Scan completed!")
            clearInterval(pollInterval)
            setSubdomainScanning(false)
            setHasScannedSubdomains(true)

            // Update local storage
            if (scanResults && data.results) {
              const updatedResults = {
                ...scanResults,
                subdomains: data.results,
              }
              localStorage.setItem("scanResults", JSON.stringify(updatedResults))
              setScanResults(updatedResults)
            }

            if (data.error) {
              toast({
                title: "Subdomain Scan Failed",
                description: data.error,
                variant: "destructive",
              })
            } else {
              toast({
                title: "Subdomain Discovery Complete",
                description: `Found ${data.results.length} subdomains for ${new URL(scanResults?.url || "").hostname}`,
              })
            }
          }
        } else {
          console.error("Poll failed:", data.error)
        }
      } catch (error) {
        console.error("Error polling subdomain progress:", error)
      }
    }, 2000) // Poll every 2 seconds

    return () => {
      console.log("Cleaning up polling interval")
      clearInterval(pollInterval)
    }
  }, [subdomainScanId, subdomainScanning, scanResults])

  const handleSubdomainScan = async () => {
    if (!scanResults) return

    console.log(`Starting subdomain scan for: ${scanResults.url}`)
    setSubdomainScanning(true)
    setSubdomainProgress(0)
    setSubdomainResults([])
    setSubdomainDialogOpen(true)
    setHasScannedSubdomains(true)

    try {
      const response = await fetch("/api/subdomain-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: scanResults.url }),
      })

      const data = await response.json()
      console.log("Scan start response:", data)

      if (data.success) {
        setSubdomainScanId(data.scanId)
        console.log(`Scan started with ID: ${data.scanId}`)
      } else {
        throw new Error(data.error || "Failed to start subdomain scan")
      }
    } catch (error) {
      console.error("Subdomain scan failed:", error)
      setSubdomainScanning(false)
      toast({
        title: "Subdomain Scan Failed",
        description: "There was an error starting the subdomain discovery process.",
        variant: "destructive",
      })
    }
  }

  const handleExportReport = () => {
    if (!scanResults) return

    const report = {
      scanType: "Web Security Scan",
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
      subdomains: subdomainResults,
      generatedAt: new Date().toISOString(),
    }

    const dataStr = JSON.stringify(report, null, 2)
    const dataUri = "data:application/json;charset=utf-8," + encodeURIComponent(dataStr)
    const exportFileDefaultName = `web-security-report-${new URL(scanResults.url).hostname}-${new Date().toISOString().split("T")[0]}.json`

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

  // Function to render subdomain count
  const renderSubdomainCount = () => {
    if (subdomainScanning) {
      return (
        <span className="flex items-center">
          <Loader2 className="h-6 w-6 mr-2 animate-spin" />
          <span className="text-2xl">{subdomainResults.length}</span>
        </span>
      )
    }

    if (!hasScannedSubdomains) {
      return <span className="text-2xl text-gray-500">—</span>
    }

    return subdomainResults.length
  }

  // Helper function to safely check status
  const getStatusClass = (subdomain: SubdomainResult) => {
    const status = subdomain?.status || ""

    if (status.includes && status.includes("Active")) {
      if (status.includes("HTTPS")) {
        return "bg-green-500/20 text-green-400"
      }
      return "bg-yellow-500/20 text-yellow-400"
    } else if (status.includes && status.includes("Found")) {
      return "bg-blue-500/20 text-blue-400"
    }
    return "bg-gray-500/20 text-gray-400"
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-center">
          <Scan className="h-12 w-12 text-purple-400 animate-spin mx-auto mb-4" />
          <div className="text-white text-xl">Loading web security analysis...</div>
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
      <div className="absolute inset-0 bg-gradient-to-br from-purple-900/10 via-black to-cyan-900/10" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,rgba(120,119,198,0.05),transparent_50%)]" />

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
                <span className="bg-gradient-to-r from-purple-400 to-cyan-400 bg-clip-text text-transparent">
                  WEB SECURITY ANALYSIS
                </span>
              </h1>
              <div className="flex items-center text-gray-400 space-x-6">
                <div className="flex items-center">
                  <Shield className="h-4 w-4 mr-2" />
                  <span className="text-sm">Web Application Scan</span>
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
          <Card className="bg-black/40 backdrop-blur-xl border border-white/10 hover:border-purple-500/30 transition-all duration-300">
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

          <Card className="bg-black/40 backdrop-blur-xl border border-white/10 hover:border-cyan-500/30 transition-all duration-300">
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <p className="text-sm font-medium text-gray-400 uppercase tracking-wider">Subdomains</p>
                  <p className="text-4xl font-black text-cyan-400 mt-2">{renderSubdomainCount()}</p>
                </div>
                <div className="p-3 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20">
                  <Search className="h-8 w-8 text-cyan-400" />
                </div>
              </div>
              {subdomainScanning && (
                <div className="mt-2">
                  <Progress value={subdomainProgress} className="h-1 bg-gray-800" />
                  <p className="text-xs text-gray-400 mt-1">
                    {subdomainResults.length > 0
                      ? `Found ${subdomainResults.length} subdomains... ${subdomainProgress}%`
                      : `Discovering subdomains... ${subdomainProgress}%`}
                  </p>
                </div>
              )}
              {!hasScannedSubdomains && !subdomainScanning && (
                <p className="text-xs text-gray-500 mt-2">Click "Discover" to find subdomains</p>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Subdomain Discovery & Export */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
          <Card className="lg:col-span-2 bg-black/40 backdrop-blur-xl border border-white/10">
            <CardHeader>
              <CardTitle className="text-2xl font-bold text-white">Subdomain Discovery</CardTitle>
              <CardDescription className="text-gray-400">
                Find hidden subdomains and expand attack surface analysis
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="p-4 rounded-xl bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/20">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-3">
                    <Search className="h-6 w-6 text-cyan-400" />
                    <div>
                      <h3 className="font-semibold text-white">DNS & Certificate Discovery</h3>
                      <p className="text-sm text-gray-400">DNS enumeration and certificate transparency search</p>
                    </div>
                  </div>
                  <Dialog open={subdomainDialogOpen} onOpenChange={setSubdomainDialogOpen}>
                    <DialogTrigger asChild>
                      <Button
                        onClick={handleSubdomainScan}
                        disabled={subdomainScanning}
                        className="bg-cyan-600/20 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-600/30"
                      >
                        {subdomainScanning ? (
                          <>
                            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                            Scanning... {subdomainProgress}%
                          </>
                        ) : (
                          <>
                            <Search className="h-4 w-4 mr-2" />
                            Discover
                          </>
                        )}
                      </Button>
                    </DialogTrigger>
                    <DialogContent className="bg-black/90 border border-white/20 text-white max-w-4xl max-h-[80vh] overflow-y-auto">
                      <DialogHeader>
                        <DialogTitle className="text-2xl font-bold text-cyan-400">
                          Subdomain Discovery Results
                        </DialogTitle>
                        <DialogDescription className="text-gray-400">
                          {subdomainScanning
                            ? `Discovering subdomains for ${new URL(scanResults.url).hostname}...`
                            : `Found ${subdomainResults.length} subdomains for ${new URL(scanResults.url).hostname}`}
                        </DialogDescription>
                      </DialogHeader>

                      {subdomainScanning && (
                        <div className="py-8 text-center">
                          <Loader2 className="h-12 w-12 text-cyan-400 animate-spin mx-auto mb-4" />
                          <h3 className="text-xl font-semibold text-white mb-4">Discovering Subdomains</h3>
                          <Progress value={subdomainProgress} className="h-2 bg-gray-800 mb-4" />
                          <p className="text-gray-400">
                            {subdomainProgress < 30 && "Checking DNS records..."}
                            {subdomainProgress >= 30 && subdomainProgress < 70 && "Searching certificate logs..."}
                            {subdomainProgress >= 70 && "Verifying discovered subdomains..."}
                          </p>
                          {subdomainResults.length > 0 && (
                            <p className="text-cyan-400 mt-4">Found {subdomainResults.length} subdomains so far</p>
                          )}
                        </div>
                      )}

                      <div className="space-y-4 mt-6">
                        {subdomainResults.map((subdomain, index) => (
                          <div key={index} className="p-4 rounded-lg bg-white/5 border border-white/10">
                            <div className="flex items-center justify-between">
                              <div>
                                <h4 className="font-semibold text-white">{subdomain.subdomain}</h4>
                                <p className="text-sm text-gray-400">Status: {subdomain.status || "Unknown"}</p>
                                {subdomain.ip && subdomain.ip !== "Unknown" && (
                                  <p className="text-sm text-gray-400">IP: {subdomain.ip}</p>
                                )}
                              </div>
                              <Badge className={getStatusClass(subdomain)}>{subdomain.status || "Unknown"}</Badge>
                            </div>
                            {subdomain.technologies && subdomain.technologies.length > 0 && (
                              <div className="mt-2">
                                <p className="text-xs text-gray-500">Technologies:</p>
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {subdomain.technologies.map((tech, techIndex) => (
                                    <Badge
                                      key={techIndex}
                                      variant="outline"
                                      className="text-xs border-white/20 text-gray-300"
                                    >
                                      {tech}
                                    </Badge>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                        {!subdomainScanning && subdomainResults.length === 0 && hasScannedSubdomains && (
                          <div className="text-center py-8">
                            <Search className="h-12 w-12 text-gray-500 mx-auto mb-4" />
                            <p className="text-gray-400">No subdomains discovered for this domain.</p>
                          </div>
                        )}
                        {!subdomainScanning && !hasScannedSubdomains && (
                          <div className="text-center py-8">
                            <Search className="h-12 w-12 text-gray-500 mx-auto mb-4" />
                            <p className="text-gray-400">Click "Discover" to start scanning for subdomains.</p>
                          </div>
                        )}
                      </div>
                    </DialogContent>
                  </Dialog>
                </div>

                {/* Subdomain status indicator */}
                {subdomainScanning && (
                  <div className="mt-4 p-3 rounded-lg bg-cyan-900/20 border border-cyan-800/30">
                    <div className="flex items-center">
                      <Loader2 className="h-4 w-4 text-cyan-400 animate-spin mr-2" />
                      <span className="text-sm text-cyan-300">
                        Subdomain discovery in progress ({subdomainProgress}%)
                      </span>
                    </div>
                    <Progress value={subdomainProgress} className="h-1 bg-gray-800 mt-2" />
                    <p className="text-xs text-gray-400 mt-1">
                      {subdomainResults.length > 0
                        ? `Found ${subdomainResults.length} subdomains so far`
                        : "Searching for subdomains..."}
                    </p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          <Card className="bg-black/40 backdrop-blur-xl border border-white/10">
            <CardHeader>
              <CardTitle className="text-xl font-bold text-white">Export Report</CardTitle>
              <CardDescription className="text-gray-400">Download comprehensive web security analysis</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button
                onClick={handleExportReport}
                className="w-full justify-start bg-gradient-to-r from-purple-600/20 to-cyan-600/20 border border-purple-500/30 text-white hover:from-purple-600/30 hover:to-cyan-600/30 backdrop-blur-sm"
              >
                <Download className="h-4 w-4 mr-3" />
                Download Web Report
              </Button>
              <div className="text-xs text-gray-500 mt-2">
                Exports comprehensive JSON report including web vulnerabilities, security headers, and subdomains.
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
            <CardTitle className="text-2xl font-bold text-white">Web Security Vulnerabilities</CardTitle>
            <CardDescription className="text-gray-400">Detailed web application security analysis</CardDescription>
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
                          ? "Your website appears to be secure!"
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

export default function WebDashboardPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-black flex items-center justify-center">
          <div className="text-white">Loading web security analysis...</div>
        </div>
      }
    >
      <WebDashboardContent />
    </Suspense>
  )
}
