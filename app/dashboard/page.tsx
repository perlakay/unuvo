"use client"

import { useSearchParams } from "next/navigation"
import { Suspense } from "react"
import {
  ArrowLeft,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Globe,
  Clock,
  Zap,
  Target,
  Eye,
  TrendingUp,
} from "lucide-react"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

// Mock data for demonstration
const mockScanResults = {
  url: "https://example.com",
  scanDate: "2024-01-15T10:30:00Z",
  securityScore: 72,
  totalVulnerabilities: 23,
  critical: 2,
  high: 5,
  medium: 8,
  low: 8,
  vulnerabilities: [
    {
      id: 1,
      title: "Missing Content Security Policy",
      severity: "high",
      category: "Security Headers",
      description:
        "The application does not implement Content Security Policy headers, making it vulnerable to XSS attacks.",
      impact: "High risk of cross-site scripting attacks",
      remediation: "Implement CSP headers with appropriate directives",
    },
    {
      id: 2,
      title: "Weak SSL/TLS Configuration",
      severity: "critical",
      category: "Encryption",
      description: "The server supports weak cipher suites and outdated TLS versions.",
      impact: "Man-in-the-middle attacks possible",
      remediation: "Update TLS configuration to support only TLS 1.2+ with strong ciphers",
    },
    {
      id: 3,
      title: "Missing X-Frame-Options Header",
      severity: "medium",
      category: "Security Headers",
      description: "The X-Frame-Options header is not set, allowing the page to be embedded in frames.",
      impact: "Clickjacking attacks possible",
      remediation: "Set X-Frame-Options header to DENY or SAMEORIGIN",
    },
    {
      id: 4,
      title: "Information Disclosure in Error Pages",
      severity: "low",
      category: "Information Disclosure",
      description: "Error pages reveal sensitive information about the server configuration.",
      impact: "Information leakage to attackers",
      remediation: "Configure custom error pages that don't reveal system information",
    },
  ],
}

function DashboardContent() {
  const searchParams = useSearchParams()
  const scannedUrl = searchParams.get("url") || mockScanResults.url

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

  return (
    <div className="min-h-screen bg-black relative overflow-hidden">
      {/* Animated background */}
      <div className="absolute inset-0 bg-gradient-to-br from-purple-900/10 via-black to-cyan-900/10" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,rgba(120,119,198,0.05),transparent_50%)]" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_70%_80%,rgba(34,211,238,0.05),transparent_50%)]" />

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
                  THREAT ANALYSIS
                </span>
              </h1>
              <div className="flex items-center text-gray-400 space-x-6">
                <div className="flex items-center">
                  <Globe className="h-4 w-4 mr-2" />
                  <span className="font-mono text-sm">{scannedUrl}</span>
                </div>
                <div className="flex items-center">
                  <Clock className="h-4 w-4 mr-2" />
                  <span className="text-sm">{new Date(mockScanResults.scanDate).toLocaleString()}</span>
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
                  <p className={`text-4xl font-black ${getScoreColor(mockScanResults.securityScore)} mt-2`}>
                    {mockScanResults.securityScore}
                  </p>
                </div>
                <div
                  className={`p-3 rounded-xl bg-gradient-to-br ${getScoreGradient(mockScanResults.securityScore)}/20`}
                >
                  <TrendingUp className={`h-8 w-8 ${getScoreColor(mockScanResults.securityScore)}`} />
                </div>
              </div>
              <Progress value={mockScanResults.securityScore} className="h-2 bg-gray-800" />
            </CardContent>
          </Card>

          <Card className="bg-black/40 backdrop-blur-xl border border-white/10 hover:border-orange-500/30 transition-all duration-300">
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <p className="text-sm font-medium text-gray-400 uppercase tracking-wider">Total Threats</p>
                  <p className="text-4xl font-black text-white mt-2">{mockScanResults.totalVulnerabilities}</p>
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
                  <p className="text-4xl font-black text-red-400 mt-2">{mockScanResults.critical}</p>
                </div>
                <div className="p-3 rounded-xl bg-gradient-to-br from-red-500/20 to-pink-500/20">
                  <XCircle className="h-8 w-8 text-red-400" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-black/40 backdrop-blur-xl border border-white/10 hover:border-yellow-500/30 transition-all duration-300">
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <p className="text-sm font-medium text-gray-400 uppercase tracking-wider">High Risk</p>
                  <p className="text-4xl font-black text-orange-400 mt-2">{mockScanResults.high}</p>
                </div>
                <div className="p-3 rounded-xl bg-gradient-to-br from-orange-500/20 to-yellow-500/20">
                  <AlertTriangle className="h-8 w-8 text-orange-400" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Vulnerability Breakdown */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
          <Card className="lg:col-span-2 bg-black/40 backdrop-blur-xl border border-white/10">
            <CardHeader>
              <CardTitle className="text-2xl font-bold text-white">Threat Distribution</CardTitle>
              <CardDescription className="text-gray-400">Security vulnerabilities by severity level</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between p-4 rounded-xl bg-gradient-to-r from-red-500/10 to-red-600/10 border border-red-500/20">
                <div className="flex items-center space-x-4">
                  <div className="w-3 h-3 bg-gradient-to-r from-red-500 to-red-600 rounded-full"></div>
                  <span className="font-semibold text-white">CRITICAL</span>
                </div>
                <div className="flex items-center space-x-4">
                  <span className="text-3xl font-black text-red-400">{mockScanResults.critical}</span>
                  <Progress
                    value={(mockScanResults.critical / mockScanResults.totalVulnerabilities) * 100}
                    className="w-32 h-2 bg-gray-800"
                  />
                </div>
              </div>

              <div className="flex items-center justify-between p-4 rounded-xl bg-gradient-to-r from-orange-500/10 to-red-500/10 border border-orange-500/20">
                <div className="flex items-center space-x-4">
                  <div className="w-3 h-3 bg-gradient-to-r from-orange-500 to-red-500 rounded-full"></div>
                  <span className="font-semibold text-white">HIGH</span>
                </div>
                <div className="flex items-center space-x-4">
                  <span className="text-3xl font-black text-orange-400">{mockScanResults.high}</span>
                  <Progress
                    value={(mockScanResults.high / mockScanResults.totalVulnerabilities) * 100}
                    className="w-32 h-2 bg-gray-800"
                  />
                </div>
              </div>

              <div className="flex items-center justify-between p-4 rounded-xl bg-gradient-to-r from-yellow-500/10 to-orange-500/10 border border-yellow-500/20">
                <div className="flex items-center space-x-4">
                  <div className="w-3 h-3 bg-gradient-to-r from-yellow-500 to-orange-500 rounded-full"></div>
                  <span className="font-semibold text-white">MEDIUM</span>
                </div>
                <div className="flex items-center space-x-4">
                  <span className="text-3xl font-black text-yellow-400">{mockScanResults.medium}</span>
                  <Progress
                    value={(mockScanResults.medium / mockScanResults.totalVulnerabilities) * 100}
                    className="w-32 h-2 bg-gray-800"
                  />
                </div>
              </div>

              <div className="flex items-center justify-between p-4 rounded-xl bg-gradient-to-r from-blue-500/10 to-cyan-500/10 border border-blue-500/20">
                <div className="flex items-center space-x-4">
                  <div className="w-3 h-3 bg-gradient-to-r from-blue-500 to-cyan-500 rounded-full"></div>
                  <span className="font-semibold text-white">LOW</span>
                </div>
                <div className="flex items-center space-x-4">
                  <span className="text-3xl font-black text-blue-400">{mockScanResults.low}</span>
                  <Progress
                    value={(mockScanResults.low / mockScanResults.totalVulnerabilities) * 100}
                    className="w-32 h-2 bg-gray-800"
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-black/40 backdrop-blur-xl border border-white/10">
            <CardHeader>
              <CardTitle className="text-xl font-bold text-white">Quick Actions</CardTitle>
              <CardDescription className="text-gray-400">Recommended next steps</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button className="w-full justify-start bg-gradient-to-r from-purple-600/20 to-cyan-600/20 border border-purple-500/30 text-white hover:from-purple-600/30 hover:to-cyan-600/30 backdrop-blur-sm">
                <Shield className="h-4 w-4 mr-3" />
                Export Intel Report
              </Button>
              <Button className="w-full justify-start bg-gradient-to-r from-orange-600/20 to-red-600/20 border border-orange-500/30 text-white hover:from-orange-600/30 hover:to-red-600/30 backdrop-blur-sm">
                <Zap className="h-4 w-4 mr-3" />
                Schedule Re-scan
              </Button>
              <Button className="w-full justify-start bg-gradient-to-r from-green-600/20 to-emerald-600/20 border border-green-500/30 text-white hover:from-green-600/30 hover:to-emerald-600/30 backdrop-blur-sm">
                <Eye className="h-4 w-4 mr-3" />
                Remediation Guide
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Detailed Vulnerabilities */}
        <Card className="bg-black/40 backdrop-blur-xl border border-white/10">
          <CardHeader>
            <CardTitle className="text-2xl font-bold text-white">Threat Intelligence</CardTitle>
            <CardDescription className="text-gray-400">
              Detailed vulnerability analysis and remediation strategies
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="all" className="w-full">
              <TabsList className="grid w-full grid-cols-5 bg-black/60 border border-white/10">
                <TabsTrigger value="all" className="data-[state=active]:bg-white/10 text-gray-300">
                  All ({mockScanResults.totalVulnerabilities})
                </TabsTrigger>
                <TabsTrigger value="critical" className="data-[state=active]:bg-red-500/20 text-gray-300">
                  Critical ({mockScanResults.critical})
                </TabsTrigger>
                <TabsTrigger value="high" className="data-[state=active]:bg-orange-500/20 text-gray-300">
                  High ({mockScanResults.high})
                </TabsTrigger>
                <TabsTrigger value="medium" className="data-[state=active]:bg-yellow-500/20 text-gray-300">
                  Medium ({mockScanResults.medium})
                </TabsTrigger>
                <TabsTrigger value="low" className="data-[state=active]:bg-blue-500/20 text-gray-300">
                  Low ({mockScanResults.low})
                </TabsTrigger>
              </TabsList>

              <TabsContent value="all" className="space-y-6 mt-8">
                {mockScanResults.vulnerabilities.map((vuln) => (
                  <Card
                    key={vuln.id}
                    className="bg-black/60 backdrop-blur-xl border-l-4 border-l-red-500 border-t border-r border-b border-white/10"
                  >
                    <CardContent className="p-6">
                      <div className="flex items-start justify-between mb-6">
                        <div className="flex items-center space-x-4">
                          <div className="p-2 rounded-lg bg-red-500/20">{getSeverityIcon(vuln.severity)}</div>
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

                        <div className="p-4 rounded-xl bg-red-500/5 border border-red-500/20">
                          <h4 className="font-semibold text-red-400 mb-2 uppercase tracking-wider text-sm">Impact</h4>
                          <p className="text-gray-300 leading-relaxed">{vuln.impact}</p>
                        </div>

                        <div className="p-4 rounded-xl bg-green-500/5 border border-green-500/20">
                          <h4 className="font-semibold text-green-400 mb-2 uppercase tracking-wider text-sm">
                            Remediation
                          </h4>
                          <p className="text-gray-300 leading-relaxed">{vuln.remediation}</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </TabsContent>

              <TabsContent value="critical" className="space-y-6 mt-8">
                {mockScanResults.vulnerabilities
                  .filter((vuln) => vuln.severity === "critical")
                  .map((vuln) => (
                    <Card
                      key={vuln.id}
                      className="bg-black/60 backdrop-blur-xl border-l-4 border-l-red-500 border-t border-r border-b border-white/10"
                    >
                      <CardContent className="p-6">
                        <div className="flex items-start justify-between mb-6">
                          <div className="flex items-center space-x-4">
                            <div className="p-2 rounded-lg bg-red-500/20">{getSeverityIcon(vuln.severity)}</div>
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

                          <div className="p-4 rounded-xl bg-red-500/5 border border-red-500/20">
                            <h4 className="font-semibold text-red-400 mb-2 uppercase tracking-wider text-sm">Impact</h4>
                            <p className="text-gray-300 leading-relaxed">{vuln.impact}</p>
                          </div>

                          <div className="p-4 rounded-xl bg-green-500/5 border border-green-500/20">
                            <h4 className="font-semibold text-green-400 mb-2 uppercase tracking-wider text-sm">
                              Remediation
                            </h4>
                            <p className="text-gray-300 leading-relaxed">{vuln.remediation}</p>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

export default function DashboardPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-black flex items-center justify-center">
          <div className="text-white">Loading threat analysis...</div>
        </div>
      }
    >
      <DashboardContent />
    </Suspense>
  )
}
