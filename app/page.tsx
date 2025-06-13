"use client"

import type React from "react"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { Scan, ArrowRight, Globe, Zap, Eye, Target, Code, Shield } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"

export default function HomePage() {
  const [url, setUrl] = useState("")
  const [token, setToken] = useState("")
  const [isScanning, setIsScanning] = useState(false)
  const [error, setError] = useState("")
  const [scanMode, setScanMode] = useState<"web" | "api">("web")
  const router = useRouter()

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!url) return

    setIsScanning(true)
    setError("")

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url,
          token,
          mode: scanMode,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || "Scan failed")
      }

      // Store results in localStorage
      localStorage.setItem("scanResults", JSON.stringify(data.data))

      // Navigate to appropriate dashboard based on scan mode
      if (scanMode === "api") {
        router.push(`/api-dashboard?url=${encodeURIComponent(url)}`)
      } else {
        router.push(`/web-dashboard?url=${encodeURIComponent(url)}`)
      }
    } catch (error) {
      console.error("Scan error:", error)
      setError(error instanceof Error ? error.message : "Failed to start scan")
    } finally {
      setIsScanning(false)
    }
  }

  const isValidUrl = (string: string) => {
    try {
      new URL(string)
      return true
    } catch (_) {
      return false
    }
  }

  return (
    <div className="min-h-screen bg-black relative overflow-hidden">
      {/* Animated background */}
      <div className="absolute inset-0 bg-gradient-to-br from-purple-900/20 via-black to-cyan-900/20" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(120,119,198,0.1),transparent_50%)]" />

      {/* Floating orbs */}
      <div className="absolute top-1/4 left-1/4 w-64 h-64 bg-purple-500/10 rounded-full blur-3xl animate-pulse" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl animate-pulse delay-1000" />

      <div className="relative z-10 container mx-auto px-4 py-32">
        {/* Main Scan Form */}
        <div className="max-w-3xl mx-auto mb-20">
          <Card className="bg-black/40 backdrop-blur-xl border border-white/10 shadow-2xl">
            <CardHeader className="text-center pb-8">
              <CardTitle className="text-3xl font-bold text-white">Initialize Security Scan</CardTitle>
              <CardDescription className="text-gray-400 text-lg">
                Choose scan type and enter target for comprehensive vulnerability assessment
              </CardDescription>
            </CardHeader>
            <CardContent className="p-8">
              {/* Scan Mode Toggle */}
              <div className="mb-8">
                <div className="flex items-center justify-center space-x-8 p-6 rounded-xl bg-gradient-to-r from-purple-500/10 to-cyan-500/10 border border-white/20">
                  <div className="flex items-center space-x-3">
                    <Shield className={`h-6 w-6 ${scanMode === "web" ? "text-purple-400" : "text-gray-500"}`} />
                    <Label
                      htmlFor="scan-mode"
                      className={`text-lg font-semibold ${scanMode === "web" ? "text-white" : "text-gray-400"}`}
                    >
                      Web Security Scan
                    </Label>
                  </div>

                  <Switch
                    id="scan-mode"
                    checked={scanMode === "api"}
                    onCheckedChange={(checked) => setScanMode(checked ? "api" : "web")}
                    className="data-[state=checked]:bg-cyan-600 data-[state=unchecked]:bg-purple-600"
                  />

                  <div className="flex items-center space-x-3">
                    <Label
                      htmlFor="scan-mode"
                      className={`text-lg font-semibold ${scanMode === "api" ? "text-white" : "text-gray-400"}`}
                    >
                      API Security Scan
                    </Label>
                    <Code className={`h-6 w-6 ${scanMode === "api" ? "text-cyan-400" : "text-gray-500"}`} />
                  </div>
                </div>

                <div className="mt-4 text-center">
                  <p className="text-sm text-gray-400">
                    {scanMode === "web"
                      ? "Comprehensive web application security assessment including headers, SSL, and vulnerabilities"
                      : "API endpoint discovery, fuzzing, and security testing with authentication analysis"}
                  </p>
                </div>
              </div>

              <form onSubmit={handleScan} className="space-y-8">
                {scanMode === "web" ? (
                  <>
                    <div className="relative group">
                      <div className="absolute inset-0 bg-gradient-to-r from-purple-500/20 to-cyan-500/20 rounded-xl blur-xl group-focus-within:blur-2xl transition-all duration-300" />
                      <div className="relative">
                        <Globe className="absolute left-4 top-1/2 transform -translate-y-1/2 text-gray-400 h-6 w-6 z-10" />
                        <Input
                          type="url"
                          placeholder="https://target-website.com"
                          value={url}
                          onChange={(e) => setUrl(e.target.value)}
                          className="pl-14 h-16 text-lg bg-black/60 border-white/20 text-white placeholder:text-gray-500 focus:border-purple-500/50 focus:ring-purple-500/20 rounded-xl backdrop-blur-sm"
                          required
                        />
                      </div>
                    </div>

                    {error && (
                      <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-center">
                        {error}
                      </div>
                    )}

                    <Button
                      type="submit"
                      className="w-full h-16 text-lg font-bold bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-700 hover:to-cyan-700 border-0 rounded-xl shadow-lg hover:shadow-purple-500/25 transition-all duration-300"
                      disabled={!url || !isValidUrl(url) || isScanning}
                    >
                      {isScanning ? (
                        <>
                          <Scan className="mr-3 h-6 w-6 animate-spin" />
                          SCANNING WEBSITE...
                        </>
                      ) : (
                        <>
                          <Zap className="mr-3 h-6 w-6" />
                          INITIATE WEB SCAN
                          <ArrowRight className="ml-3 h-6 w-6" />
                        </>
                      )}
                    </Button>
                  </>
                ) : (
                  <div className="p-10 rounded-xl bg-gradient-to-r from-cyan-500/10 to-purple-500/10 border border-cyan-500/20 text-center">
                    <div className="inline-flex items-center px-3 py-1 rounded-full bg-cyan-500/20 text-cyan-400 text-sm font-medium mb-6">
                      <Zap className="w-4 h-4 mr-2" />
                      Coming Soon
                    </div>
                    <h3 className="text-2xl font-bold text-white mb-4">API Security Scanner</h3>
                    <p className="text-gray-400 mb-6">
                      Our advanced API security scanning tool is currently in development. Stay tuned for comprehensive
                      API endpoint discovery, authentication analysis, and vulnerability detection.
                    </p>
                    <Button
                      disabled
                      className="bg-gradient-to-r from-cyan-600/50 to-purple-600/50 hover:from-cyan-600/50 hover:to-purple-600/50 text-white/70 cursor-not-allowed"
                    >
                      Launching Soon
                    </Button>
                  </div>
                )}
              </form>
            </CardContent>
          </Card>
        </div>

        {/* Features */}
        <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
          <Card className="bg-black/30 backdrop-blur-xl border border-white/10 hover:border-purple-500/30 transition-all duration-300 group">
            <CardContent className="p-8 text-center">
              <div className="relative mb-6">
                <div className="p-4 bg-gradient-to-br from-red-500/20 to-orange-500/20 rounded-2xl w-fit mx-auto backdrop-blur-sm">
                  <Target className="h-10 w-10 text-red-400" />
                </div>
                <div className="absolute inset-0 bg-red-500/20 rounded-2xl blur-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
              </div>
              <h3 className="text-xl font-bold mb-3 text-white">Threat Detection</h3>
              <p className="text-gray-400 leading-relaxed">
                Advanced AI-powered vulnerability scanning with real-time threat intelligence and zero-day detection
              </p>
            </CardContent>
          </Card>

          <Card className="bg-black/30 backdrop-blur-xl border border-white/10 hover:border-cyan-500/30 transition-all duration-300 group">
            <CardContent className="p-8 text-center">
              <div className="relative mb-6">
                <div className="p-4 bg-gradient-to-br from-cyan-500/20 to-blue-500/20 rounded-2xl w-fit mx-auto backdrop-blur-sm">
                  <Eye className="h-10 w-10 text-cyan-400" />
                </div>
                <div className="absolute inset-0 bg-cyan-500/20 rounded-2xl blur-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
              </div>
              <h3 className="text-xl font-bold mb-3 text-white">Deep Analysis</h3>
              <p className="text-gray-400 leading-relaxed">
                Comprehensive security posture assessment including headers, certificates, and infrastructure analysis
              </p>
            </CardContent>
          </Card>

          <Card className="bg-black/30 backdrop-blur-xl border border-white/10 hover:border-green-500/30 transition-all duration-300 group">
            <CardContent className="p-8 text-center">
              <div className="relative mb-6">
                <div className="p-4 bg-gradient-to-br from-green-500/20 to-emerald-500/20 rounded-2xl w-fit mx-auto backdrop-blur-sm">
                  <Zap className="h-10 w-10 text-green-400" />
                </div>
                <div className="absolute inset-0 bg-green-500/20 rounded-2xl blur-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
              </div>
              <h3 className="text-xl font-bold mb-3 text-white">Actionable Intel</h3>
              <p className="text-gray-400 leading-relaxed">
                Detailed remediation strategies with priority-based recommendations and compliance mapping
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
