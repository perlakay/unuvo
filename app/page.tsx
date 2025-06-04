"use client"

import type React from "react"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { Scan, ArrowRight, Globe, Zap, Eye, Target } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"

export default function HomePage() {
  const [url, setUrl] = useState("")
  const [isScanning, setIsScanning] = useState(false)
  const router = useRouter()

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!url) return

    setIsScanning(true)

    // Simulate API call to backend
    await new Promise((resolve) => setTimeout(resolve, 2000))

    // Navigate to dashboard with URL parameter
    router.push(`/dashboard?url=${encodeURIComponent(url)}`)
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
                Enter target URL for comprehensive vulnerability assessment
              </CardDescription>
            </CardHeader>
            <CardContent className="p-8">
              <form onSubmit={handleScan} className="space-y-8">
                <div className="relative group">
                  <div className="absolute inset-0 bg-gradient-to-r from-purple-500/20 to-cyan-500/20 rounded-xl blur-xl group-focus-within:blur-2xl transition-all duration-300" />
                  <div className="relative">
                    <Globe className="absolute left-4 top-1/2 transform -translate-y-1/2 text-gray-400 h-6 w-6 z-10" />
                    <Input
                      type="url"
                      placeholder="https://target-domain.com"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      className="pl-14 h-16 text-lg bg-black/60 border-white/20 text-white placeholder:text-gray-500 focus:border-purple-500/50 focus:ring-purple-500/20 rounded-xl backdrop-blur-sm"
                      required
                    />
                  </div>
                </div>
                <Button
                  type="submit"
                  className="w-full h-16 text-lg font-bold bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-700 hover:to-cyan-700 border-0 rounded-xl shadow-lg hover:shadow-purple-500/25 transition-all duration-300"
                  disabled={!url || !isValidUrl(url) || isScanning}
                >
                  {isScanning ? (
                    <>
                      <Scan className="mr-3 h-6 w-6 animate-spin" />
                      SCANNING TARGET...
                    </>
                  ) : (
                    <>
                      <Zap className="mr-3 h-6 w-6" />
                      INITIATE SCAN
                      <ArrowRight className="ml-3 h-6 w-6" />
                    </>
                  )}
                </Button>
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
