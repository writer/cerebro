import type { Metadata } from "next";
import { Geist, Geist_Mono, IBM_Plex_Mono } from "next/font/google";
import { NuqsAdapter } from "nuqs/adapters/next/app";
import { Suspense } from "react";
import "./globals.css";

import CerebroAgentPanelShell from "@/components/agent/CerebroAgentPanelShell";
import { CerebroAgentProvider } from "@/components/agent/CerebroAgentProvider";
import CommandPaletteShell from "@/components/CommandPaletteShell";
import { ApiKeyProvider, CommandPaletteProvider, ConsoleConfigProvider, CurrentUserProvider, GRCQueryProvider, SidebarProvider, ThemeProvider, UserPreferencesProvider } from "@/components/providers";
import { SecurityProducerCatalogProvider } from "@/components/SecurityProducerCatalogProvider";
import Sidebar from "@/components/Sidebar";
import Topbar from "@/components/Topbar";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

const agentMono = IBM_Plex_Mono({
  variable: "--font-agent-mono",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

// Every document must render per request: the CSP script nonce is generated in
// src/proxy.ts for each request, and a build-time prerender would ship script
// tags without it.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Cerebro",
  applicationName: "Cerebro",
  description: "Security posture and attack surface: what can reach production, through which path, and who owns the fix.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${geistSans.variable} ${geistMono.variable} ${agentMono.variable} text-[var(--text-primary)] antialiased`}>
        <NuqsAdapter>
          <ApiKeyProvider>
            <GRCQueryProvider>
              <CurrentUserProvider>
                <ConsoleConfigProvider>
                  <SecurityProducerCatalogProvider>
                    <UserPreferencesProvider>
                      <ThemeProvider>
                        <CerebroAgentProvider>
                          <CommandPaletteProvider>
                            <SidebarProvider>
                              <div className="flex h-screen max-w-full overflow-hidden">
                                <Sidebar />
                                <div className="flex min-w-0 flex-1 flex-col overflow-x-hidden">
                                  <Suspense fallback={null}>
                                    <Topbar />
                                  </Suspense>
                                  <main className="min-w-0 flex-1 overflow-x-hidden overflow-y-auto px-10 py-8 max-lg:px-6 max-md:px-4 max-md:py-5">
                                    <div className="mx-auto w-full max-w-[1480px]">
                                      <Suspense fallback={null}>{children}</Suspense>
                                    </div>
                                  </main>
                                </div>
                              </div>
                              <CommandPaletteShell />
                              <CerebroAgentPanelShell />
                            </SidebarProvider>
                          </CommandPaletteProvider>
                        </CerebroAgentProvider>
                      </ThemeProvider>
                    </UserPreferencesProvider>
                  </SecurityProducerCatalogProvider>
                </ConsoleConfigProvider>
              </CurrentUserProvider>
            </GRCQueryProvider>
          </ApiKeyProvider>
        </NuqsAdapter>
      </body>
    </html>
  );
}
