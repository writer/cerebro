import type { Metadata } from "next";
import { Geist, Geist_Mono, IBM_Plex_Mono } from "next/font/google";
import { NuqsAdapter } from "nuqs/adapters/next/app";
import { Suspense } from "react";
import "./globals.css";

import AppChrome from "@/components/AppChrome";
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
  description: "Security posture and attack surface management.",
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
                              <AppChrome
                                sidebar={<Sidebar />}
                                topbar={(
                                  <Suspense fallback={null}>
                                    <Topbar />
                                  </Suspense>
                                )}
                                overlays={(
                                  <>
                                    <CommandPaletteShell />
                                    <CerebroAgentPanelShell />
                                  </>
                                )}
                              >
                                <Suspense fallback={null}>{children}</Suspense>
                              </AppChrome>
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
