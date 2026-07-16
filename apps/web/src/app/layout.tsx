import type { Metadata } from "next";
import { Geist, Geist_Mono, IBM_Plex_Mono } from "next/font/google";
import { NuqsAdapter } from "nuqs/adapters/next/app";
import { Suspense } from "react";
import "./globals.css";

import CerebroAgentPanelShell from "@/components/agent/CerebroAgentPanelShell";
import { CerebroAgentProvider } from "@/components/agent/CerebroAgentProvider";
import CommandPaletteShell from "@/components/CommandPaletteShell";
import { ApiKeyProvider, CommandPaletteProvider, CurrentUserProvider, GRCQueryProvider, SidebarProvider, ThemeProvider, UserPreferencesProvider } from "@/components/providers";
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

export const metadata: Metadata = {
  title: "Cerebro",
  description: "Findings, controls, evidence, and connector health.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${geistSans.variable} ${geistMono.variable} ${agentMono.variable} bg-[var(--app-bg)] text-[var(--text-primary)] antialiased`}>
        <NuqsAdapter>
          <ApiKeyProvider>
            <GRCQueryProvider>
              <CurrentUserProvider>
                <UserPreferencesProvider>
                  <ThemeProvider>
                    <CerebroAgentProvider>
                      <CommandPaletteProvider>
                        <SidebarProvider>
                          <div className="flex h-screen max-w-full overflow-hidden bg-[var(--app-bg)]">
                            <Sidebar />
                            <div className="flex min-w-0 flex-1 flex-col overflow-x-hidden">
                              <Topbar />
                              <main className="min-w-0 flex-1 overflow-x-hidden overflow-y-auto bg-[var(--app-bg)] px-8 py-6 max-md:px-4">
                                <Suspense fallback={null}>{children}</Suspense>
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
              </CurrentUserProvider>
            </GRCQueryProvider>
          </ApiKeyProvider>
        </NuqsAdapter>
      </body>
    </html>
  );
}
