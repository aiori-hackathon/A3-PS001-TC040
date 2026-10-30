"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, type ReactNode } from "react";
import {
  Bot,
  BrainCircuit,
  ChevronDown,
  Crosshair,
  FileSearch,
  FlaskConical,
  History,
  LayoutDashboard,
  Menu,
  MessagesSquare,
  Monitor,
  Network,
  Plug,
  ScrollText,
  Settings,
  ShieldCheck,
  Siren,
  X,
} from "lucide-react";

import { AuthGate, SessionMenu } from "@/components/sentivra/auth-gate";
import { StatusPill } from "@/components/sentivra/badges";
import { ThemeToggle } from "@/components/sentivra/theme-toggle";
import { useApi } from "@/hooks/use-api";
import { cn } from "@/lib/utils";
import type { Health } from "@/types/api";

const NAV: { href: string; label: string; icon: typeof Bot; group: "Monitor" | "Detect" | "Try it" }[] = [
  { href: "/", label: "Overview", icon: LayoutDashboard, group: "Monitor" },
  { href: "/threats", label: "Threats", icon: Siren, group: "Monitor" },
  { href: "/network", label: "Network", icon: Network, group: "Detect" },
  { href: "/files", label: "Files", icon: FileSearch, group: "Detect" },
  { href: "/messages", label: "Messages", icon: MessagesSquare, group: "Detect" },
  { href: "/prompt-security", label: "Prompt Security", icon: Bot, group: "Detect" },
  { href: "/endpoint", label: "Endpoint", icon: Monitor, group: "Detect" },
  { href: "/demo", label: "Demo mode", icon: FlaskConical, group: "Try it" },
  { href: "/cyber-defense", label: "Cyber Defense Lab", icon: Crosshair, group: "Try it" },
];

const ADVANCED = [
  { href: "/models", label: "Models", icon: BrainCircuit },
  { href: "/rules", label: "Rules", icon: ScrollText },
  { href: "/integrations", label: "Integrations", icon: Plug },
  { href: "/audit", label: "Audit Log", icon: History },
  { href: "/settings", label: "Settings", icon: Settings },
];

function isActive(pathname: string, href: string) {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);
}

function BackendStatus() {
  const { data, error } = useApi<Health>("/api/v1/health", { refreshInterval: 30_000 });
  if (error) return <StatusPill status="Error" />;
  if (!data) return <span className="text-[13px] text-muted-foreground">Connecting…</span>;
  return (
    <span className="flex items-center gap-2 text-[13px] text-muted-foreground">
      Backend <StatusPill status={data.status === "ok" ? "Available" : "Degraded"} />
    </span>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <AuthGate>
      <Shell>{children}</Shell>
    </AuthGate>
  );
}

function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);
  const groups = [...new Set(NAV.map((n) => n.group))];
  const linkClass = (href: string) => cn(
    "flex items-center gap-2 rounded-md px-2.5 py-2 text-sm text-sidebar-foreground/80 hover:bg-sidebar-accent hover:text-sidebar-foreground",
    isActive(pathname, href) && "bg-sidebar-accent font-medium text-sidebar-foreground",
  );
  return (
    <div className="flex min-h-dvh">
      <aside className="sticky top-0 hidden h-dvh w-60 shrink-0 flex-col border-r bg-sidebar md:flex">
        <Link href="/" className="flex items-center gap-2 border-b px-4 py-4">
          <ShieldCheck className="size-5" aria-hidden />
          <span className="leading-tight">
            <span className="block text-sm font-semibold tracking-[0.18em]">SENTIVRA</span>
             <span className="block text-sm text-muted-foreground">One Security Layer. Every Threat.</span>
          </span>
        </Link>
        <nav className="flex-1 overflow-y-auto px-2 py-3" aria-label="Main">
          {groups.map((group) => (
            <div key={group} className="mb-3">
               <p className="px-2 pb-1 text-sm font-medium tracking-wide text-muted-foreground uppercase">{group}</p>
              <ul className="space-y-0.5">
                {NAV.filter((n) => n.group === group).map(({ href, label, icon: Icon }) => (
                  <li key={href}>
                    <Link
                      href={href}
                      aria-current={isActive(pathname, href) ? "page" : undefined}
                      className={cn(
                        "flex items-center gap-2 rounded-md px-2 py-1.5 text-sm text-sidebar-foreground/80 hover:bg-sidebar-accent hover:text-sidebar-foreground",
                        isActive(pathname, href) && "bg-sidebar-accent font-medium text-sidebar-foreground",
                      )}
                    >
                      <Icon className="size-4" aria-hidden />
                      {label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
          <details className="mb-3" open={ADVANCED.some((item) => isActive(pathname, item.href))}>
            <summary className="flex cursor-pointer list-none items-center justify-between px-2 py-1 text-sm font-medium tracking-wide text-muted-foreground uppercase">
              Advanced <ChevronDown className="size-3" aria-hidden />
            </summary>
            <ul className="mt-1 space-y-0.5">
              {ADVANCED.map(({ href, label, icon: Icon }) => <li key={href}><Link href={href} aria-current={isActive(pathname, href) ? "page" : undefined} className={linkClass(href)}><Icon className="size-4" aria-hidden />{label}</Link></li>)}
            </ul>
          </details>
        </nav>
        <p className="border-t px-4 py-3 text-[13px] text-muted-foreground">
          Demonstration build: local, no automation.
        </p>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b bg-background/85 px-4 py-2.5 backdrop-blur md:px-6">
          <div className="relative md:hidden">
            <button type="button" className="inline-flex items-center gap-2 rounded-md border px-3 py-2 text-sm font-medium" aria-expanded={mobileOpen} onClick={() => setMobileOpen((open) => !open)}>
              {mobileOpen ? <X className="size-4" aria-hidden /> : <Menu className="size-4" aria-hidden />} Menu
            </button>
             {mobileOpen ? <nav className="absolute left-0 top-11 z-20 grid min-w-56 gap-1 rounded-xl border bg-popover p-2 shadow-xl" aria-label="Main mobile">
              {[...NAV, ...ADVANCED].map(({ href, label, icon: Icon }) => <Link key={href} href={href} onClick={() => setMobileOpen(false)} aria-current={isActive(pathname, href) ? "page" : undefined} className={cn("flex items-center gap-2 rounded-md px-3 py-2 text-sm", isActive(pathname, href) ? "bg-muted font-medium" : "text-muted-foreground hover:bg-muted")}><Icon className="size-4" aria-hidden />{label}</Link>)}
            </nav> : null}
          </div>
          <div className="hidden md:block" />
          <div className="flex shrink-0 items-center gap-3">
            <BackendStatus />
            <SessionMenu />
            <ThemeToggle />
          </div>
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 space-y-6 px-4 py-6 md:px-6">{children}</main>
      </div>
    </div>
  );
}
