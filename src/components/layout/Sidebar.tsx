import React from "react";
import { LayoutDashboard, History, RotateCcw, Settings, ShieldCheck } from "lucide-react";

export type NavTab = "dashboard" | "backups" | "restore" | "settings";

interface SidebarProps {
  activeTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  isEncryptedActive?: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  isEncryptedActive = true,
}) => {
  const navItems: { id: NavTab; label: string; icon: React.ReactNode }[] = [
    {
      id: "dashboard",
      label: "Dashboard",
      icon: <LayoutDashboard className="w-4 h-4" />,
    },
    {
      id: "backups",
      label: "Backup History",
      icon: <History className="w-4 h-4" />,
    },
    {
      id: "restore",
      label: "Restore",
      icon: <RotateCcw className="w-4 h-4" />,
    },
    {
      id: "settings",
      label: "Settings",
      icon: <Settings className="w-4 h-4" />,
    },
  ];

  return (
    <aside className="w-64 bg-zinc-950 border-r border-zinc-800/80 flex flex-col justify-between p-4 select-none shrink-0">
      <div>
        {/* Brand header */}
        <div className="flex items-center gap-3 px-2 py-3 mb-6 border-b border-zinc-800/60">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center text-white shadow-lg shadow-blue-500/20">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-sm font-semibold tracking-tight text-zinc-100">
              Secure Backup
            </h1>
            <p className="text-[11px] font-medium text-zinc-400">
              Zero-Knowledge Vault
            </p>
          </div>
        </div>

        {/* Navigation items */}
        <nav className="space-y-1">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all duration-150 text-left ${
                  isActive
                    ? "bg-blue-600/15 text-blue-400 border border-blue-500/25 shadow-sm"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 border border-transparent"
                }`}
              >
                <span className={isActive ? "text-blue-400" : "text-zinc-400"}>
                  {item.icon}
                </span>
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer / Status */}
      <div className="pt-4 border-t border-zinc-800/60 space-y-2 px-2">
        <div className="flex items-center gap-2 text-xs">
          <span
            className={`w-2 h-2 rounded-full ${
              isEncryptedActive
                ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)]"
                : "bg-amber-500"
            }`}
          />
          <span className="text-zinc-300 font-medium text-[11px]">
            AES-256 Engine Ready
          </span>
        </div>
        <div className="flex items-center justify-between text-[10px] text-zinc-400">
          <span>Tauri v2 Core</span>
          <span className="font-mono bg-zinc-900 px-1.5 py-0.5 rounded text-zinc-400 border border-zinc-800">
            v0.3.0
          </span>
        </div>
      </div>
    </aside>
  );
};
