import { ShieldCheckIcon, UserPlusIcon } from "@heroicons/react/24/outline";
import { mockUsers } from "../../utils/mockData";

export default function UsersPage() {
  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-[var(--color-text-primary)]">User & RBAC Access Management</h1>
          <p className="text-xs text-[var(--color-text-secondary)]">SOC team management, role-based permission assignment, and MFA security status</p>
        </div>
        <button className="px-4 py-2 rounded-lg bg-[var(--color-primary-500)] text-[var(--color-surface-0)] text-xs font-bold shadow-lg shadow-[var(--color-primary-500)]/20 hover:opacity-90 flex items-center gap-2">
          <UserPlusIcon className="w-4 h-4" />
          <span>Provision New Analyst</span>
        </button>
      </div>

      {/* Users Table */}
      <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="bg-[var(--color-surface-200)]/80 text-[var(--color-text-muted)] uppercase text-[10px] tracking-wider border-b border-[var(--color-border)]">
              <th className="p-4">User</th>
              <th className="p-4">Role</th>
              <th className="p-4">Department</th>
              <th className="p-4">MFA Status</th>
              <th className="p-4">Last Login</th>
              <th className="p-4">Status</th>
              <th className="p-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--color-border)] text-[var(--color-text-secondary)]">
            {mockUsers.map((user) => (
              <tr key={user.id} className="hover:bg-[var(--color-surface-200)]/60 transition-colors">
                <td className="p-4 flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-[var(--color-primary-500)]/20 text-[var(--color-primary-500)] font-bold flex items-center justify-center text-xs">
                    {user.name.split(" ").map((n) => n[0]).join("")}
                  </div>
                  <div>
                    <p className="font-bold text-[var(--color-text-primary)]">{user.name}</p>
                    <p className="text-[11px] text-[var(--color-text-muted)] font-mono">{user.email}</p>
                  </div>
                </td>
                <td className="p-4">
                  <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold ${
                    user.role === "Admin" ? "bg-[var(--color-critical)]/20 text-[var(--color-critical)]" :
                    user.role === "SOC Manager" ? "bg-[var(--color-secondary-500)]/20 text-[var(--color-secondary-500)]" :
                    "bg-[var(--color-primary-500)]/20 text-[var(--color-primary-500)]"
                  }`}>
                    {user.role}
                  </span>
                </td>
                <td className="p-4 text-[11px]">{user.department}</td>
                <td className="p-4">
                  {user.mfaEnabled ? (
                    <span className="inline-flex items-center gap-1 text-[10px] font-bold text-[var(--color-safe)] bg-[var(--color-safe)]/10 px-2 py-0.5 rounded border border-[var(--color-safe)]/20">
                      <ShieldCheckIcon className="w-3.5 h-3.5" />
                      MFA Active
                    </span>
                  ) : (
                    <span className="text-[10px] font-bold text-[var(--color-high)] bg-[var(--color-high)]/10 px-2 py-0.5 rounded">
                      MFA Required
                    </span>
                  )}
                </td>
                <td className="p-4 font-mono text-[11px] text-[var(--color-text-muted)]">{user.lastLogin}</td>
                <td className="p-4">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    user.status === "Active" ? "bg-[var(--color-safe)]/20 text-[var(--color-safe)]" : "bg-[var(--color-surface-300)] text-[var(--color-text-muted)]"
                  }`}>
                    {user.status}
                  </span>
                </td>
                <td className="p-4 text-right">
                  <button className="px-3 py-1 text-[11px] font-bold rounded bg-[var(--color-surface-300)] text-[var(--color-text-primary)] hover:bg-[var(--color-primary-500)] hover:text-black transition-all">
                    Edit Role
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
