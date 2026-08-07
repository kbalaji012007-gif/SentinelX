import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  UsersIcon,
  UserPlusIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  PencilSquareIcon,
  TrashIcon,
  KeyIcon,
  NoSymbolIcon,
  CheckCircleIcon,
  XMarkIcon,
  ShieldCheckIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  EyeIcon,
} from "@heroicons/react/24/outline";

import { useAuth } from "../../contexts/AuthContext";
import {
  fetchUsers,
  createUser,
  updateUser,
  deleteUser,
  resetUserPassword,
  enableUser,
  disableUser,
  type User,
  type CreateUserPayload,
} from "../../services/userService";

export default function UsersPage() {
  const queryClient = useQueryClient();
  const { user: currentUser } = useAuth();

  const isSuperAdmin = currentUser?.role?.name === "Super Administrator";

  // Filters & Pagination State
  const [search, setSearch] = useState("");
  const [selectedRole, setSelectedRole] = useState<string>("");
  const [selectedStatus, setSelectedStatus] = useState<string>("");
  const [page, setPage] = useState(1);
  const pageSize = 15;

  // Modals & Drawer State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showResetModal, setShowResetModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [drawerUser, setDrawerUser] = useState<User | null>(null);

  // Form States
  const [createForm, setCreateForm] = useState<CreateUserPayload>({
    first_name: "",
    last_name: "",
    display_name: "",
    email: "",
    password: "",
    role_name: "SOC Analyst",
    department: "",
    phone: "",
  });

  const [editForm, setEditForm] = useState({
    first_name: "",
    last_name: "",
    email: "",
    role_name: "",
    department: "",
    phone: "",
    is_active: true,
  });

  const [newPassword, setNewPassword] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  // Fetch Users Query
  const { data, isLoading } = useQuery({
    queryKey: ["users-list", search, selectedRole, selectedStatus, page],
    queryFn: () =>
      fetchUsers({
        search: search || undefined,
        role: selectedRole || undefined,
        is_active: selectedStatus === "" ? undefined : selectedStatus === "active",
        page,
        page_size: pageSize,
      }),
    refetchInterval: 15000,
  });

  // Mutations
  const createMutation = useMutation({
    mutationFn: createUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users-list"] });
      setShowCreateModal(false);
      setCreateForm({
        first_name: "",
        last_name: "",
        display_name: "",
        email: "",
        password: "",
        role_name: "SOC Analyst",
        department: "",
        phone: "",
      });
      setFormError(null);
    },
    onError: (err: any) => {
      setFormError(err.response?.data?.detail || "Failed to create user.");
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: any }) => updateUser(id, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users-list"] });
      setShowEditModal(false);
      setSelectedUser(null);
    },
    onError: (err: any) => {
      setFormError(err.response?.data?.detail || "Failed to update user.");
    },
  });

  const resetPasswordMutation = useMutation({
    mutationFn: ({ id, newPwd }: { id: string; newPwd: string }) => resetUserPassword(id, newPwd),
    onSuccess: () => {
      setShowResetModal(false);
      setNewPassword("");
      setSelectedUser(null);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deleteUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users-list"] });
    },
  });

  const toggleStatusMutation = useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) =>
      active ? disableUser(id) : enableUser(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users-list"] });
    },
  });

  const handleOpenEdit = (user: User) => {
    if (!isSuperAdmin) return;
    setSelectedUser(user);
    setEditForm({
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
      role_name: user.role?.name || "SOC Analyst",
      department: user.department || "",
      phone: user.phone || "",
      is_active: user.is_active,
    });
    setShowEditModal(true);
  };

  const users = data?.items || [];
  const total = data?.total || 0;
  const totalPages = Math.ceil(total / pageSize) || 1;

  const rolesList = [
    "Super Administrator",
    "Administrator",
    "SOC Manager",
    "SOC Analyst",
    "Threat Hunter",
    "Incident Responder",
    "Auditor",
    "Read Only",
  ];

  const getRoleBadge = (roleName?: string) => {
    switch (roleName) {
      case "Super Administrator":
        return "bg-purple-500/20 text-purple-400 border-purple-500/40";
      case "Administrator":
        return "bg-blue-500/20 text-blue-400 border-blue-500/40";
      case "SOC Manager":
        return "bg-cyan-500/20 text-cyan-400 border-cyan-500/40";
      case "Threat Hunter":
        return "bg-amber-500/20 text-amber-400 border-amber-500/40";
      case "Incident Responder":
        return "bg-rose-500/20 text-rose-400 border-rose-500/40";
      default:
        return "bg-[var(--color-surface-300)] text-[var(--color-text-secondary)] border-[var(--color-border)]";
    }
  };

  return (
    <div className="space-y-6 animate-fade-in pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-[var(--color-surface-100)] via-[var(--color-surface-200)] to-[var(--color-surface-100)] p-6 rounded-2xl border border-[var(--color-border)] shadow-xl">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <UsersIcon className="w-6 h-6 text-[var(--color-primary-500)]" />
            <h1 className="text-xl font-extrabold text-[var(--color-text-primary)]">
              Enterprise User Management & RBAC Directory
            </h1>
          </div>
          <p className="text-xs text-[var(--color-text-secondary)]">
            Manage platform accounts, role-based access control, security permissions, and bcrypt password credentials
          </p>
        </div>

        {/* RBAC: Add New User button rendered ONLY for Super Administrator */}
        {isSuperAdmin && (
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[var(--color-primary-500)] text-[var(--color-surface-0)] text-xs font-bold hover:bg-[var(--color-primary-600)] transition-all shadow-lg shadow-[var(--color-primary-500)]/20 shrink-0"
          >
            <UserPlusIcon className="w-4 h-4" />
            <span>Add New User</span>
          </button>
        )}
      </div>

      {/* Filter & Search Toolbar */}
      <div className="glass rounded-xl p-4 border border-[var(--color-border)] flex flex-col md:flex-row items-center justify-between gap-4 font-mono text-xs">
        <div className="flex items-center gap-3 w-full md:w-auto flex-1 max-w-md">
          <div className="relative w-full">
            <MagnifyingGlassIcon className="w-4 h-4 text-[var(--color-text-muted)] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search users by name or email..."
              className="w-full pl-9 pr-4 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-primary-500)]"
            />
          </div>
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto">
          <div className="flex items-center gap-1">
            <FunnelIcon className="w-4 h-4 text-[var(--color-text-muted)]" />
            <select
              value={selectedRole}
              onChange={(e) => setSelectedRole(e.target.value)}
              className="px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs text-[var(--color-text-primary)] focus:outline-none"
            >
              <option value="">All Roles</option>
              {rolesList.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>

          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs text-[var(--color-text-primary)] focus:outline-none"
          >
            <option value="">All Statuses</option>
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
          </select>
        </div>
      </div>

      {/* Users Data Table */}
      <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden font-mono text-xs shadow-xl">
        {isLoading ? (
          <div className="p-8 space-y-3">
            {[1, 2, 3, 4].map((n) => (
              <div key={n} className="h-12 w-full skeleton rounded-lg" />
            ))}
          </div>
        ) : users.length === 0 ? (
          <div className="p-12 text-center text-[var(--color-text-muted)] space-y-2">
            <UsersIcon className="w-8 h-8 mx-auto text-[var(--color-text-muted)] opacity-40" />
            <p>No user accounts found matching query criteria.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="bg-[var(--color-surface-200)] text-[var(--color-text-muted)] font-bold uppercase border-b border-[var(--color-border)] text-[10px]">
                <tr>
                  <th className="px-4 py-3">User</th>
                  <th className="px-4 py-3">Email Address</th>
                  <th className="px-4 py-3">Role</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border)]">
                {users.map((user) => (
                  <tr key={user.id} className="hover:bg-[var(--color-surface-200)]/40 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-8 h-8 rounded-full bg-[var(--color-primary-500)]/20 border border-[var(--color-primary-500)]/40 flex items-center justify-center font-bold text-[var(--color-primary-500)] shrink-0">
                          {user.first_name[0]}
                        </div>
                        <div>
                          <p className="font-bold text-[var(--color-text-primary)]">
                            {user.first_name} {user.last_name}
                          </p>
                          <p className="text-[10px] text-[var(--color-text-muted)] font-sans">{user.department || "SecOps"}</p>
                        </div>
                      </div>
                    </td>

                    <td className="px-4 py-3 text-[var(--color-primary-500)] font-bold">{user.email}</td>

                    <td className="px-4 py-3">
                      <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold border ${getRoleBadge(user.role?.name)}`}>
                        {user.role?.name || "SOC Analyst"}
                      </span>
                    </td>

                    <td className="px-4 py-3">
                      {user.is_active ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[var(--color-safe)]/20 text-[var(--color-safe)] border border-[var(--color-safe)]/40 flex items-center gap-1 w-fit">
                          <CheckCircleIcon className="w-3 h-3" />
                          <span>Active</span>
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[var(--color-critical)]/20 text-[var(--color-critical)] border border-[var(--color-critical)]/40 flex items-center gap-1 w-fit">
                          <NoSymbolIcon className="w-3 h-3" />
                          <span>Disabled</span>
                        </span>
                      )}
                    </td>

                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => setDrawerUser(user)}
                          title="View Details"
                          className="px-2.5 py-1 rounded bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] font-mono text-[10px] font-bold flex items-center gap-1"
                        >
                          <EyeIcon className="w-3.5 h-3.5" />
                          <span>View Details</span>
                        </button>

                        {/* RBAC: Privileged mutation buttons rendered ONLY for Super Administrator */}
                        {isSuperAdmin && (
                          <>
                            <button
                              onClick={() => handleOpenEdit(user)}
                              title="Edit User & Role"
                              className="p-1.5 rounded bg-[var(--color-surface-200)] text-[var(--color-primary-500)] hover:bg-[var(--color-primary-500)]/20"
                            >
                              <PencilSquareIcon className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => {
                                setSelectedUser(user);
                                setShowResetModal(true);
                              }}
                              title="Reset Password"
                              className="p-1.5 rounded bg-[var(--color-surface-200)] text-amber-400 hover:bg-amber-400/20"
                            >
                              <KeyIcon className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => toggleStatusMutation.mutate({ id: user.id, active: user.is_active })}
                              title={user.is_active ? "Disable Account" : "Enable Account"}
                              className={`p-1.5 rounded bg-[var(--color-surface-200)] ${
                                user.is_active ? "text-[var(--color-medium)]" : "text-[var(--color-safe)]"
                              }`}
                            >
                              {user.is_active ? <NoSymbolIcon className="w-4 h-4" /> : <CheckCircleIcon className="w-4 h-4" />}
                            </button>
                            <button
                              onClick={() => {
                                if (window.confirm(`Are you sure you want to delete user ${user.email}?`)) {
                                  deleteMutation.mutate(user.id);
                                }
                              }}
                              title="Delete User"
                              className="p-1.5 rounded bg-[var(--color-surface-200)] text-[var(--color-critical)] hover:bg-[var(--color-critical)]/20"
                            >
                              <TrashIcon className="w-4 h-4" />
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        <div className="p-4 bg-[var(--color-surface-200)] border-t border-[var(--color-border)] flex items-center justify-between font-mono text-xs">
          <span className="text-[var(--color-text-muted)]">
            Showing page {page} of {totalPages} ({total} total users)
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="p-1.5 rounded bg-[var(--color-surface-300)] text-[var(--color-text-primary)] disabled:opacity-40"
            >
              <ChevronLeftIcon className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="p-1.5 rounded bg-[var(--color-surface-300)] text-[var(--color-text-primary)] disabled:opacity-40"
            >
              <ChevronRightIcon className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Modal 1: Create New User */}
      {showCreateModal && isSuperAdmin && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in font-mono text-xs">
          <div className="w-full max-w-lg bg-[var(--color-surface-100)] rounded-2xl border border-[var(--color-border)] p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-[var(--color-border)]">
              <h3 className="text-sm font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                <UserPlusIcon className="w-5 h-5 text-[var(--color-primary-500)]" />
                <span>Create New Enterprise User</span>
              </h3>
              <button onClick={() => setShowCreateModal(false)} className="p-1 text-[var(--color-text-muted)] hover:text-white">
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            {formError && (
              <div className="p-3 rounded-xl bg-[var(--color-critical)]/15 border border-[var(--color-critical)]/40 text-[var(--color-critical)] text-xs">
                {formError}
              </div>
            )}

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[10px] uppercase font-bold text-[var(--color-text-muted)] mb-1">First Name *</label>
                <input
                  type="text"
                  value={createForm.first_name}
                  onChange={(e) => setCreateForm({ ...createForm, first_name: e.target.value })}
                  placeholder="First name..."
                  className="w-full px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[var(--color-text-primary)]"
                />
              </div>

              <div>
                <label className="block text-[10px] uppercase font-bold text-[var(--color-text-muted)] mb-1">Last Name *</label>
                <input
                  type="text"
                  value={createForm.last_name}
                  onChange={(e) => setCreateForm({ ...createForm, last_name: e.target.value })}
                  placeholder="Last name..."
                  className="w-full px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[var(--color-text-primary)]"
                />
              </div>

              <div className="col-span-2">
                <label className="block text-[10px] uppercase font-bold text-[var(--color-text-muted)] mb-1">Email Address *</label>
                <input
                  type="email"
                  value={createForm.email}
                  onChange={(e) => setCreateForm({ ...createForm, email: e.target.value })}
                  placeholder="user@sentinelx.ai"
                  className="w-full px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[var(--color-text-primary)]"
                />
              </div>

              <div className="col-span-2">
                <label className="block text-[10px] uppercase font-bold text-[var(--color-text-muted)] mb-1">Password * (Bcrypt Hashed)</label>
                <input
                  type="password"
                  value={createForm.password}
                  onChange={(e) => setCreateForm({ ...createForm, password: e.target.value })}
                  placeholder="Minimum 8 characters..."
                  className="w-full px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[var(--color-text-primary)]"
                />
              </div>

              <div>
                <label className="block text-[10px] uppercase font-bold text-[var(--color-text-muted)] mb-1">Assign Role *</label>
                <select
                  value={createForm.role_name}
                  onChange={(e) => setCreateForm({ ...createForm, role_name: e.target.value })}
                  className="w-full px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[var(--color-text-primary)]"
                >
                  {rolesList.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-[10px] uppercase font-bold text-[var(--color-text-muted)] mb-1">Department</label>
                <input
                  type="text"
                  value={createForm.department}
                  onChange={(e) => setCreateForm({ ...createForm, department: e.target.value })}
                  placeholder="e.g. SOC Ops"
                  className="w-full px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[var(--color-text-primary)]"
                />
              </div>
            </div>

            <div className="pt-3 border-t border-[var(--color-border)] flex justify-end gap-2">
              <button
                onClick={() => setShowCreateModal(false)}
                className="px-4 py-2 rounded-xl bg-[var(--color-surface-300)] text-[var(--color-text-primary)] font-bold"
              >
                Cancel
              </button>
              <button
                onClick={() => createMutation.mutate(createForm)}
                disabled={createMutation.isPending}
                className="px-4 py-2 rounded-xl bg-[var(--color-primary-500)] text-[var(--color-surface-0)] font-bold hover:bg-[var(--color-primary-600)]"
              >
                Create Account
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal 2: Edit User */}
      {showEditModal && selectedUser && isSuperAdmin && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in font-mono text-xs">
          <div className="w-full max-w-lg bg-[var(--color-surface-100)] rounded-2xl border border-[var(--color-border)] p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-[var(--color-border)]">
              <h3 className="text-sm font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                <PencilSquareIcon className="w-5 h-5 text-[var(--color-primary-500)]" />
                <span>Edit User Profile: {selectedUser.email}</span>
              </h3>
              <button onClick={() => setShowEditModal(false)} className="p-1 text-[var(--color-text-muted)] hover:text-white">
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[10px] uppercase font-bold text-[var(--color-text-muted)] mb-1">First Name</label>
                <input
                  type="text"
                  value={editForm.first_name}
                  onChange={(e) => setEditForm({ ...editForm, first_name: e.target.value })}
                  className="w-full px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[var(--color-text-primary)]"
                />
              </div>

              <div>
                <label className="block text-[10px] uppercase font-bold text-[var(--color-text-muted)] mb-1">Last Name</label>
                <input
                  type="text"
                  value={editForm.last_name}
                  onChange={(e) => setEditForm({ ...editForm, last_name: e.target.value })}
                  className="w-full px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[var(--color-text-primary)]"
                />
              </div>

              <div className="col-span-2">
                <label className="block text-[10px] uppercase font-bold text-[var(--color-text-muted)] mb-1">Change Role</label>
                <select
                  value={editForm.role_name}
                  onChange={(e) => setEditForm({ ...editForm, role_name: e.target.value })}
                  className="w-full px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[var(--color-text-primary)]"
                >
                  {rolesList.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="pt-3 border-t border-[var(--color-border)] flex justify-end gap-2">
              <button
                onClick={() => setShowEditModal(false)}
                className="px-4 py-2 rounded-xl bg-[var(--color-surface-300)] text-[var(--color-text-primary)] font-bold"
              >
                Cancel
              </button>
              <button
                onClick={() => updateMutation.mutate({ id: selectedUser.id, payload: editForm })}
                disabled={updateMutation.isPending}
                className="px-4 py-2 rounded-xl bg-[var(--color-primary-500)] text-[var(--color-surface-0)] font-bold"
              >
                Save Changes
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal 3: Reset Password */}
      {showResetModal && selectedUser && isSuperAdmin && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in font-mono text-xs">
          <div className="w-full max-w-sm bg-[var(--color-surface-100)] rounded-2xl border border-[var(--color-border)] p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-[var(--color-border)]">
              <h3 className="text-sm font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                <KeyIcon className="w-5 h-5 text-amber-400" />
                <span>Reset User Password</span>
              </h3>
              <button onClick={() => setShowResetModal(false)} className="p-1 text-[var(--color-text-muted)] hover:text-white">
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            <p className="text-[11px] text-[var(--color-text-secondary)] font-sans">
              Reset password for <strong>{selectedUser.email}</strong>. The new password will be hashed using Bcrypt.
            </p>

            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Enter new password (min 8 chars)..."
              className="w-full px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[var(--color-text-primary)]"
            />

            <div className="pt-3 border-t border-[var(--color-border)] flex justify-end gap-2">
              <button
                onClick={() => setShowResetModal(false)}
                className="px-4 py-2 rounded-xl bg-[var(--color-surface-300)] text-[var(--color-text-primary)] font-bold"
              >
                Cancel
              </button>
              <button
                onClick={() => resetPasswordMutation.mutate({ id: selectedUser.id, newPwd: newPassword })}
                disabled={!newPassword || resetPasswordMutation.isPending}
                className="px-4 py-2 rounded-xl bg-amber-500 text-black font-bold disabled:opacity-50"
              >
                Update Password
              </button>
            </div>
          </div>
        </div>
      )}

      {/* User Details Drawer */}
      {drawerUser && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-fade-in font-mono text-xs">
          <div className="w-full max-w-md bg-[var(--color-surface-100)] border-l border-[var(--color-border)] p-6 space-y-6 overflow-y-auto">
            <div className="flex items-center justify-between border-b border-[var(--color-border)] pb-3">
              <h3 className="text-sm font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                <ShieldCheckIcon className="w-5 h-5 text-[var(--color-primary-500)]" />
                <span>User Profile & Security Scope</span>
              </h3>
              <button onClick={() => setDrawerUser(null)} className="p-1 text-[var(--color-text-muted)] hover:text-white">
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] space-y-2">
                <span className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase block">Account Identity</span>
                <p className="text-base font-bold text-[var(--color-text-primary)]">
                  {drawerUser.first_name} {drawerUser.last_name}
                </p>
                <p className="text-[11px] text-[var(--color-primary-500)] font-bold">{drawerUser.email}</p>
              </div>

              <div className="p-4 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] space-y-2">
                <span className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase block">Assigned Role & Scope</span>
                <span className={`px-3 py-1 rounded text-xs font-bold border ${getRoleBadge(drawerUser.role?.name)}`}>
                  {drawerUser.role?.name || "SOC Analyst"}
                </span>
                <p className="text-[10px] text-[var(--color-text-secondary)] font-sans pt-1">
                  {drawerUser.role?.description || "Assigned SOC platform capabilities and permissions."}
                </p>
              </div>

              <div className="p-4 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] space-y-1 text-[11px]">
                <span className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase block">Account Status & Meta</span>
                <p className="text-[var(--color-text-primary)]">
                  Status: <strong>{drawerUser.is_active ? "Active" : "Disabled"}</strong>
                </p>
                <p className="text-[var(--color-text-primary)]">
                  MFA Enforced: <strong>{drawerUser.mfa_enabled ? "Yes" : "No"}</strong>
                </p>
                <p className="text-[var(--color-text-primary)]">
                  Last Login: <strong>{drawerUser.last_login ? new Date(drawerUser.last_login).toLocaleString() : "Never"}</strong>
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
