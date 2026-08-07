import apiClient from "./apiClient";

export interface Role {
  id: string;
  name: string;
  description?: string;
}

export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  display_name?: string | null;
  role_id: string;
  role?: Role | null;
  phone?: string | null;
  department?: string | null;
  is_active: boolean;
  mfa_enabled: boolean;
  last_login?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface PaginatedUserList {
  total: number;
  page: number;
  page_size: number;
  items: User[];
}

export interface CreateUserPayload {
  first_name: string;
  last_name: string;
  display_name?: string;
  email: string;
  password: string;
  role_name: string;
  phone?: string;
  department?: string;
}

export interface UpdateUserPayload {
  first_name?: string;
  last_name?: string;
  display_name?: string;
  email?: string;
  role_name?: string;
  phone?: string;
  department?: string;
  is_active?: boolean;
}

export async function fetchUsers(params?: {
  search?: string;
  role?: string;
  is_active?: boolean;
  page?: number;
  page_size?: number;
}): Promise<PaginatedUserList> {
  const { data } = await apiClient.get<PaginatedUserList>("/users", { params });
  return data;
}

export async function createUser(payload: CreateUserPayload): Promise<User> {
  const { data } = await apiClient.post<User>("/users", payload);
  return data;
}

export async function getUserDetails(id: string): Promise<User> {
  const { data } = await apiClient.get<User>(`/users/${id}`);
  return data;
}

export async function updateUser(id: string, payload: UpdateUserPayload): Promise<User> {
  const { data } = await apiClient.put<User>(`/users/${id}`, payload);
  return data;
}

export async function deleteUser(id: string): Promise<void> {
  await apiClient.delete(`/users/${id}`);
}

export async function resetUserPassword(id: string, new_password: string): Promise<void> {
  await apiClient.post(`/users/${id}/reset-password`, { new_password });
}

export async function enableUser(id: string): Promise<User> {
  const { data } = await apiClient.post<User>(`/users/${id}/enable`);
  return data;
}

export async function disableUser(id: string): Promise<User> {
  const { data } = await apiClient.post<User>(`/users/${id}/disable`);
  return data;
}
