/**
 * SentinelX AI – Asset Types
 */

export interface Asset {
  id: string;
  asset_group_id?: string;
  hostname: string;
  asset_name: string;
  asset_type: "Server" | "Workstation" | "Cloud Resource" | "Router" | "Switch" | "Firewall" | "Network Device";
  operating_system?: string;
  ip_address: string;
  mac_address?: string;
  owner?: string;
  department?: string;
  criticality: "Critical" | "High" | "Medium" | "Low";
  status: "Active" | "Inactive" | "Maintenance" | "Decommissioned";
  location?: string;
  serial_number?: string;
  tags?: string[];
  last_seen?: string;
  created_at: string;
  updated_at: string;
}

export interface AssetCreate {
  asset_group_id: string;
  hostname: string;
  asset_name: string;
  asset_type: string;
  operating_system?: string;
  ip_address: string;
  mac_address?: string;
  department?: string;
  criticality?: string;
  status?: string;
}
