/**
 * SentinelX AI – Asset Management Service
 * Real-time API service for retrieving and managing network assets.
 */

import apiClient from "./apiClient";
import type { Asset, AssetCreate } from "../types/asset";

export async function fetchAssets(skip = 0, limit = 100): Promise<Asset[]> {
  const response = await apiClient.get<Asset[]>("/assets", {
    params: { skip, limit },
  });
  return response.data;
}

export async function fetchAssetById(id: string): Promise<Asset> {
  const response = await apiClient.get<Asset>(`/assets/${id}`);
  return response.data;
}

export async function createAsset(payload: AssetCreate): Promise<Asset> {
  const response = await apiClient.post<Asset>("/assets", payload);
  return response.data;
}
