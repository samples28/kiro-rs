import axios from 'axios'
import { storage } from '@/lib/storage'
import type {
  CredentialsStatusResponse,
  BalanceResponse,
  SuccessResponse,
  SetDisabledRequest,
  SetPriorityRequest,
  AddCredentialRequest,
  AddCredentialResponse,
  CooldownConfigResponse,
  SetCooldownConfigRequest,
  SetCredentialCooldownRequest,
  CacheRatiosResponse,
  SetCacheRatiosRequest,
  CacheModeResponse,
  SetCacheModeRequest,
  CacheInterruptResponse,
  SetCacheInterruptRequest,
  ModelMappingsResponse,
  SetModelMappingsRequest,
  SetProxyRequest,
  ProxyLatencyResponse,
  ProxyPoolResponse,
} from '@/types/api'

// 创建 axios 实例
const api = axios.create({
  baseURL: '/api/admin',
  headers: {
    'Content-Type': 'application/json',
  },
})

// 请求拦截器添加 API Key
api.interceptors.request.use((config) => {
  const apiKey = storage.getApiKey()
  if (apiKey) {
    config.headers['x-api-key'] = apiKey
  }
  return config
})

// 获取所有凭据状态
export async function getCredentials(): Promise<CredentialsStatusResponse> {
  const { data } = await api.get<CredentialsStatusResponse>('/credentials')
  return data
}

// 设置凭据禁用状态
export async function setCredentialDisabled(
  id: number,
  disabled: boolean
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(
    `/credentials/${id}/disabled`,
    { disabled } as SetDisabledRequest
  )
  return data
}

// 设置凭据优先级
export async function setCredentialPriority(
  id: number,
  priority: number
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(
    `/credentials/${id}/priority`,
    { priority } as SetPriorityRequest
  )
  return data
}

// 重置失败计数
export async function resetCredentialFailure(
  id: number
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/credentials/${id}/reset`)
  return data
}

// 强制刷新 Token
export async function forceRefreshToken(
  id: number
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/credentials/${id}/refresh`)
  return data
}

// 获取凭据余额
export async function getCredentialBalance(id: number, force?: boolean): Promise<BalanceResponse> {
  const params = force ? '?force=1' : ''
  const { data } = await api.get<BalanceResponse>(`/credentials/${id}/balance${params}`)
  return data
}

// 添加新凭据
export async function addCredential(
  req: AddCredentialRequest
): Promise<AddCredentialResponse> {
  const { data } = await api.post<AddCredentialResponse>('/credentials', req)
  return data
}

// 删除凭据
export async function deleteCredential(id: number): Promise<SuccessResponse> {
  const { data } = await api.delete<SuccessResponse>(`/credentials/${id}`)
  return data
}

// 获取负载均衡模式
export async function getLoadBalancingMode(): Promise<{ mode: 'priority' | 'balanced' }> {
  const { data } = await api.get<{ mode: 'priority' | 'balanced' }>('/config/load-balancing')
  return data
}

// 设置负载均衡模式
export async function setLoadBalancingMode(mode: 'priority' | 'balanced'): Promise<{ mode: 'priority' | 'balanced' }> {
  const { data } = await api.put<{ mode: 'priority' | 'balanced' }>('/config/load-balancing', { mode })
  return data
}

// 获取冷却限流配置
export async function getCooldownConfig(): Promise<CooldownConfigResponse> {
  const { data } = await api.get<CooldownConfigResponse>('/config/cooldown')
  return data
}

// 设置冷却限流配置
export async function setCooldownConfig(req: SetCooldownConfigRequest): Promise<CooldownConfigResponse> {
  const { data } = await api.put<CooldownConfigResponse>('/config/cooldown', req)
  return data
}

// 设置单个凭据的冷却限流配置
export async function setCredentialCooldown(id: number, req: SetCredentialCooldownRequest): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/credentials/${id}/cooldown`, req)
  return data
}

// 获取缓存 token 估算倍率
export async function getCacheRatios(): Promise<CacheRatiosResponse> {
  const { data } = await api.get<CacheRatiosResponse>('/config/cache-ratios')
  return data
}

// 设置缓存 token 估算倍率
export async function setCacheRatios(req: SetCacheRatiosRequest): Promise<CacheRatiosResponse> {
  const { data } = await api.put<CacheRatiosResponse>('/config/cache-ratios', req)
  return data
}

// 获取缓存模式
export async function getCacheMode(): Promise<CacheModeResponse> {
  const { data } = await api.get<CacheModeResponse>('/config/cache-mode')
  return data
}

// 设置缓存模式
export async function setCacheMode(req: SetCacheModeRequest): Promise<CacheModeResponse> {
  const { data } = await api.put<CacheModeResponse>('/config/cache-mode', req)
  return data
}

// 获取缓存间歇中断配置
export async function getCacheInterrupt(): Promise<CacheInterruptResponse> {
  const { data } = await api.get<CacheInterruptResponse>('/config/cache-interrupt')
  return data
}

// 设置缓存间歇中断配置
export async function setCacheInterrupt(req: SetCacheInterruptRequest): Promise<CacheInterruptResponse> {
  const { data } = await api.put<CacheInterruptResponse>('/config/cache-interrupt', req)
  return data
}

// 获取模型映射
export async function getModelMappings(): Promise<ModelMappingsResponse> {
  const { data } = await api.get<ModelMappingsResponse>('/config/model-mappings')
  return data
}

// 设置模型映射
export async function setModelMappings(req: SetModelMappingsRequest): Promise<ModelMappingsResponse> {
  const { data } = await api.put<ModelMappingsResponse>('/config/model-mappings', req)
  return data
}

// 批量开启超额（传 ids 则只对指定凭据操作）
export async function enableOverage(ids?: number[]): Promise<{ results: Array<{ id: number, status: string, message: string }> }> {
  const { data } = await api.post<{ results: Array<{ id: number, status: string, message: string }> }>('/overage/enable', ids ? { ids } : {})
  return data
}

// 设置凭据代理
export async function setCredentialProxy(id: number, req: SetProxyRequest): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/credentials/${id}/proxy`, req)
  return data
}

// 获取代理延迟
export async function getProxyLatency(id: number): Promise<ProxyLatencyResponse> {
  const { data } = await api.get<ProxyLatencyResponse>(`/credentials/${id}/proxy-latency`)
  return data
}

// 获取代理池
export async function getProxyPool(): Promise<ProxyPoolResponse> {
  const { data } = await api.get<ProxyPoolResponse>('/proxy-pool')
  return data
}

// 批量导入代理
export async function importProxies(text: string): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>('/proxy-pool/import', { text })
  return data
}

// 删除代理池中的代理
export async function deletePoolProxy(id: number): Promise<SuccessResponse> {
  const { data } = await api.delete<SuccessResponse>(`/proxy-pool/${id}`)
  return data
}

// 测试代理池中的代理连通性
export async function testPoolProxy(id: number): Promise<ProxyLatencyResponse> {
  const { data } = await api.get<ProxyLatencyResponse>(`/proxy-pool/${id}/test`)
  return data
}

// 获取 429 冷却配置
export async function getRateLimitCooldown(): Promise<{ seconds: number }> {
  const { data } = await api.get<{ seconds: number }>('/config/rate-limit-cooldown')
  return data
}

// 设置 429 冷却配置
export async function setRateLimitCooldown(seconds: number): Promise<{ seconds: number }> {
  const { data } = await api.put<{ seconds: number }>('/config/rate-limit-cooldown', { seconds })
  return data
}

// 批量重置 429 计数
export async function resetRateLimit(ids: number[]): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>('/reset-rate-limit', { ids })
  return data
}

// 批量设置凭据级 429 冷却时长
export async function setCredentialRateLimitCooldown(ids: number[], seconds: number | null): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>('/set-credential-rate-limit-cooldown', { ids, seconds })
  return data
}

// 获取模型价格配置
export async function getModelPrices(): Promise<{ prices: Record<string, { input: number, output: number, cache_read: number, cache_write: number }> }> {
  const { data } = await api.get<{ prices: Record<string, { input: number, output: number, cache_read: number, cache_write: number }> }>('/config/model-prices')
  return data
}

// 设置模型价格配置
export async function setModelPrices(req: { prices: Record<string, { input: number, output: number, cache_read: number, cache_write: number }> }): Promise<{ prices: Record<string, { input: number, output: number, cache_read: number, cache_write: number }> }> {
  const { data } = await api.put<{ prices: Record<string, { input: number, output: number, cache_read: number, cache_write: number }> }>('/config/model-prices', req)
  return data
}

// 获取计费统计
export async function getBillingStats(): Promise<{ credentials: Record<string, { total_cost: number, total_requests: number, by_model: Record<string, { cost: number, requests: number, input_tokens: number, output_tokens: number }> }> }> {
  const { data } = await api.get<{ credentials: Record<string, { total_cost: number, total_requests: number, by_model: Record<string, { cost: number, requests: number, input_tokens: number, output_tokens: number }> }> }>('/billing/stats')
  return data
}
