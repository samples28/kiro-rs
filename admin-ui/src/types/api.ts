// 凭据状态响应
export interface CredentialsStatusResponse {
  total: number
  available: number
  currentId: number
  rpm: number
  cooldownEnabled: boolean
  cooldownSeconds: number
  cooldownMaxRequests: number
  credentials: CredentialStatusItem[]
}

// 单个凭据状态
export interface CredentialStatusItem {
  id: number
  priority: number
  disabled: boolean
  failureCount: number
  isCurrent: boolean
  expiresAt: string | null
  authMethod: string | null
  hasProfileArn: boolean
  email?: string
  refreshTokenHash?: string
  apiKeyHash?: string
  maskedApiKey?: string
  successCount: number
  lastUsedAt: string | null
  hasProxy: boolean
  proxyUrl?: string
  refreshFailureCount: number
  disabledReason?: string
  endpoint: string
  cooldownEnabled?: boolean
  cooldownSeconds?: number
  cooldownMaxRequests?: number
  rpm: number
  lastTtfbMs?: number | null
  rateLimitCount: number
  rateLimitCooling: boolean
}

// 余额响应
export interface BalanceResponse {
  id: number
  subscriptionTitle: string | null
  currentUsage: number
  usageLimit: number
  remaining: number
  usagePercentage: number
  nextResetAt: number | null
  email: string | null
  overageStatus?: string | null
}

// 成功响应
export interface SuccessResponse {
  success: boolean
  message: string
}

// 错误响应
export interface AdminErrorResponse {
  error: {
    type: string
    message: string
  }
}

// 请求类型
export interface SetDisabledRequest {
  disabled: boolean
}

export interface SetPriorityRequest {
  priority: number
}

// 添加凭据请求
export interface AddCredentialRequest {
  refreshToken?: string
  authMethod?: 'social' | 'idc' | 'api_key' | 'enterprise' | 'builderid'
  clientId?: string
  clientSecret?: string
  priority?: number
  authRegion?: string
  apiRegion?: string
  machineId?: string
  email?: string
  password?: string
  proxyUrl?: string
  proxyUsername?: string
  proxyPassword?: string
  kiroApiKey?: string
  endpoint?: string
  cooldownEnabled?: boolean
  cooldownSeconds?: number
  cooldownMaxRequests?: number
  autoAllocateProxy?: boolean
}

// 添加凭据响应
export interface AddCredentialResponse {
  success: boolean
  message: string
  credentialId: number
  email?: string
  balance?: BalanceResponse
}

// 冷却限流配置
export interface CooldownConfigResponse {
  enabled: boolean
  seconds: number
  maxRequests: number
}

export interface SetCooldownConfigRequest {
  enabled: boolean
  seconds: number
  maxRequests: number
}

export interface SetCredentialCooldownRequest {
  enabled?: boolean
  seconds?: number
  maxRequests?: number
}

// 缓存 token 估算倍率
export interface CacheRatiosResponse {
  creation: number
  read: number
  uncached: number
  firstTurn: number
  output: number
}

export interface SetCacheRatiosRequest {
  creation: number
  read: number
  uncached: number
  firstTurn: number
  output: number
}

// 缓存模式
export interface CacheModeResponse {
  mode: 'fixed' | 'standard'
}

export interface SetCacheModeRequest {
  mode: 'fixed' | 'standard'
}

// 缓存间歇中断
export interface CacheInterruptResponse {
  enabled: boolean
  minSecs: number
  maxSecs: number
  durationSecs: number
}

export interface SetCacheInterruptRequest {
  enabled: boolean
  minSecs: number
  maxSecs: number
  durationSecs: number
}

// 模型映射
export interface ModelMappingItem {
  from: string
  to: string
}

export interface ModelMappingsResponse {
  mappings: ModelMappingItem[]
  freeModelMappings: ModelMappingItem[]
}

export interface SetModelMappingsRequest {
  mappings: ModelMappingItem[]
  freeModelMappings?: ModelMappingItem[]
}

// 代理设置
export interface SetProxyRequest {
  proxyUrl?: string | null
  proxyUsername?: string | null
  proxyPassword?: string | null
}

// 代理延迟响应
export interface ProxyLatencyResponse {
  latencyMs: number | null
  error?: string
}

// 代理池
export interface ProxyPoolItem {
  id: number
  url: string
  username?: string
  password?: string
  usedByCredentialId?: number | null
  flagged?: boolean
  historyCount?: number
}

export interface ProxyPoolResponse {
  total: number
  available: number
  proxies: ProxyPoolItem[]
}
