import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getCredentials,
  setCredentialDisabled,
  setCredentialPriority,
  resetCredentialFailure,
  forceRefreshToken,
  addCredential,
  deleteCredential,
  getLoadBalancingMode,
  setLoadBalancingMode,
  getCooldownConfig,
  setCooldownConfig,
  setCredentialCooldown,
  getCacheRatios,
  setCacheRatios,
  getCacheMode,
  setCacheMode,
  getCacheInterrupt,
  setCacheInterrupt,
  getModelMappings,
  setModelMappings,
  setCredentialProxy,
} from '@/api/credentials'
import type { AddCredentialRequest, SetCooldownConfigRequest, SetCredentialCooldownRequest, SetCacheRatiosRequest, SetCacheModeRequest, SetCacheInterruptRequest, SetModelMappingsRequest, SetProxyRequest } from '@/types/api'

// 查询凭据列表
export function useCredentials() {
  return useQuery({
    queryKey: ['credentials'],
    queryFn: getCredentials,
    refetchInterval: 30000, // 每 30 秒刷新一次
  })
}

// 设置禁用状态
export function useSetDisabled() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, disabled }: { id: number; disabled: boolean }) =>
      setCredentialDisabled(id, disabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 设置优先级
export function useSetPriority() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, priority }: { id: number; priority: number }) =>
      setCredentialPriority(id, priority),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 重置失败计数
export function useResetFailure() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => resetCredentialFailure(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 强制刷新 Token
export function useForceRefreshToken() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => forceRefreshToken(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 添加新凭据
export function useAddCredential() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (req: AddCredentialRequest) => addCredential(req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 删除凭据
export function useDeleteCredential() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => deleteCredential(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 获取负载均衡模式
export function useLoadBalancingMode() {
  return useQuery({
    queryKey: ['loadBalancingMode'],
    queryFn: getLoadBalancingMode,
  })
}

// 设置负载均衡模式
export function useSetLoadBalancingMode() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: setLoadBalancingMode,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['loadBalancingMode'] })
    },
  })
}

// 获取冷却限流配置
export function useCooldownConfig() {
  return useQuery({
    queryKey: ['cooldownConfig'],
    queryFn: getCooldownConfig,
  })
}

// 设置冷却限流配置
export function useSetCooldownConfig() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (req: SetCooldownConfigRequest) => setCooldownConfig(req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cooldownConfig'] })
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 设置单个凭据冷却限流
export function useSetCredentialCooldown() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...req }: { id: number } & SetCredentialCooldownRequest) =>
      setCredentialCooldown(id, req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 获取缓存 token 估算倍率
export function useCacheRatios() {
  return useQuery({
    queryKey: ['cacheRatios'],
    queryFn: getCacheRatios,
  })
}

// 设置缓存 token 估算倍率
export function useSetCacheRatios() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (req: SetCacheRatiosRequest) => setCacheRatios(req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cacheRatios'] })
    },
  })
}

// 获取缓存模式
export function useCacheMode() {
  return useQuery({
    queryKey: ['cacheMode'],
    queryFn: getCacheMode,
  })
}

// 设置缓存模式
export function useSetCacheMode() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (req: SetCacheModeRequest) => setCacheMode(req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cacheMode'] })
    },
  })
}

// 获取缓存间歇中断配置
export function useCacheInterrupt() {
  return useQuery({
    queryKey: ['cacheInterrupt'],
    queryFn: getCacheInterrupt,
  })
}

// 设置缓存间歇中断配置
export function useSetCacheInterrupt() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (req: SetCacheInterruptRequest) => setCacheInterrupt(req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cacheInterrupt'] })
    },
  })
}

// 获取模型映射
export function useModelMappings() {
  return useQuery({
    queryKey: ['modelMappings'],
    queryFn: getModelMappings,
  })
}

// 设置模型映射
export function useSetModelMappings() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (req: SetModelMappingsRequest) => setModelMappings(req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['modelMappings'] })
    },
  })
}

// 设置凭据代理
export function useSetProxy() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...req }: { id: number } & SetProxyRequest) =>
      setCredentialProxy(id, req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}
