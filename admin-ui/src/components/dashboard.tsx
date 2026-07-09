import { useState, useEffect } from 'react'
import { RefreshCw, LogOut, Moon, Sun, Server, Plus, Upload, Trash2, Timer, Database, Layers, Zap, Search, DollarSign, Power, PowerOff } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { storage } from '@/lib/storage'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { CredentialTable } from '@/components/credential-table'
import { AddCredentialDialog } from '@/components/add-credential-dialog'
import { BatchImportDialog } from '@/components/batch-import-dialog'
import { CooldownConfigDialog } from '@/components/cooldown-config-dialog'
import { CacheRatiosDialog } from '@/components/cache-ratios-dialog'
import { ModelMappingDialog } from '@/components/model-mapping-dialog'
import { ModelPricesDialog } from '@/components/model-prices-dialog'
import { ProxyImportDialog } from '@/components/proxy-import-dialog'
import { useCredentials, useDeleteCredential, useLoadBalancingMode, useSetLoadBalancingMode, useCooldownConfig } from '@/hooks/use-credentials'
import { getCredentialBalance, forceRefreshToken, enableOverage, setCredentialCooldown, getProxyPool, getRateLimitCooldown, setRateLimitCooldown, resetRateLimit, setCredentialRateLimitCooldown, setCredentialDisabled } from '@/api/credentials'
import { extractErrorMessage } from '@/lib/utils'
import type { BalanceResponse, ProxyPoolResponse } from '@/types/api'

interface DashboardProps {
  onLogout: () => void
  onNavigate: (page: string) => void
}

export function Dashboard({ onLogout, onNavigate }: DashboardProps) {
  const [addDialogOpen, setAddDialogOpen] = useState(false)
  const [batchImportDialogOpen, setBatchImportDialogOpen] = useState(false)
  const [cooldownDialogOpen, setCooldownDialogOpen] = useState(false)
  const [cacheRatiosDialogOpen, setCacheRatiosDialogOpen] = useState(false)
  const [modelMappingDialogOpen, setModelMappingDialogOpen] = useState(false)
  const [modelPricesDialogOpen, setModelPricesDialogOpen] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [balanceMap, setBalanceMap] = useState<Map<number, BalanceResponse>>(() => {
    try {
      const saved = localStorage.getItem('kiro_balance_map')
      if (saved) {
        const parsed = JSON.parse(saved) as Array<[number, BalanceResponse]>
        return new Map(parsed)
      }
    } catch {}
    return new Map()
  })
  const [, setLoadingBalanceIds] = useState<Set<number>>(new Set())
  const [queryingInfo, setQueryingInfo] = useState(false)
  const [queryInfoProgress, setQueryInfoProgress] = useState({ current: 0, total: 0 })
  const [enablingOverage, setEnablingOverage] = useState(false)
  const [batchRefreshing, setBatchRefreshing] = useState(false)
  const [batchRefreshProgress, setBatchRefreshProgress] = useState({ current: 0, total: 0 })
  const [batchCooldowning, setBatchCooldowning] = useState(false)
  const [batchTogglingDisabled, setBatchTogglingDisabled] = useState(false)
  const [batchCooldownDialogOpen, setBatchCooldownDialogOpen] = useState(false)
  const [batchCooldownMode, setBatchCooldownMode] = useState<'custom' | 'off' | 'global'>('custom')
  const [batchCdSecsInput, setBatchCdSecsInput] = useState('')
  const [batchCdReqsInput, setBatchCdReqsInput] = useState('')
  const [batchCd429Input, setBatchCd429Input] = useState('')
  const [proxyImportOpen, setProxyImportOpen] = useState(false)
  const [proxyPoolData, setProxyPoolData] = useState<ProxyPoolResponse | null>(null)
  const [rateLimitCooldownSecs, setRateLimitCooldownSecs] = useState(30)
  const [rateLimitDialogOpen, setRateLimitDialogOpen] = useState(false)
  const [rateLimitInput, setRateLimitInput] = useState('')
  const [currentPage, setCurrentPage] = useState(1)
  const [itemsPerPage, setItemsPerPage] = useState(20)
  const [selectedProxy, setSelectedProxy] = useState<string | null>(null)
  const [selectedSubscription, setSelectedSubscription] = useState<string | null>(null)
  const [darkMode, setDarkMode] = useState(() => {
    if (typeof window !== 'undefined') {
      return document.documentElement.classList.contains('dark')
    }
    return false
  })

  const queryClient = useQueryClient()
  const { data, isLoading, error, refetch } = useCredentials()
  const { mutate: deleteCredential } = useDeleteCredential()
  const { data: loadBalancingData, isLoading: isLoadingMode } = useLoadBalancingMode()
  const { mutate: setLoadBalancingMode, isPending: isSettingMode } = useSetLoadBalancingMode()
  const { data: cooldownData } = useCooldownConfig()

  // 根据代理和订阅等级过滤凭据
  const filteredCredentials = (() => {
    if (!data?.credentials) return []
    let result = data.credentials
    if (selectedProxy) {
      result = result.filter(cred => {
        const raw = cred.proxyUrl || '无代理'
        const key = raw.replace(/^(socks5?|https?):\/\//, '')
        return key === selectedProxy
      })
    }
    if (selectedSubscription) {
      if (selectedSubscription === 'DISABLED') {
        result = result.filter(cred => cred.disabled)
      } else {
        result = result.filter(cred => {
          if (cred.disabled) return false
          const title = (balanceMap.get(cred.id)?.subscriptionTitle || cred.endpoint || '').toUpperCase()
          if (selectedSubscription === 'KIRO PRO') {
            return title.includes('PRO') && !title.includes('PRO+') && !title.includes('POWER')
          }
          return title.includes(selectedSubscription.toUpperCase())
        })
      }
    }
    return result
  })()

  // 计算分页
  const totalPages = Math.ceil(filteredCredentials.length / itemsPerPage)
  const startIndex = (currentPage - 1) * itemsPerPage
  const endIndex = startIndex + itemsPerPage
  const currentCredentials = filteredCredentials.slice(startIndex, endIndex)
  const disabledCredentialCount = data?.credentials.filter(credential => credential.disabled).length || 0

  // 当凭据列表变化时重置到第一页
  useEffect(() => {
    setCurrentPage(1)
  }, [data?.credentials.length])

  // balanceMap 变化时持久化到 localStorage
  useEffect(() => {
    if (balanceMap.size > 0) {
      try {
        localStorage.setItem('kiro_balance_map', JSON.stringify(Array.from(balanceMap.entries())))
      } catch {}
    }
  }, [balanceMap])

  // 只保留当前仍存在的凭据缓存，避免删除后残留旧数据
  useEffect(() => {
    if (!data?.credentials) {
      // 数据未加载时不清空缓存，保留 localStorage 恢复的数据
      setLoadingBalanceIds(new Set())
      return
    }

    const validIds = new Set(data.credentials.map(credential => credential.id))

    setBalanceMap(prev => {
      const next = new Map<number, BalanceResponse>()
      prev.forEach((value, id) => {
        if (validIds.has(id)) {
          next.set(id, value)
        }
      })
      return next.size === prev.size ? prev : next
    })

    setLoadingBalanceIds(prev => {
      if (prev.size === 0) {
        return prev
      }
      const next = new Set<number>()
      prev.forEach(id => {
        if (validIds.has(id)) {
          next.add(id)
        }
      })
      return next.size === prev.size ? prev : next
    })
  }, [data?.credentials])

  // 加载代理池数据
  const fetchProxyPool = () => {
    getProxyPool().then(setProxyPoolData).catch(() => {})
  }
  useEffect(() => {
    fetchProxyPool()
    getRateLimitCooldown().then(r => setRateLimitCooldownSecs(r.seconds)).catch(() => {})
  }, [data?.credentials])

  const toggleDarkMode = () => {
    setDarkMode(!darkMode)
    document.documentElement.classList.toggle('dark')
  }

  const handleRefresh = () => {
    refetch()
    toast.success('已刷新凭据列表')
  }

  const handleLogout = () => {
    storage.removeApiKey()
    queryClient.clear()
    onLogout()
  }

  // 选择管理
  const toggleSelect = (id: number) => {
    const newSelected = new Set(selectedIds)
    if (newSelected.has(id)) {
      newSelected.delete(id)
    } else {
      newSelected.add(id)
    }
    setSelectedIds(newSelected)
  }

  const deselectAll = () => {
    setSelectedIds(new Set())
  }

  // 批量删除（直接删除选中的所有凭据）
  const handleBatchDelete = async () => {
    if (selectedIds.size === 0) {
      toast.error('请先选择要删除的凭据')
      return
    }

    if (!confirm(`确定要删除选中的 ${selectedIds.size} 个凭据吗？此操作无法撤销。`)) {
      return
    }

    const ids = Array.from(selectedIds)
    let successCount = 0
    let failCount = 0

    for (const id of ids) {
      try {
        await new Promise<void>((resolve, reject) => {
          deleteCredential(id, {
            onSuccess: () => {
              successCount++
              resolve()
            },
            onError: (err) => {
              failCount++
              reject(err)
            }
          })
        })
      } catch (error) {
        // 错误已在 onError 中处理
      }
    }

    if (failCount === 0) {
      toast.success(`成功删除 ${successCount} 个凭据`)
    } else {
      toast.warning(`删除凭据：成功 ${successCount} 个，失败 ${failCount} 个`)
    }

    deselectAll()
  }

  // 批量刷新 Token
  const handleBatchForceRefresh = async () => {
    if (selectedIds.size === 0) {
      toast.error('请先选择要刷新的凭据')
      return
    }

    const enabledIds = Array.from(selectedIds).filter(id => {
      const cred = data?.credentials.find(c => c.id === id)
      return cred && !cred.disabled
    })

    if (enabledIds.length === 0) {
      toast.error('选中的凭据中没有启用的凭据')
      return
    }

    setBatchRefreshing(true)
    setBatchRefreshProgress({ current: 0, total: enabledIds.length })

    let successCount = 0
    let failCount = 0

    for (let i = 0; i < enabledIds.length; i++) {
      try {
        await forceRefreshToken(enabledIds[i])
        successCount++
      } catch {
        failCount++
      }
      setBatchRefreshProgress({ current: i + 1, total: enabledIds.length })
    }

    setBatchRefreshing(false)
    queryClient.invalidateQueries({ queryKey: ['credentials'] })

    if (failCount === 0) {
      toast.success(`成功刷新 ${successCount} 个凭据的 Token`)
    } else {
      toast.warning(`刷新 Token：成功 ${successCount} 个，失败 ${failCount} 个`)
    }

    deselectAll()
  }

  // 批量启用/禁用
  const handleBatchSetDisabled = async (disabled: boolean) => {
    if (selectedIds.size === 0) {
      toast.error(`请先选择要${disabled ? '禁用' : '启用'}的凭据`)
      return
    }

    // 只处理状态需要变更的凭据
    const targetIds = Array.from(selectedIds).filter(id => {
      const cred = data?.credentials.find(c => c.id === id)
      return cred && cred.disabled !== disabled
    })

    if (targetIds.length === 0) {
      toast.error(`选中的凭据都已${disabled ? '禁用' : '启用'}`)
      return
    }

    setBatchTogglingDisabled(true)

    let successCount = 0
    let failCount = 0

    for (const id of targetIds) {
      try {
        await setCredentialDisabled(id, disabled)
        successCount++
      } catch {
        failCount++
      }
    }

    setBatchTogglingDisabled(false)
    queryClient.invalidateQueries({ queryKey: ['credentials'] })

    if (failCount === 0) {
      toast.success(`成功${disabled ? '禁用' : '启用'} ${successCount} 个凭据`)
    } else {
      toast.warning(`${disabled ? '禁用' : '启用'}凭据：成功 ${successCount} 个，失败 ${failCount} 个`)
    }

    deselectAll()
  }
  const handleBatchCooldown = async (mode: 'custom' | 'off' | 'global', seconds?: number, maxReqs?: number) => {
    if (mode === 'custom') {
      if (seconds !== undefined && (isNaN(seconds) || seconds <= 0)) {
        toast.error('秒数必须为正整数')
        return
      }
      if (maxReqs !== undefined && (isNaN(maxReqs) || maxReqs <= 0)) {
        toast.error('次数必须为正整数')
        return
      }
    }
    const ids = Array.from(selectedIds)
    setBatchCooldowning(true)
    let successCount = 0
    let failCount = 0
    for (const id of ids) {
      try {
        if (mode === 'global') {
          await setCredentialCooldown(id, {})
        } else if (mode === 'off') {
          await setCredentialCooldown(id, { enabled: false })
        } else {
          await setCredentialCooldown(id, { enabled: true, seconds, maxRequests: maxReqs })
        }
        successCount++
      } catch {
        failCount++
      }
    }
    setBatchCooldowning(false)
    queryClient.invalidateQueries({ queryKey: ['credentials'] })
    if (failCount === 0) {
      toast.success(`成功设置 ${successCount} 个凭据为独立限流`)
    } else {
      toast.warning(`设置限流：成功 ${successCount} 个，失败 ${failCount} 个`)
    }
    deselectAll()
  }

  // 一键清除所有已禁用凭据
  const handleClearAll = async () => {
    if (!data?.credentials || data.credentials.length === 0) {
      toast.error('没有可清除的凭据')
      return
    }

    const disabledCredentials = data.credentials.filter(credential => credential.disabled)

    if (disabledCredentials.length === 0) {
      toast.error('没有可清除的已禁用凭据')
      return
    }

    if (!confirm(`确定要清除所有 ${disabledCredentials.length} 个已禁用凭据吗？此操作无法撤销。`)) {
      return
    }

    let successCount = 0
    let failCount = 0

    for (const credential of disabledCredentials) {
      try {
        await new Promise<void>((resolve, reject) => {
          deleteCredential(credential.id, {
            onSuccess: () => {
              successCount++
              resolve()
            },
            onError: (err) => {
              failCount++
              reject(err)
            }
          })
        })
      } catch (error) {
        // 错误已在 onError 中处理
      }
    }

    if (failCount === 0) {
      toast.success(`成功清除所有 ${successCount} 个已禁用凭据`)
    } else {
      toast.warning(`清除已禁用凭据：成功 ${successCount} 个，失败 ${failCount} 个`)
    }

    deselectAll()
  }

  // 查询当前页凭据信息（逐个查询，避免瞬时并发）
  const handleEnableOverage = async () => {
    if (selectedIds.size === 0) {
      toast.error('请先选择要开启超额的凭据')
      return
    }
    setEnablingOverage(true)
    try {
      const { results } = await enableOverage(Array.from(selectedIds))
      const success = results.filter(r => r.status === 'success').length
      const skipped = results.filter(r => r.status === 'skipped').length
      const errors = results.filter(r => r.status === 'error').length
      toast.success(`批量超额完成: ${success} 成功, ${skipped} 跳过, ${errors} 失败`)
      if (errors > 0) {
        results.filter(r => r.status === 'error').forEach(r => {
          toast.error(`凭据 #${r.id}: ${r.message}`)
        })
      }
    } catch (e) {
      toast.error(`批量超额失败: ${extractErrorMessage(e)}`)
    } finally {
      setEnablingOverage(false)
    }
  }

  const handleQueryCurrentPageInfo = async () => {
    if (currentCredentials.length === 0) {
      toast.error('当前页没有可查询的凭据')
      return
    }

    const ids = currentCredentials
      .filter(credential => !credential.disabled)
      .map(credential => credential.id)

    if (ids.length === 0) {
      toast.error('当前页没有可查询的启用凭据')
      return
    }

    setQueryingInfo(true)
    setQueryInfoProgress({ current: 0, total: ids.length })

    let successCount = 0
    let failCount = 0
    let completed = 0

    const CONCURRENCY = 10
    const executing = new Set<Promise<void>>()

    for (const id of ids) {
      const p = (async () => {
        setLoadingBalanceIds(prev => { const next = new Set(prev); next.add(id); return next })
        try {
          const balance = await getCredentialBalance(id, true)
          successCount++
          setBalanceMap(prev => { const next = new Map(prev); next.set(id, balance); return next })
        } catch {
          failCount++
        } finally {
          setLoadingBalanceIds(prev => { const next = new Set(prev); next.delete(id); return next })
          completed++
          setQueryInfoProgress({ current: completed, total: ids.length })
        }
      })().then(() => { executing.delete(p) })
      executing.add(p)
      if (executing.size >= CONCURRENCY) await Promise.race(executing)
    }
    await Promise.all(executing)

    setQueryingInfo(false)
    refetch()

    if (failCount === 0) {
      toast.success(`查询完成：成功 ${successCount}/${ids.length}`)
    } else {
      toast.warning(`查询完成：成功 ${successCount} 个，失败 ${failCount} 个`)
    }
  }

  // 批量查询选中凭据信息
  const handleBatchQuerySelected = async () => {
    if (selectedIds.size === 0) {
      toast.error('请先选择要查询的凭据')
      return
    }
    const ids = Array.from(selectedIds)
    setQueryingInfo(true)
    setQueryInfoProgress({ current: 0, total: ids.length })
    let successCount = 0
    let failCount = 0
    let completed = 0

    const CONCURRENCY = 10
    const executing = new Set<Promise<void>>()

    for (const id of ids) {
      const p = (async () => {
        try {
          const balance = await getCredentialBalance(id, true)
          successCount++
          setBalanceMap(prev => { const next = new Map(prev); next.set(id, balance); return next })
        } catch {
          failCount++
        }
        completed++
        setQueryInfoProgress({ current: completed, total: ids.length })
      })().then(() => { executing.delete(p) })
      executing.add(p)
      if (executing.size >= CONCURRENCY) await Promise.race(executing)
    }
    await Promise.all(executing)

    setQueryingInfo(false)
    refetch()
    if (failCount === 0) {
      toast.success(`查询完成：成功 ${successCount}/${ids.length}`)
    } else {
      toast.warning(`查询完成：成功 ${successCount} 个，失败 ${failCount} 个`)
    }
  }

  // 切换负载均衡模式
  const handleToggleLoadBalancing = () => {
    const currentMode = loadBalancingData?.mode || 'priority'
    const newMode = currentMode === 'priority' ? 'balanced' : 'priority'

    setLoadBalancingMode(newMode, {
      onSuccess: () => {
        const modeName = newMode === 'priority' ? '优先级模式' : '均衡负载模式'
        toast.success(`已切换到${modeName}`)
      },
      onError: (error) => {
        toast.error(`切换失败: ${extractErrorMessage(error)}`)
      }
    })
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">加载中...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <Card className="w-full max-w-md">
          <CardContent className="pt-6 text-center">
            <div className="text-red-500 mb-4">加载失败</div>
            <p className="text-muted-foreground mb-4">{(error as Error).message}</p>
            <div className="space-x-2">
              <Button onClick={() => refetch()}>重试</Button>
              <Button variant="outline" onClick={handleLogout}>重新登录</Button>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      {/* 顶部导航 */}
      <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="flex h-14 items-center justify-between px-4 md:px-8">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Server className="h-5 w-5" />
              <span className="font-semibold text-primary">Kiro Admin</span>
            </div>
            <button onClick={() => onNavigate('proxy')} className="font-semibold text-muted-foreground hover:text-primary transition-colors">
              IP Admin
            </button>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setCacheRatiosDialogOpen(true)}
              title="缓存 token 估算倍率"
            >
              <Database className="h-4 w-4 mr-2" />
              缓存
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setModelPricesDialogOpen(true)}
              title="模型价格设置"
            >
              <DollarSign className="h-4 w-4 mr-2" />
              计费
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setRateLimitInput(String(rateLimitCooldownSecs))
                setRateLimitDialogOpen(true)
              }}
              title="429 冷却时间（点击设置）"
            >
              <Zap className="h-4 w-4 mr-2" />
              429: {rateLimitCooldownSecs}s
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleQueryCurrentPageInfo}
              disabled={queryingInfo}
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${queryingInfo ? 'animate-spin' : ''}`} />
              {queryingInfo ? `${queryInfoProgress.current}/${queryInfoProgress.total}` : '查询全部'}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleClearAll}
              className="text-destructive hover:text-destructive"
              disabled={disabledCredentialCount === 0}
            >
              <Trash2 className="h-4 w-4 mr-2" />
              清除已禁用
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setModelMappingDialogOpen(true)}
              title="模型映射配置"
            >
              <Layers className="h-4 w-4 mr-2" />
              模型
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setCooldownDialogOpen(true)}
              title="限流配置"
            >
              <Timer className="h-4 w-4 mr-2" />
              限流
              <Badge
                variant={cooldownData?.enabled ? 'success' : 'secondary'}
                className="ml-2"
              >
                {cooldownData?.enabled ? '开' : '关'}
              </Badge>
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleToggleLoadBalancing}
              disabled={isLoadingMode || isSettingMode}
              title="切换负载均衡模式"
            >
              {isLoadingMode ? '加载中...' : (loadBalancingData?.mode === 'priority' ? '优先级模式' : '均衡负载')}
            </Button>
            <Button variant="ghost" size="icon" onClick={toggleDarkMode}>
              {darkMode ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
            </Button>
            <Button variant="ghost" size="icon" onClick={handleRefresh}>
              <RefreshCw className="h-5 w-5" />
            </Button>
            <Button variant="ghost" size="icon" onClick={handleLogout}>
              <LogOut className="h-5 w-5" />
            </Button>
          </div>
        </div>
      </header>

      {/* 主内容 */}
      <main className="mx-auto px-4 md:px-8 py-6">
        {/* 统计卡片 */}
        <div className="grid gap-4 md:grid-cols-9 mb-6">
          <Card
            className={`cursor-pointer transition-all ${!selectedSubscription ? 'ring-2 ring-primary' : 'hover:bg-muted/50'}`}
            onClick={() => { setSelectedSubscription(null); setCurrentPage(1) }}
          >
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                凭据总数
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{data?.total || 0}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                可用
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">{data?.available || 0}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                RPM
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{data?.rpm || 0}</div>
            </CardContent>
          </Card>
          <Card
            className={`cursor-pointer transition-all ${selectedSubscription === 'PRO+' ? 'ring-2 ring-purple-500' : 'hover:bg-muted/50'}`}
            onClick={() => { setSelectedSubscription(selectedSubscription === 'PRO+' ? null : 'PRO+'); setCurrentPage(1) }}
          >
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                PRO+
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-purple-600">
                {data?.credentials.filter(c => {
                  if (c.disabled) return false
                  const t = (balanceMap.get(c.id)?.subscriptionTitle || '').toUpperCase()
                  return t.includes('PRO+')
                }).length || 0}
              </div>
            </CardContent>
          </Card>
          <Card
            className={`cursor-pointer transition-all ${selectedSubscription === 'KIRO PRO' ? 'ring-2 ring-blue-500' : 'hover:bg-muted/50'}`}
            onClick={() => { setSelectedSubscription(selectedSubscription === 'KIRO PRO' ? null : 'KIRO PRO'); setCurrentPage(1) }}
          >
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                PRO
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">
                {data?.credentials.filter(c => {
                  if (c.disabled) return false
                  const t = (balanceMap.get(c.id)?.subscriptionTitle || '').toUpperCase()
                  return t.includes('PRO') && !t.includes('PRO+') && !t.includes('POWER')
                }).length || 0}
              </div>
            </CardContent>
          </Card>
          <Card
            className={`cursor-pointer transition-all ${selectedSubscription === 'POWER' ? 'ring-2 ring-orange-500' : 'hover:bg-muted/50'}`}
            onClick={() => { setSelectedSubscription(selectedSubscription === 'POWER' ? null : 'POWER'); setCurrentPage(1) }}
          >
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                POWER
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-orange-600">
                {data?.credentials.filter(c => {
                  if (c.disabled) return false
                  const t = (balanceMap.get(c.id)?.subscriptionTitle || '').toUpperCase()
                  return t.includes('POWER')
                }).length || 0}
              </div>
            </CardContent>
          </Card>
          <Card
            className={`cursor-pointer transition-all ${selectedSubscription === 'FREE' ? 'ring-2 ring-gray-500' : 'hover:bg-muted/50'}`}
            onClick={() => { setSelectedSubscription(selectedSubscription === 'FREE' ? null : 'FREE'); setCurrentPage(1) }}
          >
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                FREE
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-gray-600">
                {data?.credentials.filter(c => {
                  if (c.disabled) return false
                  const t = (balanceMap.get(c.id)?.subscriptionTitle || '').toUpperCase()
                  return t.includes('FREE')
                }).length || 0}
              </div>
            </CardContent>
          </Card>
          <Card
            className={`cursor-pointer transition-all ${selectedSubscription === 'DISABLED' ? 'ring-2 ring-red-500' : 'hover:bg-muted/50'}`}
            onClick={() => { setSelectedSubscription(selectedSubscription === 'DISABLED' ? null : 'DISABLED'); setCurrentPage(1) }}
          >
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                封禁
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">
                {data?.credentials.filter(c => c.disabled).length || 0}
              </div>
            </CardContent>
          </Card>
          <Card
            className="cursor-pointer hover:bg-muted/50 transition-all"
            onClick={() => onNavigate('proxy')}
          >
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                代理池
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                <span className="text-green-600">{proxyPoolData?.available ?? 0}</span>
                <span className="text-sm font-normal text-muted-foreground">/{proxyPoolData?.total ?? 0}</span>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* 代理概览 + 凭据列表 双栏布局 */}
        <div className="flex gap-6">
          {/* 左侧代理概览 */}
          {data?.credentials && data.credentials.length > 0 && (() => {
            const proxyGroups = new Map<string, number>()
            for (const cred of data.credentials) {
              const raw = cred.proxyUrl || '无代理'
              const key = raw.replace(/^(socks5?|https?):\/\//, '')
              proxyGroups.set(key, (proxyGroups.get(key) || 0) + 1)
            }
            const entries = Array.from(proxyGroups.entries()).sort((a, b) => b[1] - a[1])
            return entries.length > 0 ? (
              <div className="w-60 shrink-0">
                <div className="sticky top-20">
                  <Card>
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-medium text-muted-foreground">代理概览</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-1 max-h-[calc(100vh-200px)] overflow-y-auto">
                      {selectedProxy && (
                        <button
                          onClick={() => { setSelectedProxy(null); setCurrentPage(1) }}
                          className="w-full text-xs text-muted-foreground hover:text-foreground mb-2 text-left"
                        >
                          ← 显示全部
                        </button>
                      )}
                      {entries.map(([proxy, count]) => (
                        <button
                          key={proxy}
                          onClick={() => { setSelectedProxy(selectedProxy === proxy ? null : proxy); setCurrentPage(1) }}
                          className={`w-full flex items-center justify-between gap-2 px-2 py-1.5 rounded-md transition-colors ${
                            selectedProxy === proxy
                              ? 'bg-primary/10 text-primary'
                              : 'hover:bg-muted'
                          }`}
                        >
                          <span className="text-xs font-mono truncate" title={proxy}>{proxy}</span>
                          <Badge variant={selectedProxy === proxy ? "default" : "secondary"} className="shrink-0">{count}</Badge>
                        </button>
                      ))}
                    </CardContent>
                  </Card>
                </div>
              </div>
            ) : null
          })()}

          {/* 右侧凭据列表 */}
          <div className="flex-1 min-w-0 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <h2 className="text-xl font-semibold">凭据管理</h2>
              {selectedIds.size > 0 && (
                <div className="flex items-center gap-2">
                  <Badge variant="secondary">已选择 {selectedIds.size} 个</Badge>
                  <Button onClick={deselectAll} size="sm" variant="ghost">
                    取消选择
                  </Button>
                </div>
              )}
            </div>
            <div className="flex gap-2">
              {selectedIds.size > 0 && (
                <>
                  <Button onClick={handleBatchQuerySelected} size="sm" variant="outline" disabled={queryingInfo}>
                    <Search className="h-4 w-4 mr-2" />
                    {queryingInfo ? `查询中... ${queryInfoProgress.current}/${queryInfoProgress.total}` : '批量查询'}
                  </Button>
                  <Button
                    onClick={handleBatchForceRefresh}
                    size="sm"
                    variant="outline"
                    disabled={batchRefreshing}
                  >
                    <RefreshCw className={`h-4 w-4 mr-2 ${batchRefreshing ? 'animate-spin' : ''}`} />
                    {batchRefreshing ? `刷新中... ${batchRefreshProgress.current}/${batchRefreshProgress.total}` : '批量刷新 Token'}
                  </Button>
                  <Button
                    onClick={() => handleBatchSetDisabled(false)}
                    size="sm"
                    variant="outline"
                    disabled={batchTogglingDisabled}
                    className="text-green-600 hover:text-green-600"
                  >
                    <Power className="h-4 w-4 mr-2" />
                    {batchTogglingDisabled ? '处理中...' : '批量启用'}
                  </Button>
                  <Button
                    onClick={() => handleBatchSetDisabled(true)}
                    size="sm"
                    variant="outline"
                    disabled={batchTogglingDisabled}
                    className="text-red-500 hover:text-red-500"
                  >
                    <PowerOff className="h-4 w-4 mr-2" />
                    {batchTogglingDisabled ? '处理中...' : '批量禁用'}
                  </Button>
                  <Button
                    onClick={handleBatchDelete}
                    size="sm"
                    variant="destructive"
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    批量删除
                  </Button>
                  <Button
                    onClick={handleEnableOverage}
                    size="sm"
                    variant="outline"
                    disabled={enablingOverage}
                  >
                    <Zap className="h-4 w-4 mr-2" />
                    {enablingOverage ? '开启中...' : '批量超额'}
                  </Button>
                  <Button
                    onClick={async () => {
                      if (selectedIds.size === 0) { toast.error('请先选择凭据'); return }
                      try {
                        const res = await resetRateLimit(Array.from(selectedIds))
                        toast.success(res.message)
                        refetch()
                      } catch (err) { toast.error('清除失败: ' + (err as Error).message) }
                    }}
                    size="sm"
                    variant="outline"
                  >
                    清除429
                  </Button>
                  <Button
                    onClick={() => { setBatchCdSecsInput(''); setBatchCdReqsInput(''); setBatchCd429Input(''); setBatchCooldownDialogOpen(true) }}
                    size="sm"
                    variant="outline"
                    disabled={batchCooldowning}
                  >
                    <Timer className="h-4 w-4 mr-2" />
                    {batchCooldowning ? '设置中...' : '批量限流'}
                  </Button>
                </>
              )}
              <Button onClick={() => setBatchImportDialogOpen(true)} size="sm" variant="outline">
                <Upload className="h-4 w-4 mr-2" />
                批量导入
              </Button>
              <Button onClick={() => setAddDialogOpen(true)} size="sm">
                <Plus className="h-4 w-4 mr-2" />
                添加凭据
              </Button>
            </div>
          </div>
          {data?.credentials.length === 0 ? (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                暂无凭据
              </CardContent>
            </Card>
          ) : (
            <>
              <CredentialTable
                credentials={currentCredentials}
                selectedIds={selectedIds}
                onToggleSelect={toggleSelect}
                onSelectAll={(ids) => setSelectedIds(new Set(ids))}
                balanceMap={balanceMap}
                onBalanceUpdate={(id, bal) => {
                  setBalanceMap(prev => {
                    const next = new Map(prev)
                    next.set(id, bal)
                    return next
                  })
                }}
                onRefresh={() => refetch()}
              />

              {/* 分页控件 */}
              <div className="flex justify-center items-center gap-2 mt-4 flex-wrap">
                {totalPages > 1 && (
                  <>
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 px-2 text-xs"
                      onClick={() => setCurrentPage(1)}
                      disabled={currentPage === 1}
                    >
                      首页
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 px-2 text-xs"
                      onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                      disabled={currentPage === 1}
                    >
                      上一页
                    </Button>
                    <span className="text-sm text-muted-foreground">
                      第 {currentPage} / {totalPages} 页（共 {filteredCredentials.length} 个）
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 px-2 text-xs"
                      onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                      disabled={currentPage === totalPages}
                    >
                      下一页
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 px-2 text-xs"
                      onClick={() => setCurrentPage(totalPages)}
                      disabled={currentPage === totalPages}
                    >
                      尾页
                    </Button>
                  </>
                )}
                {totalPages <= 1 && filteredCredentials.length > 0 && (
                  <span className="text-sm text-muted-foreground">共 {filteredCredentials.length} 个</span>
                )}
                <div className="flex items-center gap-1 ml-4">
                  <span className="text-xs text-muted-foreground">每页</span>
                  {[10, 20, 50, 100].map(size => (
                    <Button
                      key={size}
                      variant={itemsPerPage === size ? 'default' : 'outline'}
                      size="sm"
                      className="h-7 px-2 text-xs"
                      onClick={() => { setItemsPerPage(size); setCurrentPage(1) }}
                    >
                      {size}
                    </Button>
                  ))}
                  <Input
                    type="number"
                    className="w-16 h-7 text-xs px-1.5"
                    placeholder="自定"
                    min="1"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        const val = parseInt((e.target as HTMLInputElement).value, 10)
                        if (val > 0) { setItemsPerPage(val); setCurrentPage(1) }
                      }
                    }}
                  />
                </div>
              </div>
            </>
          )}
        </div>
        </div>
      </main>

      {/* 添加凭据对话框 */}
      <AddCredentialDialog
        open={addDialogOpen}
        onOpenChange={setAddDialogOpen}
        onBalanceUpdate={(id, bal) => {
          setBalanceMap(prev => {
            const next = new Map(prev)
            next.set(id, bal)
            return next
          })
        }}
      />

      {/* 批量导入对话框 */}
      <BatchImportDialog
        open={batchImportDialogOpen}
        onOpenChange={setBatchImportDialogOpen}
        onBalanceUpdate={(id, bal) => {
          setBalanceMap(prev => {
            const next = new Map(prev)
            next.set(id, bal)
            return next
          })
        }}
      />

      {/* 冷却限流配置对话框 */}
      <CooldownConfigDialog
        open={cooldownDialogOpen}
        onOpenChange={setCooldownDialogOpen}
      />

      {/* 缓存倍率对话框 */}
      <CacheRatiosDialog
        open={cacheRatiosDialogOpen}
        onOpenChange={setCacheRatiosDialogOpen}
      />

      {/* 模型映射对话框 */}
      <ModelMappingDialog
        open={modelMappingDialogOpen}
        onOpenChange={setModelMappingDialogOpen}
      />

      {/* 模型价格设置对话框 */}
      <ModelPricesDialog
        open={modelPricesDialogOpen}
        onOpenChange={setModelPricesDialogOpen}
      />

      {/* 代理导入对话框 */}
      <ProxyImportDialog
        open={proxyImportOpen}
        onOpenChange={setProxyImportOpen}
        onSuccess={fetchProxyPool}
      />

      {/* 批量限流弹窗 */}
      <Dialog open={batchCooldownDialogOpen} onOpenChange={setBatchCooldownDialogOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>批量限流设置</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <Button
                variant={batchCooldownMode === 'custom' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setBatchCooldownMode('custom')}
              >
                独立限流
              </Button>
              <Button
                variant={batchCooldownMode === 'off' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setBatchCooldownMode('off')}
              >
                不限流
              </Button>
              <Button
                variant={batchCooldownMode === 'global' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setBatchCooldownMode('global')}
              >
                跟随全局
              </Button>
            </div>
            {batchCooldownMode === 'custom' && (
              <>
                <div className="flex items-center gap-2">
                  <Input
                    type="number"
                    value={batchCdSecsInput}
                    onChange={(e) => setBatchCdSecsInput(e.target.value)}
                    placeholder="秒"
                    className="w-20"
                    min="1"
                  />
                  <span className="text-sm text-muted-foreground">S</span>
                  <Input
                    type="number"
                    value={batchCdReqsInput}
                    onChange={(e) => setBatchCdReqsInput(e.target.value)}
                    placeholder="次"
                    className="w-20"
                    min="1"
                  />
                  <span className="text-sm text-muted-foreground">次</span>
                </div>
              </>
            )}
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">429冷却时间</span>
              <Input
                type="number"
                value={batchCd429Input}
                onChange={(e) => setBatchCd429Input(e.target.value)}
                placeholder="留空跟随全局"
                className="w-28"
                min="1"
              />
              <span className="text-sm text-muted-foreground">S</span>
            </div>
            <p className="text-xs text-muted-foreground">429冷却留空则跟随全局设置</p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setBatchCooldownDialogOpen(false)}>取消</Button>
            <Button
              disabled={batchCooldowning}
              onClick={() => {
                const secs = batchCdSecsInput ? parseInt(batchCdSecsInput, 10) : undefined
                const reqs = batchCdReqsInput ? parseInt(batchCdReqsInput, 10) : undefined
                if (batchCooldownMode === 'custom') {
                  if (secs !== undefined && (isNaN(secs) || secs <= 0)) { toast.error('限流秒数必须为正整数'); return }
                  if (reqs !== undefined && (isNaN(reqs) || reqs <= 0)) { toast.error('次数必须为正整数'); return }
                }
                const rateLimitSecs = batchCd429Input.trim() ? parseInt(batchCd429Input, 10) : null
                if (rateLimitSecs !== null && (isNaN(rateLimitSecs) || rateLimitSecs <= 0)) { toast.error('429冷却秒数必须为正整数'); return }
                handleBatchCooldown(batchCooldownMode, secs, reqs)
                if (rateLimitSecs !== null) {
                  setCredentialRateLimitCooldown(Array.from(selectedIds), rateLimitSecs)
                    .catch(err => toast.error('429冷却设置失败: ' + (err as Error).message))
                }
                setBatchCooldownDialogOpen(false)
              }}
            >
              {batchCooldowning ? '设置中...' : '确定'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 429 全局冷却时间设置 */}
      <Dialog open={rateLimitDialogOpen} onOpenChange={setRateLimitDialogOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>429 冷却时间</DialogTitle>
          </DialogHeader>
          <div className="space-y-2">
            <label htmlFor="rate-limit-secs" className="text-sm font-medium">
              冷却时长（秒）
            </label>
            <Input
              id="rate-limit-secs"
              type="number"
              min="0"
              value={rateLimitInput}
              onChange={(e) => setRateLimitInput(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              凭据触发 429 后的全局冷却时长，0 表示不冷却（立即可再次使用）
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRateLimitDialogOpen(false)}>取消</Button>
            <Button
              onClick={() => {
                const secs = parseInt(rateLimitInput, 10)
                if (isNaN(secs) || secs < 0) {
                  toast.error('冷却时长必须为非负整数')
                  return
                }
                setRateLimitCooldown(secs).then(() => {
                  setRateLimitCooldownSecs(secs)
                  setRateLimitDialogOpen(false)
                  toast.success(`429 冷却时间已设为 ${secs}s`)
                }).catch(err => toast.error('设置失败: ' + (err as Error).message))
              }}
            >
              确定
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
