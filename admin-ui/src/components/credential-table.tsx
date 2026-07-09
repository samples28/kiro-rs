import { useState, useEffect } from 'react'
import { toast } from 'sonner'
import { RefreshCw, Search, Settings, Eye, Power, Zap, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table'
import { CredentialDetailDialog } from '@/components/credential-detail-dialog'
import { ProxySettingDialog } from '@/components/proxy-setting-dialog'
import type { CredentialStatusItem, BalanceResponse } from '@/types/api'
import { getCredentialBalance, forceRefreshToken, setCredentialDisabled, deleteCredential, enableOverage, getBillingStats } from '@/api/credentials'

interface CredentialTableProps {
  credentials: CredentialStatusItem[]
  selectedIds: Set<number>
  onToggleSelect: (id: number) => void
  onSelectAll: (ids: number[]) => void
  balanceMap: Map<number, BalanceResponse>
  onBalanceUpdate: (id: number, balance: BalanceResponse) => void
  onRefresh: () => void
}

export function CredentialTable({
  credentials,
  selectedIds,
  onToggleSelect,
  onSelectAll,
  balanceMap,
  onBalanceUpdate,
  onRefresh,
}: CredentialTableProps) {
  const [detailCredential, setDetailCredential] = useState<CredentialStatusItem | null>(null)
  const [proxyCredential, setProxyCredential] = useState<CredentialStatusItem | null>(null)
  const [queryingIds, setQueryingIds] = useState<Set<number>>(new Set())
  const [refreshingIds, setRefreshingIds] = useState<Set<number>>(new Set())
  const [togglingIds, setTogglingIds] = useState<Set<number>>(new Set())
  const [billingData, setBillingData] = useState<Record<string, { total_cost: number, total_requests: number, by_model: Record<string, { cost: number, requests: number, input_tokens: number, output_tokens: number }> }>>({})

  // Fetch billing stats on mount and every 60s
  useEffect(() => {
    const fetchBilling = () => {
      getBillingStats()
        .then((res) => setBillingData(res.credentials || {}))
        .catch(() => {})
    }
    fetchBilling()
    const interval = setInterval(fetchBilling, 60000)
    return () => clearInterval(interval)
  }, [])

  const handleToggleDisabled = async (id: number, currentDisabled: boolean) => {
    setTogglingIds(prev => new Set(prev).add(id))
    try {
      await setCredentialDisabled(id, !currentDisabled)
      toast.success(`凭据 #${id} 已${currentDisabled ? '启用' : '禁用'}`)
      onRefresh()
    } catch (err) {
      toast.error('操作失败: ' + (err as Error).message)
    } finally {
      setTogglingIds(prev => { const next = new Set(prev); next.delete(id); return next })
    }
  }

  const handleDelete = async (id: number) => {
    if (!confirm(`确定要删除凭据 #${id} 吗？此操作无法撤销。`)) return
    try {
      await deleteCredential(id)
      toast.success(`凭据 #${id} 已删除`)
      onRefresh()
    } catch (err) {
      toast.error('删除失败: ' + (err as Error).message)
    }
  }

  const handleEnableOverage = async (id: number) => {
    try {
      const { results } = await enableOverage([id])
      const r = results[0]
      if (r.status === 'success') {
        toast.success(`凭据 #${id} 超额已开启`)
      } else if (r.status === 'skipped') {
        toast.info(`凭据 #${id}: ${r.message}`)
      } else {
        toast.error(`凭据 #${id}: ${r.message}`)
      }
    } catch (err) {
      toast.error('超额开启失败: ' + (err as Error).message)
    }
  }

  const handleQueryBalance = async (id: number) => {
    setQueryingIds(prev => new Set(prev).add(id))
    try {
      const result = await getCredentialBalance(id, true)
      onBalanceUpdate(id, result)
      toast.success(`凭据 #${id} 查询成功`)
    } catch (err) {
      toast.error('查询失败: ' + (err as Error).message)
    } finally {
      setQueryingIds(prev => {
        const next = new Set(prev)
        next.delete(id)
        return next
      })
    }
  }

  const handleRefreshToken = async (id: number) => {
    setRefreshingIds(prev => new Set(prev).add(id))
    try {
      await forceRefreshToken(id)
      toast.success(`凭据 #${id} Token 已刷新`)
    } catch (err) {
      toast.error('刷新失败: ' + (err as Error).message)
    } finally {
      setRefreshingIds(prev => {
        const next = new Set(prev)
        next.delete(id)
        return next
      })
    }
  }

  const formatProxy = (url?: string) => {
    if (!url) return '-'
    return url.replace(/^(socks5?|https?):\/\//, '')
  }

  return (
    <>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-7">
              <Checkbox
                checked={credentials.length > 0 && credentials.every(c => selectedIds.has(c.id))}
                onCheckedChange={(checked) => {
                  onSelectAll(checked ? credentials.map(c => c.id) : [])
                }}
              />
            </TableHead>
            <TableHead>邮箱</TableHead>
            <TableHead className="text-center">类型</TableHead>
            <TableHead className="text-center">状态</TableHead>
            <TableHead>订阅等级</TableHead>
            <TableHead>用量/总量</TableHead>
            <TableHead className="text-center">超限</TableHead>
            <TableHead>代理IP</TableHead>
            <TableHead className="text-center">RPM</TableHead>
            <TableHead className="text-center">429</TableHead>
            <TableHead className="text-center">限流</TableHead>
            <TableHead className="text-center">TTFB</TableHead>
            <TableHead className="text-center">费用</TableHead>
            <TableHead className="text-right">操作</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {credentials.map((cred) => {
            const balance = balanceMap.get(cred.id)
            const used = balance?.currentUsage ?? 0
            const limit = balance?.usageLimit ?? 0
            const isOverage = balance ? used > limit : false
            const pct = limit > 0 ? Math.min(100, (used / limit) * 100) : 0

            return (
              <TableRow
                key={cred.id}
                className={cred.disabled ? 'opacity-50' : ''}
                data-state={selectedIds.has(cred.id) ? 'selected' : undefined}
              >
                <TableCell>
                  <Checkbox
                    checked={selectedIds.has(cred.id)}
                    onCheckedChange={() => onToggleSelect(cred.id)}
                  />
                </TableCell>
                <TableCell className="font-medium truncate pr-0" title={cred.email || balance?.email || '-'}>
                  {cred.email || balance?.email || '-'}
                </TableCell>
                {/* 类型 */}
                <TableCell className="text-center">
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                    cred.authMethod === 'api_key' ? 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300' :
                    cred.authMethod === 'enterprise' ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300' :
                    (cred.authMethod === 'idc' || cred.authMethod === 'builderid') ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-300' :
                    'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
                  }`}>
                    {cred.authMethod === 'api_key' ? 'API Key' :
                     cred.authMethod === 'enterprise' ? 'Enterprise' :
                     cred.authMethod === 'builderid' ? 'BuilderId' :
                     cred.authMethod === 'idc' ? 'IdC' :
                     'Social'}
                  </span>
                </TableCell>
                {/* 状态 */}
                <TableCell className="text-center">
                  {cred.rateLimitCooling ? (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300 font-medium">冷却中</span>
                  ) : cred.disabled && cred.disabledReason === 'QuotaExceeded' ? (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300 font-medium">额度用尽</span>
                  ) : cred.disabled && cred.disabledReason === 'TooManyFailures' ? (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300 font-medium">401/403</span>
                  ) : cred.disabled && cred.disabledReason === 'InvalidRefreshToken' ? (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300 font-medium">Token失效</span>
                  ) : cred.disabled && cred.disabledReason === 'Manual' ? (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 font-medium">未启用</span>
                  ) : cred.disabled ? (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 font-medium">已禁用</span>
                  ) : (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300 font-medium">正常</span>
                  )}
                </TableCell>
                {/* 订阅等级 */}
                <TableCell className="pl-1">
                  {(balance?.subscriptionTitle || cred.endpoint) ? (
                    <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${
                      (balance?.subscriptionTitle || '').toUpperCase().includes('PRO+') ? 'text-purple-700 bg-purple-100 dark:text-purple-300 dark:bg-purple-900/30' :
                      (balance?.subscriptionTitle || '').toUpperCase().includes('POWER') ? 'text-orange-700 bg-orange-100 dark:text-orange-300 dark:bg-orange-900/30' :
                      (balance?.subscriptionTitle || '').toUpperCase().includes('PRO') ? 'text-blue-700 bg-blue-100 dark:text-blue-300 dark:bg-blue-900/30' :
                      (balance?.subscriptionTitle || '').toUpperCase().includes('FREE') ? 'text-gray-600 bg-gray-100 dark:text-gray-400 dark:bg-gray-800/50' :
                      'text-foreground bg-muted'
                    }`}>
                      {balance?.subscriptionTitle || cred.endpoint}
                    </span>
                  ) : (
                    <span className="text-xs text-muted-foreground">未知</span>
                  )}
                </TableCell>
                {/* 用量/总量 - 带进度条 */}
                <TableCell>
                  {balance ? (
                    <div className="space-y-0.5">
                      <div className="flex items-baseline gap-1">
                        <span className={`text-xs font-bold ${isOverage ? 'text-red-600 dark:text-red-400' : ''}`}>
                          {Math.round(used)}
                        </span>
                        <span className="text-xs text-muted-foreground">/{Math.round(limit)}</span>
                      </div>
                      <div className="h-1 w-20 bg-muted rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${isOverage ? 'bg-purple-500' : 'bg-green-500'}`}
                          style={{ width: `${Math.min(100, pct)}%` }}
                        />
                      </div>
                    </div>
                  ) : (
                    <span className="text-xs text-muted-foreground">-</span>
                  )}
                </TableCell>
                {/* 超限状态 */}
                <TableCell className="text-center">
                  {balance ? (
                    balance.overageStatus === 'overaging' ? (
                      <span className="inline-block px-2 py-0.5 rounded text-xs font-bold text-red-600 bg-red-100 dark:bg-red-900/30">
                        超限中
                      </span>
                    ) : balance.overageStatus === 'enabled' ? (
                      <span className="inline-block px-2 py-0.5 rounded text-xs font-bold text-orange-600 bg-orange-100 dark:bg-orange-900/30">
                        已开启
                      </span>
                    ) : (
                      <span className="inline-block px-2 py-0.5 rounded text-xs font-bold text-gray-600 bg-gray-100 dark:bg-gray-800">
                        未开启
                      </span>
                    )
                  ) : '-'}
                </TableCell>
                {/* 代理IP */}
                <TableCell className="font-mono text-xs truncate" title={cred.proxyUrl || '-'}>
                  {formatProxy(cred.proxyUrl)}
                </TableCell>
                {/* RPM */}
                <TableCell className="text-center text-sm font-mono">{cred.rpm}</TableCell>
                {/* 429 */}
                <TableCell className="text-center">
                  <div className="flex items-center justify-center gap-1">
                    {cred.rateLimitCount > 0 ? (
                      <span className="text-xs font-mono text-red-500">{cred.rateLimitCount}</span>
                    ) : (
                      <span className="text-xs text-muted-foreground">0</span>
                    )}
                    {cred.rateLimitCooling && (
                      <span className="text-[10px] text-orange-500 animate-pulse">冷却中</span>
                    )}
                  </div>
                </TableCell>
                {/* 限流 */}
                <TableCell className="text-center">
                  <span className="text-xs">
                    {cred.cooldownEnabled === true
                      ? `${cred.cooldownSeconds ?? '?'}s/${cred.cooldownMaxRequests ?? '?'}次`
                      : '全局'}
                  </span>
                </TableCell>
                {/* TTFB */}
                <TableCell className="text-center">
                  {cred.lastTtfbMs != null ? (
                    <span className={`text-xs font-mono ${cred.lastTtfbMs > 5000 ? 'text-red-500' : cred.lastTtfbMs > 2000 ? 'text-yellow-500' : 'text-green-500'}`}>
                      {cred.lastTtfbMs}ms
                    </span>
                  ) : (
                    <span className="text-xs text-muted-foreground">-</span>
                  )}
                </TableCell>
                {/* 费用 */}
                <TableCell className="text-center">
                  {billingData[String(cred.id)] ? (
                    <span
                      className="text-xs font-mono cursor-help"
                      title={`请求数: ${billingData[String(cred.id)].total_requests}\n${Object.entries(billingData[String(cred.id)].by_model).map(([model, stats]) => `${model.replace('claude-', '')}: $${stats.cost.toFixed(3)}`).join('\n')}`}
                    >
                      ${billingData[String(cred.id)].total_cost.toFixed(2)}
                    </span>
                  ) : (
                    <span className="text-xs text-muted-foreground">-</span>
                  )}
                </TableCell>
                {/* 操作 */}
                <TableCell className="text-right">
                  <div className="flex justify-end gap-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      className={`h-7 px-2 ${cred.disabled ? 'text-green-600' : 'text-red-500'}`}
                      onClick={() => handleToggleDisabled(cred.id, cred.disabled)}
                      disabled={togglingIds.has(cred.id)}
                      title={cred.disabled ? '启用' : '禁用'}
                    >
                      <Power className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 px-2"
                      onClick={() => handleRefreshToken(cred.id)}
                      disabled={refreshingIds.has(cred.id) || cred.authMethod === 'api_key'}
                      title="刷新 Token"
                    >
                      <RefreshCw className={`h-3.5 w-3.5 ${refreshingIds.has(cred.id) ? 'animate-spin' : ''}`} />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 px-2"
                      onClick={() => handleQueryBalance(cred.id)}
                      disabled={queryingIds.has(cred.id)}
                      title="查询信息"
                    >
                      <Search className={`h-3.5 w-3.5 ${queryingIds.has(cred.id) ? 'animate-pulse' : ''}`} />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 px-2"
                      onClick={() => setProxyCredential(cred)}
                      title="代理设置"
                    >
                      <Settings className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 px-2"
                      onClick={() => setDetailCredential(cred)}
                      title="查看详情"
                    >
                      <Eye className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 px-2 text-orange-500"
                      onClick={() => handleEnableOverage(cred.id)}
                      title="开启超额"
                    >
                      <Zap className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 px-2 text-red-500"
                      onClick={() => handleDelete(cred.id)}
                      title="删除"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>

      <CredentialDetailDialog
        open={!!detailCredential}
        onOpenChange={(open) => { if (!open) setDetailCredential(null) }}
        credential={detailCredential}
        balance={detailCredential ? balanceMap.get(detailCredential.id) || null : null}
      />

      <ProxySettingDialog
        open={!!proxyCredential}
        onOpenChange={(open) => { if (!open) setProxyCredential(null) }}
        credential={proxyCredential}
      />
    </>
  )
}
