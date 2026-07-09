import { useState } from 'react'
import { toast } from 'sonner'
import { RefreshCw, ChevronUp, ChevronDown, Trash2, Loader2, Search } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import type { CredentialStatusItem, BalanceResponse } from '@/types/api'
import { getCredentialBalance } from '@/api/credentials'
import {
  useSetDisabled,
  useSetPriority,
  useResetFailure,
  useDeleteCredential,
  useForceRefreshToken,
  useSetCredentialCooldown,
} from '@/hooks/use-credentials'

interface CredentialCardProps {
  credential: CredentialStatusItem
  selected: boolean
  onToggleSelect: () => void
  balance: BalanceResponse | null
  loadingBalance: boolean
  onBalanceUpdate?: (id: number, balance: BalanceResponse) => void
}

function formatLastUsed(lastUsedAt: string | null): string {
  if (!lastUsedAt) return '从未使用'
  const date = new Date(lastUsedAt)
  const now = new Date()
  const diff = now.getTime() - date.getTime()
  if (diff < 0) return '刚刚'
  const seconds = Math.floor(diff / 1000)
  if (seconds < 60) return `${seconds} 秒前`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} 分钟前`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} 小时前`
  const days = Math.floor(hours / 24)
  return `${days} 天前`
}

export function CredentialCard({
  credential,
  selected,
  onToggleSelect,
  balance,
  loadingBalance,
  onBalanceUpdate,
}: CredentialCardProps) {
  const [editingPriority, setEditingPriority] = useState(false)
  const [priorityValue, setPriorityValue] = useState(String(credential.priority))
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [editingCooldown, setEditingCooldown] = useState(false)
  const [cdSeconds, setCdSeconds] = useState(String(credential.cooldownSeconds ?? ''))
  const [cdMaxReqs, setCdMaxReqs] = useState(String(credential.cooldownMaxRequests ?? ''))
  const [queryingBalance, setQueryingBalance] = useState(false)

  const setDisabled = useSetDisabled()
  const setPriority = useSetPriority()
  const resetFailure = useResetFailure()
  const deleteCredential = useDeleteCredential()
  const forceRefresh = useForceRefreshToken()
  const setCredentialCooldown = useSetCredentialCooldown()

  const handleToggleDisabled = () => {
    setDisabled.mutate(
      { id: credential.id, disabled: !credential.disabled },
      {
        onSuccess: (res) => {
          toast.success(res.message)
        },
        onError: (err) => {
          toast.error('操作失败: ' + (err as Error).message)
        },
      }
    )
  }

  const handlePriorityChange = () => {
    const newPriority = parseInt(priorityValue, 10)
    if (isNaN(newPriority) || newPriority < 0) {
      toast.error('优先级必须是非负整数')
      return
    }
    setPriority.mutate(
      { id: credential.id, priority: newPriority },
      {
        onSuccess: (res) => {
          toast.success(res.message)
          setEditingPriority(false)
        },
        onError: (err) => {
          toast.error('操作失败: ' + (err as Error).message)
        },
      }
    )
  }

  const handleReset = () => {
    resetFailure.mutate(credential.id, {
      onSuccess: (res) => {
        toast.success(res.message)
      },
      onError: (err) => {
        toast.error('操作失败: ' + (err as Error).message)
      },
    })
  }

  const handleForceRefresh = () => {
    forceRefresh.mutate(credential.id, {
      onSuccess: (res) => {
        toast.success(res.message)
      },
      onError: (err) => {
        toast.error('刷新失败: ' + (err as Error).message)
      },
    })
  }

  const handleDelete = () => {
    if (!credential.disabled) {
      toast.error('请先禁用凭据再删除')
      setShowDeleteDialog(false)
      return
    }

    deleteCredential.mutate(credential.id, {
      onSuccess: (res) => {
        toast.success(res.message)
        setShowDeleteDialog(false)
      },
      onError: (err) => {
        toast.error('删除失败: ' + (err as Error).message)
      },
    })
  }

  const handleToggleCooldown = () => {
    const currentEnabled = credential.cooldownEnabled
    // 三态循环：未设置(undefined) → 开启(true) → 关闭(false) → 未设置(undefined)
    let newEnabled: boolean | undefined
    if (currentEnabled === undefined || currentEnabled === null) {
      newEnabled = true
    } else if (currentEnabled === true) {
      newEnabled = false
    } else {
      newEnabled = undefined
    }

    setCredentialCooldown.mutate(
      {
        id: credential.id,
        enabled: newEnabled,
        seconds: newEnabled === true ? (parseInt(cdSeconds, 10) || undefined) : undefined,
        maxRequests: newEnabled === true ? (parseInt(cdMaxReqs, 10) || undefined) : undefined,
      },
      {
        onSuccess: (res) => {
          toast.success(res.message)
          setEditingCooldown(false)
        },
        onError: (err) => {
          toast.error('操作失败: ' + (err as Error).message)
        },
      }
    )
  }

  const handleSaveCooldown = () => {
    const seconds = cdSeconds ? parseInt(cdSeconds, 10) : undefined
    const maxReqs = cdMaxReqs ? parseInt(cdMaxReqs, 10) : undefined

    if (seconds !== undefined && (isNaN(seconds) || seconds <= 0)) {
      toast.error('冷却窗口时长必须为正整数')
      return
    }
    if (maxReqs !== undefined && (isNaN(maxReqs) || maxReqs <= 0)) {
      toast.error('最大请求数必须为正整数')
      return
    }

    setCredentialCooldown.mutate(
      {
        id: credential.id,
        enabled: credential.cooldownEnabled ?? undefined,
        seconds,
        maxRequests: maxReqs,
      },
      {
        onSuccess: (res) => {
          toast.success(res.message)
          setEditingCooldown(false)
        },
        onError: (err) => {
          toast.error('保存失败: ' + (err as Error).message)
        },
      }
    )
  }

  const handleQueryBalance = async () => {
    setQueryingBalance(true)
    try {
      const result = await getCredentialBalance(credential.id)
      onBalanceUpdate?.(credential.id, result)
      toast.success('查询成功')
    } catch (err) {
      toast.error('查询失败: ' + (err as Error).message)
    } finally {
      setQueryingBalance(false)
    }
  }

  return (
    <>
      <Card className={credential.isCurrent ? 'ring-2 ring-primary' : ''}>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Checkbox
                checked={selected}
                onCheckedChange={onToggleSelect}
              />
              <CardTitle className="text-lg flex items-center gap-2">
                {`凭据 #${credential.id}`}
                {credential.isCurrent && (
                  <Badge variant="success">当前</Badge>
                )}
                {credential.disabled && (
                  <Badge variant="destructive">已禁用</Badge>
                )}
                {credential.disabled && credential.disabledReason && (
                  <Badge variant="outline">{credential.disabledReason}</Badge>
                )}
                {credential.authMethod && (
                  <Badge variant="secondary">
                    {credential.authMethod === 'api_key' ? 'API Key' :
                     credential.authMethod === 'idc' ? 'IdC' :
                     credential.authMethod === 'social' ? 'Social' :
                     credential.authMethod}
                  </Badge>
                )}
                {credential.endpoint && (
                  <Badge variant="outline">{credential.endpoint}</Badge>
                )}
              </CardTitle>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">启用</span>
              <Switch
                checked={!credential.disabled}
                onCheckedChange={handleToggleDisabled}
                disabled={setDisabled.isPending}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* 信息网格 */}
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-muted-foreground">优先级：</span>
              {editingPriority ? (
                <div className="inline-flex items-center gap-1 ml-1">
                  <Input
                    type="number"
                    value={priorityValue}
                    onChange={(e) => setPriorityValue(e.target.value)}
                    className="w-16 h-7 text-sm"
                    min="0"
                  />
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 w-7 p-0"
                    onClick={handlePriorityChange}
                    disabled={setPriority.isPending}
                  >
                    ✓
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 w-7 p-0"
                    onClick={() => {
                      setEditingPriority(false)
                      setPriorityValue(String(credential.priority))
                    }}
                  >
                    ✕
                  </Button>
                </div>
              ) : (
                <span
                  className="font-medium cursor-pointer hover:underline ml-1"
                  onClick={() => setEditingPriority(true)}
                >
                  {credential.priority}
                  <span className="text-xs text-muted-foreground ml-1">(点击编辑)</span>
                </span>
              )}
            </div>
            <div>
              <span className="text-muted-foreground">失败次数：</span>
              <span className={credential.failureCount > 0 ? 'text-red-500 font-medium' : ''}>
                {credential.failureCount}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">刷新失败：</span>
              <span className={credential.refreshFailureCount > 0 ? 'text-red-500 font-medium' : ''}>
                {credential.refreshFailureCount}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">订阅等级：</span>
              <span className="font-medium">
                {loadingBalance ? (
                  <Loader2 className="inline w-3 h-3 animate-spin" />
                ) : balance?.subscriptionTitle || '未知'}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">成功次数：</span>
              <span className="font-medium">{credential.successCount}</span>
            </div>
            <div className="col-span-2">
              <span className="text-muted-foreground">邮箱：</span>
              <span className="font-medium">
                {balance?.email || credential.email || '-'}
              </span>
            </div>
            <div className="col-span-2">
              <span className="text-muted-foreground">最后调用：</span>
              <span className="font-medium">{formatLastUsed(credential.lastUsedAt)}</span>
            </div>
            {credential.maskedApiKey && (
              <div className="col-span-2">
                <span className="text-muted-foreground">API Key：</span>
                <span className="font-mono font-medium">{credential.maskedApiKey}</span>
              </div>
            )}
            <div className="col-span-2">
              <span className="text-muted-foreground">用量：</span>
              {loadingBalance ? (
                <span className="text-sm ml-1">
                  <Loader2 className="inline w-3 h-3 animate-spin" /> 加载中...
                </span>
              ) : balance ? (
                (() => {
                  const used = balance.currentUsage
                  const limit = balance.usageLimit
                  const overage = used - limit
                  const isOverage = overage > 0
                  const pct = limit > 0 ? Math.min(100, (used / limit) * 100) : 0
                  const fmt = (n: number) =>
                    n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })
                  return (
                    <span className="ml-1 inline-flex items-center gap-2 align-middle flex-wrap">
                      <span className={`font-medium ${isOverage ? 'text-red-600 dark:text-red-400' : ''}`}>
                        {fmt(used)} / {fmt(limit)} 积分
                      </span>
                      {isOverage ? (
                        <Badge variant="destructive">超额 {fmt(overage)} 积分</Badge>
                      ) : (
                        <span className="text-xs text-muted-foreground">
                          ({pct.toFixed(1)}% 已用)
                        </span>
                      )}
                    </span>
                  )
                })()
              ) : (
                <span className="text-sm text-muted-foreground ml-1">未知</span>
              )}
            </div>
            {balance?.nextResetAt && (
              <div className="col-span-2">
                <span className="text-muted-foreground">下次重置：</span>
                <span className="font-medium ml-1">
                  {new Date(balance.nextResetAt * 1000).toLocaleString('zh-CN', {
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                    hour12: false,
                  })}
                </span>
              </div>
            )}
            {credential.hasProxy && (
              <div className="col-span-2">
                <span className="text-muted-foreground">代理：</span>
                <span className="font-medium">{credential.proxyUrl}</span>
              </div>
            )}
            {credential.hasProfileArn && (
              <div className="col-span-2">
                <Badge variant="secondary">有 Profile ARN</Badge>
              </div>
            )}
            <div className="col-span-2 border-t pt-2 mt-1">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">限流：</span>
                  {credential.cooldownEnabled === true ? (
                    <Badge variant="default" className="cursor-pointer" onClick={handleToggleCooldown}>
                      独立限流
                    </Badge>
                  ) : credential.cooldownEnabled === false ? (
                    <Badge variant="outline" className="cursor-pointer" onClick={handleToggleCooldown}>
                      不限流
                    </Badge>
                  ) : (
                    <Badge variant="secondary" className="cursor-pointer" onClick={handleToggleCooldown}>
                      跟随全局
                    </Badge>
                  )}
                  {credential.cooldownEnabled === true && !editingCooldown && (
                    <span className="text-xs text-muted-foreground">
                      {credential.cooldownSeconds ?? '全局'}秒/{credential.cooldownMaxRequests ?? '全局'}个
                      <span
                        className="ml-1 cursor-pointer hover:underline"
                        onClick={() => setEditingCooldown(true)}
                      >(编辑)</span>
                    </span>
                  )}
                </div>
              </div>
              {editingCooldown && credential.cooldownEnabled === true && (
                <div className="flex items-center gap-2 mt-2">
                  <Input
                    type="number"
                    value={cdSeconds}
                    onChange={(e) => setCdSeconds(e.target.value)}
                    placeholder="秒"
                    className="w-16 h-7 text-sm"
                    min="1"
                  />
                  <span className="text-xs text-muted-foreground">秒</span>
                  <Input
                    type="number"
                    value={cdMaxReqs}
                    onChange={(e) => setCdMaxReqs(e.target.value)}
                    placeholder="个"
                    className="w-16 h-7 text-sm"
                    min="1"
                  />
                  <span className="text-xs text-muted-foreground">个</span>
                  <Button size="sm" variant="ghost" className="h-7 px-2" onClick={handleSaveCooldown}>
                    保存
                  </Button>
                  <Button size="sm" variant="ghost" className="h-7 px-2" onClick={() => setEditingCooldown(false)}>
                    取消
                  </Button>
                </div>
              )}
            </div>
          </div>

          {/* 操作按钮 */}
          <div className="flex flex-wrap gap-2 pt-2 border-t">
            <Button
              size="sm"
              variant="outline"
              onClick={handleReset}
              disabled={resetFailure.isPending || (credential.failureCount === 0 && credential.refreshFailureCount === 0)}
            >
              <RefreshCw className="h-4 w-4 mr-1" />
              重置失败
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                const newPriority = Math.max(0, credential.priority - 1)
                setPriority.mutate(
                  { id: credential.id, priority: newPriority },
                  {
                    onSuccess: (res) => toast.success(res.message),
                    onError: (err) => toast.error('操作失败: ' + (err as Error).message),
                  }
                )
              }}
              disabled={setPriority.isPending || credential.priority === 0}
            >
              <ChevronUp className="h-4 w-4 mr-1" />
              提高优先级
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                const newPriority = credential.priority + 1
                setPriority.mutate(
                  { id: credential.id, priority: newPriority },
                  {
                    onSuccess: (res) => toast.success(res.message),
                    onError: (err) => toast.error('操作失败: ' + (err as Error).message),
                  }
                )
              }}
              disabled={setPriority.isPending}
            >
              <ChevronDown className="h-4 w-4 mr-1" />
              降低优先级
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={handleForceRefresh}
              disabled={forceRefresh.isPending || credential.authMethod === 'api_key'}
              title={credential.authMethod === 'api_key' ? 'API Key 凭据无需刷新 Token' : '强制刷新 Token'}
            >
              <RefreshCw className={`h-4 w-4 mr-1 ${forceRefresh.isPending ? 'animate-spin' : ''}`} />
              刷新 Token
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={handleQueryBalance}
              disabled={queryingBalance}
              title="查询用量信息（token 失效会自动刷新）"
            >
              <Search className={`h-4 w-4 mr-1 ${queryingBalance ? 'animate-pulse' : ''}`} />
              查询信息
            </Button>
            <Button
              size="sm"
              variant="destructive"
              onClick={() => setShowDeleteDialog(true)}
              disabled={!credential.disabled}
              title={!credential.disabled ? '需要先禁用凭据才能删除' : undefined}
            >
              <Trash2 className="h-4 w-4 mr-1" />
              删除
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* 删除确认对话框 */}
      <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>确认删除凭据</DialogTitle>
            <DialogDescription>
              您确定要删除凭据 #{credential.id} 吗？此操作无法撤销。
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowDeleteDialog(false)}
              disabled={deleteCredential.isPending}
            >
              取消
            </Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={deleteCredential.isPending || !credential.disabled}
            >
              确认删除
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
