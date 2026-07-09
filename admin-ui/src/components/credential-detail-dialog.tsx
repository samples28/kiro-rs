import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import type { CredentialStatusItem, BalanceResponse } from '@/types/api'

interface CredentialDetailDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  credential: CredentialStatusItem | null
  balance: BalanceResponse | null
}

function formatTime(time: string | null): string {
  if (!time) return '-'
  return new Date(time).toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

export function CredentialDetailDialog({
  open,
  onOpenChange,
  credential,
  balance,
}: CredentialDetailDialogProps) {
  if (!credential) return null

  const rows: Array<{ label: string; value: React.ReactNode }> = [
    { label: '凭据 ID', value: `#${credential.id}` },
    { label: '邮箱', value: balance?.email || credential.email || '-' },
    {
      label: 'Refresh Token Hash',
      value: credential.refreshTokenHash ? (
        <span className="font-mono text-xs break-all">{credential.refreshTokenHash}</span>
      ) : '-',
    },
    {
      label: 'Access Token 过期时间',
      value: formatTime(credential.expiresAt),
    },
    {
      label: '订阅等级',
      value: balance?.subscriptionTitle || '-',
    },
    {
      label: '认证方式',
      value: credential.authMethod === 'api_key' ? 'API Key' :
             credential.authMethod === 'idc' ? 'IdC' :
             credential.authMethod === 'social' ? 'Social' :
             credential.authMethod || '-',
    },
    { label: '优先级', value: credential.priority },
    { label: '端点', value: credential.endpoint },
    { label: 'RPM (每分钟请求)', value: credential.rpm },
    { label: '成功次数', value: credential.successCount },
    { label: '失败次数', value: credential.failureCount },
    { label: '刷新失败次数', value: credential.refreshFailureCount },
    { label: '最后调用时间', value: formatTime(credential.lastUsedAt) },
    {
      label: '状态',
      value: credential.disabled ? (
        <Badge variant="destructive">已禁用</Badge>
      ) : (
        <Badge variant="success">启用</Badge>
      ),
    },
    {
      label: '禁用原因',
      value: credential.disabledReason || '-',
    },
    {
      label: '代理',
      value: credential.proxyUrl || '无代理',
    },
    {
      label: '限流配置',
      value: credential.cooldownEnabled === true
        ? `独立限流 (${credential.cooldownSeconds ?? '全局'}s/${credential.cooldownMaxRequests ?? '全局'}个)`
        : credential.cooldownEnabled === false
        ? '不限流'
        : '跟随全局',
    },
    {
      label: '用量',
      value: balance
        ? `${balance.currentUsage.toFixed(2)} / ${balance.usageLimit.toFixed(2)} (${balance.usagePercentage.toFixed(1)}%)`
        : '未查询',
    },
    {
      label: 'API Key (脱敏)',
      value: credential.maskedApiKey || '-',
    },
    {
      label: 'Profile ARN',
      value: credential.hasProfileArn ? '有' : '无',
    },
  ]

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>凭据 #{credential.id} 详情</DialogTitle>
        </DialogHeader>
        <div className="space-y-2">
          {rows.map((row) => (
            <div key={row.label} className="flex items-start gap-3 py-1.5 border-b last:border-0">
              <span className="text-sm text-muted-foreground w-40 shrink-0">{row.label}</span>
              <span className="text-sm font-medium break-all">{row.value}</span>
            </div>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  )
}
