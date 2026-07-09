import { useState, useEffect } from 'react'
import { toast } from 'sonner'
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import type { CredentialStatusItem, ProxyPoolItem } from '@/types/api'
import { useSetProxy } from '@/hooks/use-credentials'
import { getProxyPool } from '@/api/credentials'

interface ProxySettingDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  credential: CredentialStatusItem | null
}

export function ProxySettingDialog({
  open,
  onOpenChange,
  credential,
}: ProxySettingDialogProps) {
  const [proxyUrl, setProxyUrl] = useState('')
  const [proxyUsername, setProxyUsername] = useState('')
  const [proxyPassword, setProxyPassword] = useState('')
  const [poolProxies, setPoolProxies] = useState<ProxyPoolItem[]>([])
  const setProxy = useSetProxy()

  // 打开时加载数据
  useEffect(() => {
    if (open && credential) {
      setProxyUrl(credential.proxyUrl || '')
      setProxyUsername('')
      setProxyPassword('')
      getProxyPool().then(data => {
        setPoolProxies(data.proxies.filter(p => !p.usedByCredentialId))
      }).catch(() => {})
    }
  }, [open, credential])

  const handleSave = () => {
    if (!credential) return
    setProxy.mutate(
      {
        id: credential.id,
        proxyUrl: proxyUrl.trim() || null,
        proxyUsername: proxyUsername.trim() || null,
        proxyPassword: proxyPassword.trim() || null,
      },
      {
        onSuccess: (res) => {
          toast.success(res.message)
          onOpenChange(false)
        },
        onError: (err) => {
          toast.error('设置失败: ' + (err as Error).message)
        },
      }
    )
  }

  const handleSelectPool = (proxy: ProxyPoolItem) => {
    setProxyUrl(proxy.url)
    setProxyUsername(proxy.username || '')
    setProxyPassword(proxy.password || '')
  }

  const formatUrl = (url: string) => url.replace(/^(socks5?|https?):\/\//, '')

  if (!credential) return null

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>凭据 #{credential.id} 代理设置</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          {/* 从代理池选择 */}
          {poolProxies.length > 0 && (
            <div>
              <label className="text-sm text-muted-foreground mb-1 block">从代理池选择（空闲）</label>
              <div className="border rounded-md max-h-[120px] overflow-y-auto divide-y">
                {poolProxies.map(proxy => (
                  <button
                    key={proxy.id}
                    className="w-full flex items-center justify-between px-2 py-1.5 text-xs hover:bg-muted/50 transition-colors"
                    onClick={() => handleSelectPool(proxy)}
                  >
                    <span className="font-mono truncate">{formatUrl(proxy.url)}</span>
                    {proxy.username && <span className="text-muted-foreground ml-2">({proxy.username})</span>}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* 手动输入 */}
          <div>
            <label className="text-sm text-muted-foreground">代理 URL</label>
            <Input
              value={proxyUrl}
              onChange={(e) => setProxyUrl(e.target.value)}
              placeholder="socks5://ip:port 或 http://ip:port（留空清除代理）"
            />
          </div>
          <div>
            <label className="text-sm text-muted-foreground">用户名（可选）</label>
            <Input
              value={proxyUsername}
              onChange={(e) => setProxyUsername(e.target.value)}
              placeholder="代理认证用户名"
            />
          </div>
          <div>
            <label className="text-sm text-muted-foreground">密码（可选）</label>
            <Input
              type="password"
              value={proxyPassword}
              onChange={(e) => setProxyPassword(e.target.value)}
              placeholder="代理认证密码"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button onClick={handleSave} disabled={setProxy.isPending}>
            {setProxy.isPending ? '保存中...' : '保存'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
