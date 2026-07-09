import { useState, useEffect } from 'react'
import { toast } from 'sonner'
import { Trash2, Activity, Loader2 } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { importProxies, getProxyPool, deletePoolProxy, testPoolProxy } from '@/api/credentials'
import type { ProxyPoolItem } from '@/types/api'

interface ProxyImportDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess: () => void
}

export function ProxyImportDialog({ open, onOpenChange, onSuccess }: ProxyImportDialogProps) {
  const [text, setText] = useState('')
  const [importing, setImporting] = useState(false)
  const [proxies, setProxies] = useState<ProxyPoolItem[]>([])
  const [testingIds, setTestingIds] = useState<Set<number>>(new Set())
  const [latencyMap, setLatencyMap] = useState<Map<number, number | null>>(new Map())

  const lineCount = text.trim() ? text.trim().split('\n').filter(l => l.trim()).length : 0

  const fetchPool = async () => {
    try {
      const data = await getProxyPool()
      setProxies(data.proxies)
    } catch {}
  }

  useEffect(() => {
    if (open) fetchPool()
  }, [open])

  const handleImport = async () => {
    if (!text.trim()) {
      toast.error('请输入代理列表')
      return
    }
    setImporting(true)
    try {
      const res = await importProxies(text.trim())
      toast.success(res.message)
      setText('')
      fetchPool()
      onSuccess()
    } catch (err) {
      toast.error('导入失败: ' + (err as Error).message)
    } finally {
      setImporting(false)
    }
  }

  const handleDelete = async (id: number) => {
    try {
      await deletePoolProxy(id)
      toast.success('代理已删除')
      fetchPool()
      onSuccess()
    } catch (err) {
      toast.error('删除失败: ' + (err as Error).message)
    }
  }

  const handleTest = async (proxy: ProxyPoolItem) => {
    setTestingIds(prev => new Set(prev).add(proxy.id))
    try {
      const result = await testPoolProxy(proxy.id)
      setLatencyMap(prev => {
        const next = new Map(prev)
        next.set(proxy.id, result.latencyMs)
        return next
      })
      if (result.error) {
        toast.error(`代理 #${proxy.id} 失败: ${result.error}`)
      }
    } catch (err) {
      setLatencyMap(prev => { const next = new Map(prev); next.set(proxy.id, null); return next })
      toast.error('测试失败: ' + (err as Error).message)
    } finally {
      setTestingIds(prev => { const next = new Set(prev); next.delete(proxy.id); return next })
    }
  }

  const handleTestAll = async () => {
    if (proxies.length === 0) {
      toast.error('代理池为空')
      return
    }
    for (const proxy of proxies) {
      await handleTest(proxy)
    }
  }

  const formatUrl = (url: string) => url.replace(/^(socks5?|https?):\/\//, '')

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>代理池管理</DialogTitle>
        </DialogHeader>

        {/* 现有代理列表 */}
        {proxies.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">
                现有代理 ({proxies.filter(p => !p.usedByCredentialId).length} 可用 / {proxies.length} 总)
              </span>
              <Button size="sm" variant="outline" onClick={handleTestAll}>
                <Activity className="h-3.5 w-3.5 mr-1" />
                全部测活
              </Button>
            </div>
            <div className="border rounded-md divide-y max-h-[240px] overflow-y-auto">
              {proxies.map(proxy => (
                <div key={proxy.id} className="flex items-center justify-between px-3 py-1.5 text-xs">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="font-mono truncate">{formatUrl(proxy.url)}</span>
                    {proxy.username && <span className="text-muted-foreground">({proxy.username})</span>}
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {proxy.usedByCredentialId ? (
                      <span className="text-blue-500 text-[10px]">#{proxy.usedByCredentialId}</span>
                    ) : (
                      <span className="text-green-500 text-[10px]">空闲</span>
                    )}
                    {latencyMap.has(proxy.id) && (
                      latencyMap.get(proxy.id) !== null ? (
                        <span className={`font-mono ${(latencyMap.get(proxy.id) ?? 0) > 2000 ? 'text-red-500' : 'text-green-500'}`}>
                          {latencyMap.get(proxy.id)}ms
                        </span>
                      ) : (
                        <span className="text-red-500">失败</span>
                      )
                    )}
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 px-1"
                      onClick={() => handleTest(proxy)}
                      disabled={testingIds.has(proxy.id)}
                      title="测活"
                    >
                      {testingIds.has(proxy.id) ? <Loader2 className="h-3 w-3 animate-spin" /> : <Activity className="h-3 w-3" />}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 px-1 text-red-500"
                      onClick={() => handleDelete(proxy.id)}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* 导入区域 */}
        <div className="space-y-2 pt-2 border-t">
          <span className="text-sm font-medium">导入代理</span>
          <p className="text-xs text-muted-foreground">
            每行一个，格式: ip:port:user:pass（协议统一 socks5）
          </p>
          <textarea
            className="w-full h-32 p-2 text-xs font-mono border rounded-md bg-background resize-none focus:outline-none focus:ring-2 focus:ring-ring"
            placeholder="198.65.111.9:6783:username:password&#10;gate.kookeey.info:1000:user:pass"
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          <div className="flex items-center justify-between">
            {lineCount > 0 && (
              <p className="text-xs text-muted-foreground">检测到 {lineCount} 条代理</p>
            )}
            <Button onClick={handleImport} disabled={importing || lineCount === 0} size="sm">
              {importing ? '导入中...' : `导入 ${lineCount} 条`}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}