import { useState, useEffect } from 'react'
import { toast } from 'sonner'
import { Trash2, Activity, Loader2, Server, Moon, Sun, LogOut, Upload } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table'
import { importProxies, getProxyPool, deletePoolProxy, testPoolProxy } from '@/api/credentials'
import type { ProxyPoolItem } from '@/types/api'
import { storage } from '@/lib/storage'

interface ProxyPageProps {
  onLogout: () => void
  onNavigate: (page: string) => void
}

export function ProxyPage({ onLogout, onNavigate }: ProxyPageProps) {
  const [proxies, setProxies] = useState<ProxyPoolItem[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [testingIds, setTestingIds] = useState<Set<number>>(new Set())
  const [latencyMap, setLatencyMap] = useState<Map<number, number | null>>(new Map())
  const [text, setText] = useState('')
  const [importing, setImporting] = useState(false)
  const [testingAll, setTestingAll] = useState(false)
  const [darkMode, setDarkMode] = useState(() => document.documentElement.classList.contains('dark'))
  const [currentPage, setCurrentPage] = useState(1)
  const [itemsPerPage, setItemsPerPage] = useState(20)
  const [filter, setFilter] = useState<'all' | 'available' | 'used'>('all')

  const lineCount = text.trim() ? text.trim().split('\n').filter(l => l.trim()).length : 0
  const available = proxies.filter(p => !p.usedByCredentialId).length
  const filteredProxies = filter === 'all' ? proxies : filter === 'available' ? proxies.filter(p => !p.usedByCredentialId) : proxies.filter(p => !!p.usedByCredentialId)
  const totalPages = Math.ceil(filteredProxies.length / itemsPerPage)
  const pageProxies = filteredProxies.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage)

  const fetchPool = async () => {
    try {
      const data = await getProxyPool()
      setProxies(data.proxies)
    } catch {} finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchPool() }, [])

  const handleImport = async () => {
    if (!text.trim()) { toast.error('请输入代理列表'); return }
    setImporting(true)
    try {
      const res = await importProxies(text.trim())
      toast.success(res.message)
      setText('')
      fetchPool()
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
    } catch (err) {
      toast.error('删除失败: ' + (err as Error).message)
    }
  }

  const handleTest = async (proxy: ProxyPoolItem) => {
    setTestingIds(prev => new Set(prev).add(proxy.id))
    try {
      const result = await testPoolProxy(proxy.id)
      setLatencyMap(prev => { const next = new Map(prev); next.set(proxy.id, result.latencyMs); return next })
      if (result.error) toast.error(`#${proxy.id} 失败: ${result.error}`)
    } catch (err) {
      setLatencyMap(prev => { const next = new Map(prev); next.set(proxy.id, null); return next })
      toast.error('测试失败: ' + (err as Error).message)
    } finally {
      setTestingIds(prev => { const next = new Set(prev); next.delete(proxy.id); return next })
    }
  }

  const handleTestAll = async () => {
    if (proxies.length === 0) { toast.error('代理池为空'); return }
    setTestingAll(true)
    for (const proxy of proxies) {
      await handleTest(proxy)
    }
    setTestingAll(false)
    toast.success('全部测活完成')
  }

  const handleBatchDelete = async () => {
    if (selectedIds.size === 0) { toast.error('请先选择代理'); return }
    if (!confirm(`确定要删除选中的 ${selectedIds.size} 个代理吗？`)) return
    let success = 0, fail = 0
    for (const id of selectedIds) {
      try { await deletePoolProxy(id); success++ } catch { fail++ }
    }
    toast.success(`删除完成：成功 ${success}${fail > 0 ? `，失败 ${fail}` : ''}`)
    setSelectedIds(new Set())
    fetchPool()
  }

  const handleBatchTest = async () => {
    if (selectedIds.size === 0) { toast.error('请先选择代理'); return }
    const selected = proxies.filter(p => selectedIds.has(p.id))
    for (const proxy of selected) {
      await handleTest(proxy)
    }
    toast.success(`已测活 ${selected.length} 个代理`)
  }

  const toggleSelect = (id: number) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  const formatUrl = (url: string) => url.replace(/^(socks5?|https?):\/\//, '')

  return (
    <div className="min-h-screen bg-background">
      {/* 顶部导航 */}
      <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="flex h-14 items-center justify-between px-4 md:px-8">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Server className="h-5 w-5" />
              <button onClick={() => onNavigate('dashboard')} className="font-semibold hover:text-primary transition-colors">
                Kiro Admin
              </button>
            </div>
            <span className="text-muted-foreground">/</span>
            <span className="font-semibold text-primary">IP Admin</span>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="icon" onClick={() => { setDarkMode(!darkMode); document.documentElement.classList.toggle('dark') }}>
              {darkMode ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
            </Button>
            <Button variant="ghost" size="icon" onClick={() => { storage.removeApiKey(); onLogout() }}>
              <LogOut className="h-5 w-5" />
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto px-4 md:px-8 py-6">
        {/* 统计 */}
        <div className="grid gap-4 md:grid-cols-3 mb-6">
          <Card className={`cursor-pointer transition-all ${filter === 'all' ? 'ring-2 ring-primary' : 'hover:bg-muted/50'}`} onClick={() => { setFilter('all'); setCurrentPage(1) }}>
            <CardHeader className="pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">代理总数</CardTitle></CardHeader>
            <CardContent><div className="text-2xl font-bold">{proxies.length}</div></CardContent>
          </Card>
          <Card className={`cursor-pointer transition-all ${filter === 'available' ? 'ring-2 ring-green-500' : 'hover:bg-muted/50'}`} onClick={() => { setFilter('available'); setCurrentPage(1) }}>
            <CardHeader className="pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">可用（空闲）</CardTitle></CardHeader>
            <CardContent><div className="text-2xl font-bold text-green-600">{available}</div></CardContent>
          </Card>
          <Card className={`cursor-pointer transition-all ${filter === 'used' ? 'ring-2 ring-blue-500' : 'hover:bg-muted/50'}`} onClick={() => { setFilter('used'); setCurrentPage(1) }}>
            <CardHeader className="pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">已分配</CardTitle></CardHeader>
            <CardContent><div className="text-2xl font-bold text-blue-600">{proxies.length - available}</div></CardContent>
          </Card>
        </div>

        <div className="grid gap-6 lg:grid-cols-3">
          {/* 左侧：代理列表 */}
          <div className="lg:col-span-2">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <h2 className="text-lg font-semibold">代理列表</h2>
                {selectedIds.size > 0 && (
                  <span className="text-xs text-muted-foreground">已选 {selectedIds.size}</span>
                )}
              </div>
              <div className="flex items-center gap-2">
                {selectedIds.size > 0 && (
                  <>
                    <Button size="sm" variant="outline" onClick={handleBatchTest}>
                      <Activity className="h-4 w-4 mr-1" />
                      批量测活
                    </Button>
                    <Button size="sm" variant="destructive" onClick={handleBatchDelete}>
                      <Trash2 className="h-4 w-4 mr-1" />
                      批量删除
                    </Button>
                  </>
                )}
                <Button size="sm" variant="outline" onClick={handleTestAll} disabled={testingAll || proxies.length === 0}>
                  <Activity className={`h-4 w-4 mr-2 ${testingAll ? 'animate-spin' : ''}`} />
                  {testingAll ? '测活中...' : '全部测活'}
                </Button>
              </div>
            </div>
            {loading ? (
              <div className="text-center py-8 text-muted-foreground">加载中...</div>
            ) : proxies.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">代理池为空，请从右侧导入</div>
            ) : (
              <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-7">
                      <Checkbox
                        checked={filteredProxies.length > 0 && filteredProxies.every(p => selectedIds.has(p.id))}
                        onCheckedChange={(checked) => {
                          setSelectedIds(checked ? new Set(filteredProxies.map(p => p.id)) : new Set())
                        }}
                      />
                    </TableHead>
                    <TableHead>IP:端口</TableHead>
                    <TableHead>用户名</TableHead>
                    <TableHead>密码</TableHead>
                    <TableHead className="text-center">状态</TableHead>
                    <TableHead className="text-center">历史</TableHead>
                    <TableHead className="text-center">延迟</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pageProxies.map(proxy => (
                    <TableRow key={proxy.id} data-state={selectedIds.has(proxy.id) ? 'selected' : undefined}>
                      <TableCell>
                        <Checkbox
                          checked={selectedIds.has(proxy.id)}
                          onCheckedChange={() => toggleSelect(proxy.id)}
                        />
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {proxy.flagged && <span title="该代理曾被替换，可能有问题">⚠️ </span>}
                        {formatUrl(proxy.url)}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{proxy.username || '-'}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{proxy.password || '-'}</TableCell>
                      <TableCell className="text-center">
                        {proxy.usedByCredentialId ? (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300 font-medium">
                            #{proxy.usedByCredentialId}
                          </span>
                        ) : (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300 font-medium">
                            空闲
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-center">
                        <span className="text-xs text-muted-foreground">{proxy.historyCount ?? 0}</span>
                      </TableCell>
                      <TableCell className="text-center">
                        {testingIds.has(proxy.id) ? (
                          <Loader2 className="h-3 w-3 animate-spin inline" />
                        ) : latencyMap.has(proxy.id) ? (
                          latencyMap.get(proxy.id) !== null ? (
                            <span className={`text-xs font-mono ${(latencyMap.get(proxy.id) ?? 0) > 2000 ? 'text-red-500' : (latencyMap.get(proxy.id) ?? 0) > 500 ? 'text-yellow-500' : 'text-green-500'}`}>
                              {latencyMap.get(proxy.id)}ms
                            </span>
                          ) : (
                            <span className="text-xs text-red-500">失败</span>
                          )
                        ) : (
                          <span className="text-xs text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button variant="ghost" size="sm" className="h-6 px-1" onClick={() => handleTest(proxy)} disabled={testingIds.has(proxy.id)}>
                            {testingIds.has(proxy.id) ? <Loader2 className="h-3 w-3 animate-spin" /> : <Activity className="h-3 w-3" />}
                          </Button>
                          <Button variant="ghost" size="sm" className="h-6 px-1 text-red-500" onClick={() => handleDelete(proxy.id)}>
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {/* 分页 */}
              <div className="flex justify-center items-center gap-2 mt-4 flex-wrap">
                {totalPages > 1 && (
                  <>
                    <Button variant="outline" size="sm" className="h-7 px-2 text-xs" onClick={() => setCurrentPage(1)} disabled={currentPage === 1}>首页</Button>
                    <Button variant="outline" size="sm" className="h-7 px-2 text-xs" onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1}>上一页</Button>
                    <span className="text-xs text-muted-foreground">{currentPage}/{totalPages}（共{filteredProxies.length}）</span>
                    <Button variant="outline" size="sm" className="h-7 px-2 text-xs" onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages}>下一页</Button>
                    <Button variant="outline" size="sm" className="h-7 px-2 text-xs" onClick={() => setCurrentPage(totalPages)} disabled={currentPage === totalPages}>尾页</Button>
                  </>
                )}
                <div className="flex items-center gap-1 ml-2">
                  <span className="text-xs text-muted-foreground">每页</span>
                  {[10, 20, 50, 100].map(size => (
                    <Button key={size} variant={itemsPerPage === size ? 'default' : 'outline'} size="sm" className="h-7 px-2 text-xs" onClick={() => { setItemsPerPage(size); setCurrentPage(1) }}>{size}</Button>
                  ))}
                  <Input type="number" className="w-16 h-7 text-xs px-1.5" placeholder="自定" min="1" onKeyDown={(e) => { if (e.key === 'Enter') { const v = parseInt((e.target as HTMLInputElement).value, 10); if (v > 0) { setItemsPerPage(v); setCurrentPage(1) } } }} />
                </div>
              </div>
              </>
            )}
          </div>

          {/* 右侧：导入区域 */}
          <div>
            <h2 className="text-lg font-semibold mb-4">导入代理</h2>
            <div className="space-y-3">
              <p className="text-xs text-muted-foreground">
                每行一个，格式: ip:port:user:pass（协议统一 socks5）
              </p>
              <textarea
                className="w-full h-48 p-2 text-xs font-mono border rounded-md bg-background resize-none focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="198.65.111.9:6783:username:password&#10;gate.kookeey.info:1000:user:pass"
                value={text}
                onChange={(e) => setText(e.target.value)}
              />
              {lineCount > 0 && (
                <p className="text-xs text-muted-foreground">检测到 {lineCount} 条代理</p>
              )}
              <Button onClick={handleImport} disabled={importing || lineCount === 0} className="w-full">
                <Upload className="h-4 w-4 mr-2" />
                {importing ? '导入测活中...' : `导入 ${lineCount} 条`}
              </Button>
              <p className="text-[10px] text-muted-foreground">导入时会自动测活，不通的将被跳过</p>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
