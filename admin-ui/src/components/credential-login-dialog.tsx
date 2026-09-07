import { useEffect, useRef, useState } from 'react'
import { CheckCircle, Copy, ExternalLink, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { cancelLogin, completeSocialLogin, pollLogin, startIdcLogin, startSocialLogin } from '@/api/credentials'
import { extractErrorMessage } from '@/lib/utils'
import type { CompleteSocialLoginRequest, PollLoginResponse, StartIdcLoginResponse, StartSocialLoginResponse } from '@/types/api'

export type LoginMode = 'social' | 'builder-id' | 'enterprise'
type Session = StartSocialLoginResponse | StartIdcLoginResponse
type Step = 'form' | 'waiting' | 'done' | 'error'

const TITLES: Record<LoginMode, string> = {
  social: 'Kiro 账号登录（Google / GitHub）',
  'builder-id': 'AWS SSO / Builder ID 登录',
  enterprise: 'Enterprise (IAM Identity Center) 登录',
}

function parseCallback(raw: string, portalUrl: string): CompleteSocialLoginRequest | null {
  try {
    const url = new URL(raw.trim())
    const portal = new URL(portalUrl)
    const redirect = new URL(portal.searchParams.get('redirect_uri')!)
    const code = url.searchParams.get('code')
    const state = url.searchParams.get('state')
    if (!code || !state || url.searchParams.has('error') || url.protocol !== 'http:'
      || !['localhost', '127.0.0.1'].includes(url.hostname) || url.port !== redirect.port
      || !['/oauth/callback', '/signin/callback'].includes(url.pathname)
      || state !== portal.searchParams.get('state')) return null
    return { code, state, loginOption: url.searchParams.get('login_option') ?? '', path: url.pathname }
  } catch { return null }
}

// 对话框按登录模式挂载，退出时撤销会话，避免旧请求影响下一次登录。
export function CredentialLoginDialog({ mode, onClose, onSuccess }: {
  mode: LoginMode
  onClose: () => void
  onSuccess: (credentialId: number) => void
}) {
  const social = mode === 'social'
  const [step, setStep] = useState<Step>('form')
  const [email, setEmail] = useState('')
  const [region, setRegion] = useState('us-east-1')
  const [startUrl, setStartUrl] = useState('')
  const [incognito, setIncognito] = useState(false)
  const [busy, setBusy] = useState(false)
  const [session, setSession] = useState<Session | null>(null)
  const [credentialId, setCredentialId] = useState<number>()
  const [callback, setCallback] = useState('')
  const [error, setError] = useState('')
  const [manualCopy, setManualCopy] = useState(false)
  const active = useRef(false)
  const sessionRef = useRef<Session | null>(null)
  const timer = useRef<ReturnType<typeof setTimeout>>()
  const controller = useRef<AbortController>()
  const completed = useRef(false)
  const manuallyCompleting = useRef(false)
  const linkRef = useRef<HTMLTextAreaElement>(null)
  const successRef = useRef(onSuccess)
  successRef.current = onSuccess

  useEffect(() => {
    active.current = true
    return () => {
      active.current = false
      clearTimeout(timer.current)
      controller.current?.abort()
      if (sessionRef.current) void cancelLogin(sessionRef.current.sessionId).catch(() => {})
    }
  }, [])

  const stopPolling = () => {
    clearTimeout(timer.current)
    controller.current?.abort()
  }

  const fail = (message: string) => {
    stopPolling()
    setError(message)
    setStep('error')
  }

  const acceptResult = (result: PollLoginResponse): boolean => {
    if (!active.current || completed.current) return true
    if (result.status === 'pending') return false
    stopPolling()
    if (result.status === 'success') {
      completed.current = true
      setCredentialId(result.credentialId)
      setStep('done')
      successRef.current(result.credentialId)
      toast.success(`登录成功，已添加凭据 #${result.credentialId}`)
    } else {
      fail('登录会话已过期，请重新发起登录。')
    }
    return true
  }

  const schedulePoll = (current: Session, interval: number) => {
    clearTimeout(timer.current)
    timer.current = setTimeout(async () => {
      if (!active.current || completed.current || manuallyCompleting.current) return
      // 由服务器判断过期，避免客户端时钟偏差或正在保存时误报过期。
      const request = new AbortController()
      controller.current = request
      try {
        const result = await pollLogin(social ? 'social' : 'idc', current.sessionId, request.signal)
        if (!active.current || request.signal.aborted) return
        setError(previous => previous === '暂时无法连接服务器，正在重试…' ? '' : previous)
        if (!acceptResult(result) && result.status === 'pending') schedulePoll(current, result.pollInterval)
      } catch (e) {
        if (!active.current || request.signal.aborted) return
        // 断网时保留当前会话，HTTP 错误则显示明确的重试入口。
        if ((e as { response?: unknown }).response) {
          fail(extractErrorMessage(e))
        } else {
          setError('暂时无法连接服务器，正在重试…')
          schedulePoll(current, Math.max(5, interval))
        }
      }
    }, Math.max(1, interval) * 1000)
  }

  const copy = async (text: string) => {
    const sessionId = sessionRef.current?.sessionId
    const stillWaiting = () => active.current && !completed.current && sessionRef.current?.sessionId === sessionId
    try {
      await navigator.clipboard.writeText(text)
      if (stillWaiting()) { setManualCopy(false); toast.success('已复制') }
    } catch {
      if (!stillWaiting()) return
      setManualCopy(true)
      linkRef.current?.focus()
      linkRef.current?.select()
    }
  }

  const begin = async () => {
    if (!social && !region.trim()) { setError('请填写 AWS Region'); return }
    if (mode === 'enterprise' && !startUrl.trim()) { setError('请填写组织的 SSO Start URL'); return }
    if (!social && startUrl.trim()) {
      try {
        if (new URL(startUrl.trim()).protocol !== 'https:') throw new Error()
      } catch { setError('SSO Start URL 必须是有效的 HTTPS 地址'); return }
    }
    setBusy(true)
    setError('')
    completed.current = false
    // 在点击事件中预开窗口以兼容弹窗拦截；无痕模式由用户自行打开。
    const loginWindow = !incognito && social ? window.open('about:blank', '_blank') : null
    if (loginWindow) loginWindow.opener = null
    try {
      if (sessionRef.current) await cancelLogin(sessionRef.current.sessionId)
      const current = social
        ? await startSocialLogin({ email: email.trim() || undefined })
        : await startIdcLogin({ region: region.trim(), startUrl: startUrl.trim() || undefined, email: email.trim() || undefined })
      if (!active.current) {
        loginWindow?.close()
        void cancelLogin(current.sessionId).catch(() => {})
        return
      }
      sessionRef.current = current
      setSession(current)
      setCallback('')
      setManualCopy(false)
      setStep('waiting')
      const url = 'portalUrl' in current ? current.portalUrl : current.verificationUriComplete ?? current.verificationUri
      if (loginWindow) loginWindow.location.href = url
      // 本机、远程及端口转发均支持轮询；回调不可达时可手动粘贴。
      if (active.current) schedulePoll(current, 'pollInterval' in current ? current.pollInterval : 2)
      // 剪贴板权限可能一直等待用户选择，不能阻塞登录状态轮询。
      if (incognito) void copy(url)
    } catch (e) {
      loginWindow?.close()
      if (active.current) setError('发起登录失败：' + extractErrorMessage(e))
    } finally { if (active.current) setBusy(false) }
  }

  const complete = async () => {
    if (!session || !('portalUrl' in session)) return
    const parsed = parseCallback(callback, session.portalUrl)
    if (!parsed) { setError('回调地址无效或不属于本次登录，请复制授权后地址栏中的完整 URL。'); return }
    manuallyCompleting.current = true
    stopPolling()
    setBusy(true)
    setError('')
    const request = new AbortController()
    controller.current = request
    try {
      const result = await completeSocialLogin(session.sessionId, parsed, request.signal)
      if (!active.current || request.signal.aborted) return
      if (!acceptResult(result) && result.status === 'pending') schedulePoll(session, result.pollInterval)
    } catch (e) {
      if (active.current && !request.signal.aborted) {
        setError('完成登录失败：' + extractErrorMessage(e))
        schedulePoll(session, 2)
      }
    } finally {
      manuallyCompleting.current = false
      if (active.current) setBusy(false)
    }
  }

  const url = session ? ('portalUrl' in session ? session.portalUrl : session.verificationUriComplete ?? session.verificationUri) : ''

  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{TITLES[mode]}</DialogTitle>
          <DialogDescription>
            {social ? '在 Kiro 登录页选择 Google 或 GitHub，授权后自动添加凭据。'
              : mode === 'enterprise' ? '填写组织的 SSO Start URL 和区域，通过设备授权添加企业凭据。'
                : '通过 AWS 设备授权添加凭据，无需手动导出令牌。'}
          </DialogDescription>
        </DialogHeader>

        {step === 'form' && (
          <div className="space-y-4">
            {!social && <>
              <div className="space-y-1.5">
                <label htmlFor="login-region" className="text-sm font-medium">AWS Region</label>
                <Input id="login-region" list="login-regions" value={region} disabled={busy} onChange={e => setRegion(e.target.value)} />
                <datalist id="login-regions">
                  {['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-west-2', 'eu-central-1', 'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2'].map(r => <option key={r} value={r} />)}
                </datalist>
              </div>
              <div className="space-y-1.5">
                <label htmlFor="login-start-url" className="text-sm font-medium">SSO Start URL{mode === 'builder-id' && '（留空使用 AWS Builder ID）'}</label>
                <Input id="login-start-url" placeholder={mode === 'enterprise' ? 'https://your-org.awsapps.com/start' : 'https://view.awsapps.com/start'} value={startUrl} disabled={busy} onChange={e => setStartUrl(e.target.value)} autoComplete="off" />
              </div>
            </>}
            <div className="space-y-1.5">
              <label htmlFor="login-email" className="text-sm font-medium">邮箱（可选）</label>
              <Input id="login-email" placeholder="user@example.com" value={email} disabled={busy} onChange={e => setEmail(e.target.value)} autoComplete="off" />
            </div>
            <label className="flex cursor-pointer items-start gap-2 rounded-lg border bg-muted/40 p-3 text-sm">
              <input type="checkbox" className="mt-1 accent-primary" checked={incognito} disabled={busy} onChange={e => setIncognito(e.target.checked)} />
              <span>使用无痕窗口登录<span className="mt-1 block text-xs text-muted-foreground">发起后复制链接，在浏览器无痕 / 隐私窗口打开，可切换其他账号。</span></span>
            </label>
          </div>
        )}

        {step === 'waiting' && session && (
          <div className="space-y-4">
            <div className="space-y-3 rounded-lg border bg-muted/40 p-4">
              <p className="text-sm">{incognito ? '请在无痕 / 隐私窗口（Ctrl+Shift+N）打开以下链接并完成授权。' : '请打开登录页并完成授权，然后返回此处。'}</p>
              <textarea aria-label="登录链接" ref={linkRef} readOnly value={url} onFocus={e => e.currentTarget.select()} className="min-h-[72px] w-full rounded-md border bg-background p-2 font-mono text-xs" />
              <div className="flex flex-wrap items-center gap-3">
                <Button size="sm" variant="outline" onClick={() => void copy(url)}><Copy className="mr-2 h-4 w-4" />复制登录链接</Button>
                {!incognito && <a className="inline-flex items-center gap-1 text-sm text-primary hover:underline" href={url} target="_blank" rel="noopener noreferrer">打开登录页<ExternalLink className="h-4 w-4" /></a>}
              </div>
              {manualCopy && <p role="status" className="text-xs text-muted-foreground">浏览器未允许自动复制，请选中上方链接后按 Ctrl+C。</p>}
              {'userCode' in session && <div className="text-center">
                <p className="text-xs text-muted-foreground">在授权页面确认或输入验证码</p>
                <p className="select-all font-mono text-2xl font-bold tracking-widest">{session.userCode}</p>
              </div>}
            </div>
            <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />正在等待授权完成…</p>
            {social && <div className="space-y-2">
              <label htmlFor="login-callback" className="text-sm font-medium">回调地址</label>
              <p className="text-xs text-muted-foreground">远程访问或容器部署时，授权后可能跳转到无法访问的 localhost / 127.0.0.1 页面。请复制该页面地址栏中的完整 URL，粘贴后点击“完成登录”。本机访问可自动完成。</p>
              <textarea id="login-callback" value={callback} onChange={e => setCallback(e.target.value)} disabled={busy} placeholder="http://127.0.0.1:3128/oauth/callback?code=...&state=..." className="min-h-[80px] w-full rounded-md border bg-background p-2 font-mono text-xs" />
            </div>}
          </div>
        )}

        {step === 'done' && <div className="flex flex-col items-center gap-3 py-4">
          <CheckCircle className="h-10 w-10 text-green-500" />
          <p>登录成功</p><p className="text-sm text-muted-foreground">凭据 #{credentialId} 已添加并启用</p>
        </div>}
        {error && step !== 'done' && <p role="alert" className="break-words text-sm text-destructive">{error}</p>}

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>{step === 'done' ? '关闭' : '取消'}</Button>
          {step === 'form' && <Button onClick={begin} disabled={busy}>{busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}发起登录</Button>}
          {step === 'waiting' && social && <Button onClick={complete} disabled={busy || !callback.trim()}>{busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}完成登录</Button>}
          {step === 'error' && <Button onClick={() => { setError(''); setStep('form') }}>重新登录</Button>}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
