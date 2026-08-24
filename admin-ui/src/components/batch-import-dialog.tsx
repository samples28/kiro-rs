import { useState, useMemo } from 'react'
import { toast } from 'sonner'
import { useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, XCircle, AlertCircle, Loader2 } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { useCredentials, useAddCredential, useDeleteCredential } from '@/hooks/use-credentials'
import { getCredentialBalance, setCredentialDisabled } from '@/api/credentials'
import { extractErrorMessage, sha256Hex } from '@/lib/utils'

interface BatchImportDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onBalanceUpdate?: (id: number, balance: import('@/types/api').BalanceResponse) => void
}

// 统一的输入格式：把通用 JSON、KAM 格式（{accounts:[...]}、credentials 嵌套、平铺）
// 与提取器格式（kiro_personal：apiKey / provider / plan / credits_* 等）归一化到这个结构
interface CredentialInput {
  refreshToken?: string
  clientId?: string
  clientSecret?: string
  profileArn?: string
  region?: string
  authRegion?: string
  apiRegion?: string
  priority?: number
  machineId?: string
  kiroApiKey?: string
  authMethod?: 'social' | 'idc' | 'enterprise' | 'builderid' | 'api_key'
  endpoint?: string
  proxyUrl?: string
  proxyUsername?: string
  proxyPassword?: string
  // 仅用于展示与跳过
  email?: string
  password?: string
  nickname?: string
  status?: string
}

interface VerificationResult {
  index: number
  status: 'pending' | 'checking' | 'verifying' | 'verified' | 'duplicate' | 'failed' | 'skipped'
  error?: string
  usage?: string
  email?: string
  credentialId?: number
  rollbackStatus?: 'success' | 'failed' | 'skipped'
  rollbackError?: string
}

// 按顺序取第一个非空字符串字段（兼容 camelCase / snake_case 别名）
function pickStr(
  obj: Record<string, unknown>,
  ...keys: string[]
): string | undefined {
  for (const key of keys) {
    const value = obj[key]
    if (typeof value === 'string' && value.trim().length > 0) return value.trim()
  }
  return undefined
}

function pickNum(obj: Record<string, unknown>, ...keys: string[]): number | undefined {
  for (const key of keys) {
    const value = obj[key]
    if (typeof value === 'number' && Number.isFinite(value)) return value
    if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) {
      return Number(value)
    }
  }
  return undefined
}

// 归一化 authMethod / provider 到后端接受的取值
function canonAuthMethod(raw?: string): CredentialInput['authMethod'] | undefined {
  if (!raw) return undefined
  const v = raw.toLowerCase().replace(/[\s-]/g, '_')
  if (v === 'api_key' || v === 'apikey' || v === 'kiro_api_key') return 'api_key'
  if (v === 'idc' || v === 'iam' || v === 'sso') return 'idc'
  if (v === 'builderid' || v === 'builder_id' || v === 'aws_builder_id') return 'builderid'
  if (v === 'enterprise') return 'enterprise'
  if (v === 'social' || v === 'google' || v === 'github' || v === 'oauth') return 'social'
  return undefined
}

// 把单条 JSON 项归一化为 CredentialInput
// 支持：
//   1. 通用格式：{ refreshToken, clientId, ... } 或 { kiroApiKey }
//   2. KAM 旧格式：{ email, credentials: { refreshToken, clientId, ... }, machineId, status }
//   3. KAM 新格式（1.8.3+）：{ email, refreshToken, ... } 平铺
//   4. 提取器格式（type=kiro_personal）：{ apiKey, accessToken, refreshToken, clientId,
//      clientSecret, authMethod, provider, profileArn, plan, credits_*, ... } 平铺，
//      字段名允许 snake_case 别名
function normalizeItem(item: unknown): CredentialInput | null {
  if (typeof item !== 'object' || item === null) return null
  const obj = item as Record<string, unknown>

  // KAM 旧格式：credentials 嵌套。把嵌套字段抬到顶层后走统一逻辑
  const nested =
    typeof obj.credentials === 'object' && obj.credentials !== null
      ? (obj.credentials as Record<string, unknown>)
      : null
  const flat: Record<string, unknown> = nested ? { ...obj, ...nested } : obj

  const refreshToken = pickStr(flat, 'refreshToken', 'refresh_token')
  const apiKey = pickStr(flat, 'kiroApiKey', 'kiro_api_key', 'apiKey', 'api_key')
  const clientId = pickStr(flat, 'clientId', 'client_id')
  const clientSecret = pickStr(flat, 'clientSecret', 'client_secret')

  const explicitAuthMethod = canonAuthMethod(pickStr(flat, 'authMethod', 'auth_method'))
  // provider 仅在没有显式 authMethod 时作为回退：Enterprise → enterprise,
  // BuilderId → builderid, Google/GitHub → social
  const declared = explicitAuthMethod ?? canonAuthMethod(pickStr(flat, 'provider'))
  const hasOidcClient = !!(clientId && clientSecret)

  // 决定走 OAuth 还是 API Key。
  // 有些导出（如 type=kiro_personal）同时带 refreshToken 和 ksk_ 开头的 apiKey：
  // 后端只要看到 kiroApiKey 就会把整条凭据当作不可刷新的 API Key 模式，
  // 所以这里优先用 refreshToken，仅在显式 api_key 或没有 refreshToken 时才用 apiKey。
  const useApiKey = !!apiKey && (declared === 'api_key' || !refreshToken)

  let authMethod: CredentialInput['authMethod']
  if (useApiKey) {
    authMethod = 'api_key'
  } else if (explicitAuthMethod && explicitAuthMethod !== 'api_key') {
    // 显式声明优先；client 凭据缺失等问题留到导入阶段给出明确报错
    authMethod = explicitAuthMethod
  } else if (!hasOidcClient) {
    // 没有完整 OIDC 客户端凭据时只能走 social 刷新端点，
    // 避免由 provider 推断出必然刷新失败的 idc/builderid
    authMethod = 'social'
  } else {
    // 有完整 client 凭据：沿用 provider 推断出的 OIDC 家族，否则按 idc
    authMethod = declared === 'builderid' || declared === 'enterprise' ? declared : 'idc'
  }

  return {
    refreshToken: useApiKey ? undefined : refreshToken,
    clientId: useApiKey ? undefined : clientId,
    clientSecret: useApiKey ? undefined : clientSecret,
    profileArn: pickStr(flat, 'profileArn', 'profile_arn'),
    region: pickStr(flat, 'region'),
    authRegion: pickStr(flat, 'authRegion', 'auth_region'),
    apiRegion: pickStr(flat, 'apiRegion', 'api_region'),
    priority: pickNum(flat, 'priority'),
    machineId: pickStr(flat, 'machineId', 'machine_id'),
    kiroApiKey: useApiKey ? apiKey : undefined,
    authMethod,
    endpoint: pickStr(flat, 'endpoint'),
    proxyUrl: pickStr(flat, 'proxyUrl', 'proxy_url'),
    proxyUsername: pickStr(flat, 'proxyUsername', 'proxy_username'),
    proxyPassword: pickStr(flat, 'proxyPassword', 'proxy_password'),
    email: pickStr(flat, 'email'),
    password: pickStr(flat, 'password'),
    nickname: pickStr(flat, 'nickname', 'label', 'name'),
    status: pickStr(flat, 'status', 'accountStatus', 'account_status'),
  }
}

// 解析根节点为原始条目数组
// 支持：数组、单对象、{ accounts | credentials | data | items: [...] } 包裹
function rootToItems(parsed: unknown): unknown[] {
  if (Array.isArray(parsed)) return parsed
  if (parsed && typeof parsed === 'object') {
    const obj = parsed as Record<string, unknown>
    for (const key of ['accounts', 'credentials', 'data', 'items']) {
      if (Array.isArray(obj[key])) return obj[key] as unknown[]
    }
    return [parsed]
  }
  throw new Error('JSON 根必须是对象、数组或 { accounts: [...] }')
}

// 逐条解析多个并列/换行分隔的 JSON 对象（JSONL 或直接首尾相接粘贴）
// 通过括号配对切分，字符串内的括号与转义会被跳过
function splitConcatenatedJson(raw: string): unknown[] {
  const items: unknown[] = []
  let depth = 0
  let start = -1
  let inString = false
  let escaped = false

  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i]
    if (inString) {
      if (escaped) escaped = false
      else if (ch === '\\') escaped = true
      else if (ch === '"') inString = false
      continue
    }
    if (ch === '"') {
      inString = true
    } else if (ch === '{' || ch === '[') {
      if (depth === 0) start = i
      depth++
    } else if (ch === '}' || ch === ']') {
      depth--
      if (depth === 0 && start >= 0) {
        items.push(JSON.parse(raw.slice(start, i + 1)))
        start = -1
      } else if (depth < 0) {
        throw new Error('括号不匹配')
      }
    }
  }

  if (depth !== 0) throw new Error('JSON 不完整')
  if (items.length === 0) throw new Error('未找到 JSON 对象')
  return items
}

// 解析输入 JSON，归一化为 CredentialInput[]
function parseInput(raw: string): CredentialInput[] {
  let rawItems: unknown[]
  try {
    rawItems = rootToItems(JSON.parse(raw))
  } catch (e) {
    // 整体解析失败时，尝试按并列 JSON 对象（JSONL / 多段粘贴）切分
    try {
      rawItems = splitConcatenatedJson(raw).flatMap((p) => rootToItems(p))
    } catch {
      throw e
    }
  }

  const result: CredentialInput[] = []
  for (const item of rawItems) {
    const norm = normalizeItem(item)
    if (norm && (norm.refreshToken || norm.kiroApiKey)) {
      result.push(norm)
    }
  }
  return result
}

export function BatchImportDialog({ open, onOpenChange, onBalanceUpdate }: BatchImportDialogProps) {
  const queryClient = useQueryClient()
  const [jsonInput, setJsonInput] = useState('')
  const [importing, setImporting] = useState(false)
  const [skipErrorAccounts, setSkipErrorAccounts] = useState(true)
  const [autoAllocateProxy, setAutoAllocateProxy] = useState(true)
  const [progress, setProgress] = useState({ current: 0, total: 0 })
  const [currentProcessing, setCurrentProcessing] = useState<string>('')
  const [results, setResults] = useState<VerificationResult[]>([])

  const { data: existingCredentials } = useCredentials()
  const { mutateAsync: addCredential } = useAddCredential()
  const { mutateAsync: deleteCredential } = useDeleteCredential()

  const rollbackCredential = async (id: number): Promise<{ success: boolean; error?: string }> => {
    try {
      await setCredentialDisabled(id, true)
    } catch (error) {
      return {
        success: false,
        error: `禁用失败: ${extractErrorMessage(error)}`,
      }
    }

    try {
      await deleteCredential(id)
      return { success: true }
    } catch (error) {
      return {
        success: false,
        error: `删除失败: ${extractErrorMessage(error)}`,
      }
    }
  }

  const resetForm = () => {
    setJsonInput('')
    setProgress({ current: 0, total: 0 })
    setCurrentProcessing('')
    setResults([])
  }

  // 预览解析结果（用于在按钮可用前给反馈，并显示 error 跳过开关）
  const { previewItems, parseError } = useMemo(() => {
    if (!jsonInput.trim()) return { previewItems: [] as CredentialInput[], parseError: '' }
    try {
      return { previewItems: parseInput(jsonInput), parseError: '' }
    } catch (e) {
      return { previewItems: [] as CredentialInput[], parseError: extractErrorMessage(e) }
    }
  }, [jsonInput])

  const errorAccountCount = previewItems.filter((c) => c.status === 'error').length

  const handleBatchImport = async () => {
    let credentials: CredentialInput[]
    try {
      credentials = parseInput(jsonInput)
    } catch (error) {
      toast.error('JSON 格式错误: ' + extractErrorMessage(error))
      return
    }

    if (credentials.length === 0) {
      toast.error('没有可导入的凭据')
      return
    }

    try {
      setImporting(true)
      setProgress({ current: 0, total: credentials.length })

      // 初始化结果（提前标记 KAM error 状态为 skipped）
      const initialResults: VerificationResult[] = credentials.map((c, i) => {
        if (skipErrorAccounts && c.status === 'error') {
          return {
            index: i + 1,
            status: 'skipped',
            email: c.email || c.nickname,
          }
        }
        return {
          index: i + 1,
          status: 'pending',
          email: c.email || c.nickname,
        }
      })
      setResults(initialResults)

      // 检测重复：OAuth 与 API Key 分别使用对应的 hash 集合
      const existingOauthHashes = new Set(
        existingCredentials?.credentials
          .map(c => c.refreshTokenHash)
          .filter((hash): hash is string => Boolean(hash)) || []
      )
      const existingApiKeyHashes = new Set(
        existingCredentials?.credentials
          .map(c => c.apiKeyHash)
          .filter((hash): hash is string => Boolean(hash)) || []
      )

      let successCount = 0
      let duplicateCount = 0
      let failCount = 0
      let skippedCount = 0
      let rollbackSuccessCount = 0
      let rollbackFailedCount = 0
      let rollbackSkippedCount = 0

      // Phase 1: 同步去重和参数校验
      interface TaskItem {
        i: number
        cred: CredentialInput
        isApiKeyCred: boolean
        credHash: string
      }
      const tasks: TaskItem[] = []

      for (let i = 0; i < credentials.length; i++) {
        const cred = credentials[i]

        if (skipErrorAccounts && cred.status === 'error') {
          skippedCount++
          setResults(prev => {
            const newResults = [...prev]
            newResults[i] = { ...newResults[i], status: 'skipped' }
            return newResults
          })
          setProgress({ current: i + 1, total: credentials.length })
          continue
        }

        const isApiKeyCred = cred.authMethod === 'api_key' || !!cred.kiroApiKey

        let credHash = ''
        if (isApiKeyCred) {
          const apiKey = cred.kiroApiKey?.trim() || ''
          if (!apiKey) {
            setResults(prev => {
              const newResults = [...prev]
              newResults[i] = { ...newResults[i], status: 'failed', error: '缺少 kiroApiKey' }
              return newResults
            })
            failCount++
            setProgress({ current: i + 1, total: credentials.length })
            continue
          }
          credHash = await sha256Hex(apiKey)
          if (existingApiKeyHashes.has(credHash)) {
            duplicateCount++
            const existingCred = existingCredentials?.credentials.find(c => c.apiKeyHash === credHash)
            setResults(prev => {
              const newResults = [...prev]
              newResults[i] = { ...newResults[i], status: 'duplicate', error: '该凭据已存在', email: existingCred?.email || cred.email }
              return newResults
            })
            setProgress({ current: i + 1, total: credentials.length })
            continue
          }
          existingApiKeyHashes.add(credHash)
        } else {
          const token = cred.refreshToken?.trim() || ''
          if (!token) {
            setResults(prev => {
              const newResults = [...prev]
              newResults[i] = { ...newResults[i], status: 'failed', error: '缺少 refreshToken' }
              return newResults
            })
            failCount++
            setProgress({ current: i + 1, total: credentials.length })
            continue
          }
          credHash = await sha256Hex(token)
          if (existingOauthHashes.has(credHash)) {
            duplicateCount++
            const existingCred = existingCredentials?.credentials.find(c => c.refreshTokenHash === credHash)
            setResults(prev => {
              const newResults = [...prev]
              newResults[i] = { ...newResults[i], status: 'duplicate', error: '该凭据已存在', email: existingCred?.email || cred.email }
              return newResults
            })
            setProgress({ current: i + 1, total: credentials.length })
            continue
          }
          existingOauthHashes.add(credHash)
        }

        tasks.push({ i, cred, isApiKeyCred, credHash })
      }

      // Phase 2: 10 并发执行 API 调用
      const CONCURRENCY = 10
      let completed = credentials.length - tasks.length // 已处理的（去重/跳过/失败）

      const processTask = async (task: TaskItem) => {
        const { i, cred, isApiKeyCred } = task

        setResults(prev => {
          const newResults = [...prev]
          newResults[i] = { ...newResults[i], status: 'verifying' }
          return newResults
        })

        let addedCredId: number | null = null

        try {
          let addedCred: { credentialId: number; email?: string; balance?: import('@/types/api').BalanceResponse }

          // normalizeItem 已完成 trim 与字段归一化，这里只做分支与必填校验
          const common = {
            priority: cred.priority || 0,
            authRegion: cred.authRegion || cred.region,
            apiRegion: cred.apiRegion,
            machineId: cred.machineId,
            endpoint: cred.endpoint,
            proxyUrl: cred.proxyUrl,
            proxyUsername: cred.proxyUsername,
            proxyPassword: cred.proxyPassword,
            email: cred.email,
            password: cred.password,
            autoAllocateProxy,
          }

          if (isApiKeyCred) {
            addedCred = await addCredential({
              ...common,
              authMethod: 'api_key',
              kiroApiKey: cred.kiroApiKey,
            })
          } else {
            // normalizeItem 保证这里不会是 api_key
            const authMethod = cred.authMethod as Exclude<typeof cred.authMethod, 'api_key'>

            // idc / enterprise / builderid 走 OIDC 刷新，必须同时有 clientId 和 clientSecret
            if (authMethod !== 'social' && !(cred.clientId && cred.clientSecret)) {
              throw new Error(`${authMethod} 模式需要同时提供 clientId 和 clientSecret`)
            }
            if (authMethod === 'social' && (cred.clientId || cred.clientSecret)) {
              throw new Error('idc 模式需要同时提供 clientId 和 clientSecret')
            }

            addedCred = await addCredential({
              ...common,
              refreshToken: cred.refreshToken,
              authMethod,
              clientId: cred.clientId,
              clientSecret: cred.clientSecret,
              profileArn: cred.profileArn,
            })
          }

          addedCredId = addedCred.credentialId
          if (addedCred.balance && onBalanceUpdate) {
            onBalanceUpdate(addedCred.credentialId, addedCred.balance)
          }

          await new Promise(resolve => setTimeout(resolve, 1000))
          const balance = await getCredentialBalance(addedCred.credentialId)

          successCount++
          setResults(prev => {
            const newResults = [...prev]
            newResults[i] = {
              ...newResults[i],
              status: 'verified',
              usage: `${balance.currentUsage}/${balance.usageLimit}`,
              email: addedCred.email || cred.email,
              credentialId: addedCred.credentialId,
            }
            return newResults
          })
        } catch (error) {
          let rollbackStatus: VerificationResult['rollbackStatus'] = 'skipped'
          let rollbackError: string | undefined

          if (addedCredId) {
            const rollbackResult = await rollbackCredential(addedCredId)
            if (rollbackResult.success) {
              rollbackStatus = 'success'
              rollbackSuccessCount++
            } else {
              rollbackStatus = 'failed'
              rollbackFailedCount++
              rollbackError = rollbackResult.error
            }
          } else {
            rollbackSkippedCount++
          }

          failCount++
          setResults(prev => {
            const newResults = [...prev]
            newResults[i] = {
              ...newResults[i],
              status: 'failed',
              error: extractErrorMessage(error),
              rollbackStatus,
              rollbackError,
            }
            return newResults
          })
        }

        completed++
        setProgress({ current: completed, total: credentials.length })
        setCurrentProcessing(`并发导入中 ${completed}/${credentials.length}`)
      }

      // 并发池
      const executing = new Set<Promise<void>>()
      for (const task of tasks) {
        const p = processTask(task).then(() => { executing.delete(p) })
        executing.add(p)
        if (executing.size >= CONCURRENCY) {
          await Promise.race(executing)
        }
      }
      await Promise.all(executing)

      const parts: string[] = []
      if (successCount > 0) parts.push(`成功 ${successCount}`)
      if (duplicateCount > 0) parts.push(`重复 ${duplicateCount}`)
      if (failCount > 0) parts.push(`失败 ${failCount}`)
      if (skippedCount > 0) parts.push(`跳过 ${skippedCount}`)

      if (failCount === 0 && duplicateCount === 0 && skippedCount === 0) {
        toast.success(`成功导入并验活 ${successCount} 个凭据`)
      } else {
        const failureSummary =
          failCount > 0
            ? `（失败回滚：已排除 ${rollbackSuccessCount}，未排除 ${rollbackFailedCount}，无需排除 ${rollbackSkippedCount}）`
            : ''
        toast.info(`导入完成：${parts.join('，')}${failureSummary}`)

        if (rollbackFailedCount > 0) {
          toast.warning(`有 ${rollbackFailedCount} 个失败凭据回滚未完成，请手动禁用并删除`)
        }
      }
    } catch (error) {
      toast.error('导入失败: ' + extractErrorMessage(error))
    } finally {
      setImporting(false)
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    }
  }

  const getStatusIcon = (status: VerificationResult['status']) => {
    switch (status) {
      case 'pending':
        return <div className="w-5 h-5 rounded-full border-2 border-gray-300" />
      case 'checking':
      case 'verifying':
        return <Loader2 className="w-5 h-5 animate-spin text-blue-500" />
      case 'verified':
        return <CheckCircle2 className="w-5 h-5 text-green-500" />
      case 'duplicate':
        return <AlertCircle className="w-5 h-5 text-yellow-500" />
      case 'skipped':
        return <AlertCircle className="w-5 h-5 text-gray-400" />
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-500" />
    }
  }

  const getStatusText = (result: VerificationResult) => {
    switch (result.status) {
      case 'pending':
        return '等待中'
      case 'checking':
        return '检查重复...'
      case 'verifying':
        return '验活中...'
      case 'verified':
        return '验活成功'
      case 'duplicate':
        return '重复凭据'
      case 'skipped':
        return '已跳过（error 状态）'
      case 'failed':
        if (result.rollbackStatus === 'success') return '验活失败（已排除）'
        if (result.rollbackStatus === 'failed') return '验活失败（未排除）'
        return '验活失败（未创建）'
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(newOpen) => {
        if (!newOpen && !importing) {
          resetForm()
        }
        onOpenChange(newOpen)
      }}
    >
      <DialogContent className="sm:max-w-2xl max-h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>批量导入凭据（自动验活）</DialogTitle>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-4 py-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">JSON 凭据</label>
            <textarea
              placeholder={'粘贴 JSON 凭据，支持以下格式：\n\n1) 通用格式（数组或单对象）\nOAuth: [{"refreshToken":"...", "authMethod":"social|idc", "clientId":"...", "clientSecret":"...", "authRegion":"...", "apiRegion":"...", "priority":0, "machineId":"...", "endpoint":"...", "email":"...", "password":"...", "proxyUrl":"...", "proxyUsername":"...", "proxyPassword":"..."}]\nAPI Key: [{"kiroApiKey":"ksk_xxx", "endpoint":"...", "email":"...", "password":"...", "proxyUrl":"..."}]\n\n2) KAM 旧版导出（嵌套）\n{"version":"1.5.0", "accounts":[{"email":"...", "password":"...", "credentials":{"refreshToken":"...", "clientId":"...", "clientSecret":"...", "region":"...", "authMethod":"..."}, "machineId":"...", "proxyUrl":"...", "proxyUsername":"...", "proxyPassword":"..."}]}\n\n3) KAM 1.8.3+ 导出（平铺）\n[{"email":"...", "password":"...", "refreshToken":"...", "clientId":"...", "clientSecret":"...", "region":"...", "authRegion":"...", "apiRegion":"...", "machineId":"...", "endpoint":"...", "proxyUrl":"...", "proxyUsername":"...", "proxyPassword":"..."}]\n\n4) 提取器导出（type=kiro_personal，可直接整段粘贴，多条可换行并列）\n{"accessToken":"...", "apiKey":"ksk_xxx", "authMethod":"idc", "clientId":"...", "clientSecret":"...", "email":"...", "plan":"KIRO PRO MAX", "profileArn":"", "provider":"BuilderId", "refreshToken":"...", "type":"kiro_personal"}\n\n字段名兼容 snake_case（refresh_token / client_id / profile_arn ...）\n同时带 refreshToken 和 apiKey 时优先按 OAuth 导入（可刷新）\n所有字段除 refreshToken/kiroApiKey(apiKey) 外均为可选'}
              value={jsonInput}
              onChange={(e) => setJsonInput(e.target.value)}
              disabled={importing}
              className="flex min-h-[200px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 font-mono"
            />
            <p className="text-xs text-muted-foreground">
              导入时自动验活，失败凭据自动排除。支持凭据级代理，设置后验活和请求均走该代理
            </p>
          </div>

          {parseError && (
            <div className="text-sm text-red-600 dark:text-red-400">解析失败: {parseError}</div>
          )}

          {previewItems.length > 0 && !importing && results.length === 0 && (
            <div className="space-y-2">
              <div className="text-sm text-muted-foreground">
                识别到 {previewItems.length} 个凭据
                {errorAccountCount > 0 && `（其中 ${errorAccountCount} 个为 error 状态）`}
              </div>
              {errorAccountCount > 0 && (
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={skipErrorAccounts}
                    onChange={(e) => setSkipErrorAccounts(e.target.checked)}
                    className="rounded border-gray-300"
                  />
                  跳过 error 状态的凭据
                </label>
              )}
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={autoAllocateProxy}
                  onChange={(e) => setAutoAllocateProxy(e.target.checked)}
                  className="rounded border-gray-300"
                />
                自动分配代理池IP
              </label>
            </div>
          )}

          {(importing || results.length > 0) && (
            <>
              {/* 进度条 */}
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>{importing ? '验活进度' : '验活完成'}</span>
                  <span>{progress.current} / {progress.total}</span>
                </div>
                <div className="w-full bg-secondary rounded-full h-2">
                  <div
                    className="bg-primary h-2 rounded-full transition-all"
                    style={{ width: `${progress.total > 0 ? (progress.current / progress.total) * 100 : 0}%` }}
                  />
                </div>
                {importing && currentProcessing && (
                  <div className="text-xs text-muted-foreground">
                    {currentProcessing}
                  </div>
                )}
              </div>

              {/* 统计 */}
              <div className="flex gap-4 text-sm">
                <span className="text-green-600 dark:text-green-400">
                  ✓ 成功: {results.filter(r => r.status === 'verified').length}
                </span>
                <span className="text-yellow-600 dark:text-yellow-400">
                  ⚠ 重复: {results.filter(r => r.status === 'duplicate').length}
                </span>
                <span className="text-red-600 dark:text-red-400">
                  ✗ 失败: {results.filter(r => r.status === 'failed').length}
                </span>
                <span className="text-gray-500">
                  ○ 跳过: {results.filter(r => r.status === 'skipped').length}
                </span>
              </div>

              {/* 结果列表 */}
              <div className="border rounded-md divide-y max-h-[300px] overflow-y-auto">
                {results.map((result) => (
                  <div key={result.index} className="p-3">
                    <div className="flex items-start gap-3">
                      {getStatusIcon(result.status)}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium">
                            {result.email || `凭据 #${result.index}`}
                          </span>
                          <span className="text-xs text-muted-foreground">
                            {getStatusText(result)}
                          </span>
                        </div>
                        {result.usage && (
                          <div className="text-xs text-muted-foreground mt-1">
                            用量: {result.usage}
                          </div>
                        )}
                        {result.error && (
                          <div className="text-xs text-red-600 dark:text-red-400 mt-1">
                            {result.error}
                          </div>
                        )}
                        {result.rollbackError && (
                          <div className="text-xs text-red-600 dark:text-red-400 mt-1">
                            回滚失败: {result.rollbackError}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              onOpenChange(false)
              resetForm()
            }}
            disabled={importing}
          >
            {importing ? '验活中...' : results.length > 0 ? '关闭' : '取消'}
          </Button>
          {results.length === 0 && (
            <Button
              type="button"
              onClick={handleBatchImport}
              disabled={importing || !jsonInput.trim() || previewItems.length === 0 || !!parseError}
            >
              开始导入并验活
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
