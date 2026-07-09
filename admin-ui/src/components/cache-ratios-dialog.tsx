import { useState, useEffect } from 'react'
import { toast } from 'sonner'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { useCacheRatios, useSetCacheRatios, useCacheMode, useSetCacheMode, useCacheInterrupt, useSetCacheInterrupt } from '@/hooks/use-credentials'
import { extractErrorMessage } from '@/lib/utils'

interface CacheRatiosDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

interface FieldDef {
  key: 'creation' | 'read' | 'uncached' | 'firstTurn' | 'output'
  label: string
  hint: string
}

const FIELDS: FieldDef[] = [
  {
    key: 'creation',
    label: '缓存创建',
    hint: '本次请求新写入缓存的 token（cache_creation_input_tokens）',
  },
  {
    key: 'read',
    label: '缓存读取',
    hint: '本次请求命中已有缓存的 token（cache_read_input_tokens）',
  },
  {
    key: 'uncached',
    label: '未缓存输入',
    hint: '多轮对话中本次新提问的 token（input_tokens）',
  },
  {
    key: 'firstTurn',
    label: '首轮全量',
    hint: '首次对话（无 assistant 历史）时的全量 token',
  },
  {
    key: 'output',
    label: '输出',
    hint: '模型回复内容的 token（output_tokens）',
  },
]

export function CacheRatiosDialog({ open, onOpenChange }: CacheRatiosDialogProps) {
  const { data, isLoading } = useCacheRatios()
  const { mutate: save, isPending } = useSetCacheRatios()
  const { data: modeData, isLoading: isModeLoading } = useCacheMode()
  const { mutate: saveMode, isPending: isModePending } = useSetCacheMode()
  const { data: interruptData, isLoading: isInterruptLoading } = useCacheInterrupt()
  const { mutate: saveInterrupt, isPending: isInterruptPending } = useSetCacheInterrupt()

  const [values, setValues] = useState<Record<FieldDef['key'], string>>({
    creation: '',
    read: '',
    uncached: '',
    firstTurn: '',
    output: '',
  })
  const [interruptMin, setInterruptMin] = useState('')
  const [interruptMax, setInterruptMax] = useState('')
  const [interruptDuration, setInterruptDuration] = useState('')

  useEffect(() => {
    if (open && data) {
      setValues({
        creation: String(data.creation),
        read: String(data.read),
        uncached: String(data.uncached),
        firstTurn: String(data.firstTurn),
        output: String(data.output),
      })
    }
  }, [open, data])

  useEffect(() => {
    if (open && interruptData) {
      setInterruptMin(String(Math.floor(interruptData.minSecs / 60)))
      setInterruptMax(String(Math.floor(interruptData.maxSecs / 60)))
      setInterruptDuration(String(interruptData.durationSecs))
    }
  }, [open, interruptData])

  const handleModeToggle = (checked: boolean) => {
    const newMode = checked ? 'standard' : 'fixed'
    saveMode({ mode: newMode }, {
      onSuccess: () => {
        toast.success(`缓存模式已切换为${checked ? '标准模式' : '固定模式'}`)
      },
      onError: (error) => {
        toast.error(`切换失败: ${extractErrorMessage(error)}`)
      },
    })
  }

  const handleInterruptToggle = (checked: boolean) => {
    const min = parseInt(interruptMin) || 5
    const max = parseInt(interruptMax) || 10
    const duration = parseInt(interruptDuration) || 10
    saveInterrupt({ enabled: checked, minSecs: min * 60, maxSecs: max * 60, durationSecs: duration }, {
      onSuccess: () => {
        toast.success(`间歇中断已${checked ? '开启' : '关闭'}`)
      },
      onError: (error) => {
        toast.error(`设置失败: ${extractErrorMessage(error)}`)
      },
    })
  }

  const handleInterruptSave = () => {
    const min = parseInt(interruptMin)
    const max = parseInt(interruptMax)
    const duration = parseInt(interruptDuration)
    if (!min || !max || min <= 0 || max <= 0) {
      toast.error('间隔分钟数必须为正整数')
      return
    }
    if (min > max) {
      toast.error('最小间隔不能大于最大间隔')
      return
    }
    if (!duration || duration <= 0) {
      toast.error('中断秒数必须为正整数')
      return
    }
    saveInterrupt({ enabled: interruptData?.enabled ?? false, minSecs: min * 60, maxSecs: max * 60, durationSecs: duration }, {
      onSuccess: () => {
        toast.success('间歇中断配置已更新')
      },
      onError: (error) => {
        toast.error(`设置失败: ${extractErrorMessage(error)}`)
      },
    })
  }

  const handleSave = () => {
    const parsed: Record<FieldDef['key'], number> = {} as Record<FieldDef['key'], number>
    for (const f of FIELDS) {
      const n = parseFloat(values[f.key])
      if (!isFinite(n) || n <= 0) {
        toast.error(`${f.label} 必须为正数`)
        return
      }
      parsed[f.key] = n
    }

    save(parsed, {
      onSuccess: () => {
        toast.success('缓存倍率已更新，下一次请求生效')
        onOpenChange(false)
      },
      onError: (error) => {
        toast.error(`保存失败: ${extractErrorMessage(error)}`)
      },
    })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>缓存 token 估算倍率</DialogTitle>
        </DialogHeader>

        {(isLoading || isModeLoading || isInterruptLoading) ? (
          <div className="flex items-center justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center justify-between rounded-md border p-3">
              <div>
                <div className="text-sm font-medium">标准模式</div>
                <p className="text-xs text-muted-foreground">
                  {modeData?.mode === 'standard'
                    ? '已启用：5 分钟 TTL + 前缀哈希匹配'
                    : '已关闭：始终视为缓存命中（固定模式）'}
                </p>
              </div>
              <Switch
                checked={modeData?.mode === 'standard'}
                onCheckedChange={handleModeToggle}
                disabled={isModePending}
              />
            </div>
            {modeData?.mode === 'fixed' && (
              <div className="rounded-md border p-3 space-y-2">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm font-medium">间歇中断</div>
                    <p className="text-xs text-muted-foreground">
                      {interruptData?.enabled
                        ? `已开启：每 ${interruptMin}~${interruptMax} 分钟断缓存 ${interruptDuration} 秒`
                        : '已关闭：固定模式始终全量命中'}
                    </p>
                  </div>
                  <Switch
                    checked={interruptData?.enabled ?? false}
                    onCheckedChange={handleInterruptToggle}
                    disabled={isInterruptPending}
                  />
                </div>
                {interruptData?.enabled && (
                  <div className="flex items-center gap-2 pt-1">
                    <Input
                      type="number"
                      min="1"
                      className="w-20"
                      value={interruptMin}
                      onChange={(e) => setInterruptMin(e.target.value)}
                      disabled={isInterruptPending}
                    />
                    <span className="text-xs text-muted-foreground">~</span>
                    <Input
                      type="number"
                      min="1"
                      className="w-20"
                      value={interruptMax}
                      onChange={(e) => setInterruptMax(e.target.value)}
                      disabled={isInterruptPending}
                    />
                    <span className="text-xs text-muted-foreground">分钟，断</span>
                    <Input
                      type="number"
                      min="1"
                      className="w-16"
                      value={interruptDuration}
                      onChange={(e) => setInterruptDuration(e.target.value)}
                      disabled={isInterruptPending}
                    />
                    <span className="text-xs text-muted-foreground">秒</span>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={handleInterruptSave}
                      disabled={isInterruptPending}
                    >
                      保存
                    </Button>
                  </div>
                )}
              </div>
            )}
            {FIELDS.map((f) => (
              <div key={f.key} className="space-y-1">
                <label htmlFor={`ratio-${f.key}`} className="text-sm font-medium">
                  {f.label}
                </label>
                <Input
                  id={`ratio-${f.key}`}
                  type="number"
                  step="0.01"
                  min="0.01"
                  value={values[f.key]}
                  onChange={(e) =>
                    setValues((prev) => ({ ...prev, [f.key]: e.target.value }))
                  }
                  disabled={isPending}
                />
                <p className="text-xs text-muted-foreground">{f.hint}</p>
              </div>
            ))}
            <p className="text-xs text-muted-foreground pt-1">
              倍率仅影响返回给客户端的 token 数显示，不影响实际请求或上游计费
            </p>
          </div>
        )}

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={isPending}
          >
            取消
          </Button>
          <Button type="button" onClick={handleSave} disabled={isPending || isLoading}>
            {isPending ? '保存中...' : '保存'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
