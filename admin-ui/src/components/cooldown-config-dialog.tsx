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
import { useCooldownConfig, useSetCooldownConfig } from '@/hooks/use-credentials'
import { extractErrorMessage } from '@/lib/utils'

interface CooldownConfigDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function CooldownConfigDialog({ open, onOpenChange }: CooldownConfigDialogProps) {
  const { data: cooldownData, isLoading } = useCooldownConfig()
  const { mutate: setCooldownConfig, isPending } = useSetCooldownConfig()

  const [enabled, setEnabled] = useState(false)
  const [seconds, setSeconds] = useState('')
  const [maxRequests, setMaxRequests] = useState('')

  useEffect(() => {
    if (open && cooldownData) {
      setEnabled(cooldownData.enabled)
      setSeconds(String(cooldownData.seconds))
      setMaxRequests(String(cooldownData.maxRequests))
    }
  }, [open, cooldownData])

  const handleSave = () => {
    const secondsNum = parseInt(seconds, 10)
    const maxReqsNum = parseInt(maxRequests, 10)

    if (isNaN(secondsNum) || secondsNum <= 0) {
      toast.error('限流窗口时长必须为正整数')
      return
    }
    if (isNaN(maxReqsNum) || maxReqsNum <= 0) {
      toast.error('最大请求数必须为正整数')
      return
    }

    setCooldownConfig(
      { enabled, seconds: secondsNum, maxRequests: maxReqsNum },
      {
        onSuccess: () => {
          toast.success('限流配置已保存')
          onOpenChange(false)
        },
        onError: (error) => {
          toast.error(`保存失败: ${extractErrorMessage(error)}`)
        },
      }
    )
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>限流配置</DialogTitle>
        </DialogHeader>

        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center justify-between rounded-md border p-3">
              <div>
                <div className="text-sm font-medium">启用限流</div>
                <p className="text-xs text-muted-foreground">关闭后所有凭据不限流</p>
              </div>
              <Switch
                checked={enabled}
                onCheckedChange={setEnabled}
                disabled={isPending}
              />
            </div>

            <div className="space-y-2">
              <label htmlFor="cooldown-seconds" className="text-sm font-medium">
                限流窗口时长（秒）
              </label>
              <Input
                id="cooldown-seconds"
                type="number"
                min="1"
                value={seconds}
                onChange={(e) => setSeconds(e.target.value)}
                disabled={isPending || !enabled}
              />
            </div>

            <div className="space-y-2">
              <label htmlFor="cooldown-max" className="text-sm font-medium">
                窗口内最大请求数 / 凭据
              </label>
              <Input
                id="cooldown-max"
                type="number"
                min="1"
                value={maxRequests}
                onChange={(e) => setMaxRequests(e.target.value)}
                disabled={isPending || !enabled}
              />
            </div>

            <p className="text-xs text-muted-foreground">
              在指定时间窗口内限制每个凭据的请求数，超出后将自动等待
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
