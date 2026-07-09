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
import { getModelPrices, setModelPrices } from '@/api/credentials'
import { extractErrorMessage } from '@/lib/utils'

interface ModelPricesDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

interface ModelPrice {
  input: number
  output: number
  cache_read: number
  cache_write: number
}

type ModelPrices = Record<string, ModelPrice>

const MODEL_LIST = [
  'claude-opus-4-8',
  'claude-opus-4-7',
  'claude-opus-4-6',
  'claude-sonnet-4-6',
  'claude-sonnet-4-5',
  'claude-haiku-4-5',
]

const DEFAULT_PRICES: ModelPrices = {
  'claude-opus-4-8': { input: 5, output: 25, cache_read: 0.5, cache_write: 6.25 },
  'claude-opus-4-7': { input: 5, output: 25, cache_read: 0.5, cache_write: 6.25 },
  'claude-opus-4-6': { input: 5, output: 25, cache_read: 0.5, cache_write: 6.25 },
  'claude-sonnet-4-6': { input: 3, output: 15, cache_read: 0.3, cache_write: 3.75 },
  'claude-sonnet-4-5': { input: 3, output: 15, cache_read: 0.3, cache_write: 3.75 },
  'claude-haiku-4-5': { input: 1, output: 5, cache_read: 0.1, cache_write: 1.25 },
}

export function ModelPricesDialog({ open, onOpenChange }: ModelPricesDialogProps) {
  const [prices, setPrices] = useState<ModelPrices>(DEFAULT_PRICES)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (open) {
      setLoading(true)
      getModelPrices()
        .then((res) => {
          if (res.prices && Object.keys(res.prices).length > 0) {
            setPrices({ ...DEFAULT_PRICES, ...res.prices })
          } else {
            setPrices(DEFAULT_PRICES)
          }
        })
        .catch(() => {
          setPrices(DEFAULT_PRICES)
        })
        .finally(() => setLoading(false))
    }
  }, [open])

  const handleChange = (model: string, field: keyof ModelPrice, value: string) => {
    setPrices((prev) => ({
      ...prev,
      [model]: {
        ...prev[model],
        [field]: value === '' ? 0 : parseFloat(value) || 0,
      },
    }))
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      await setModelPrices({ prices })
      toast.success('模型价格配置已保存')
      onOpenChange(false)
    } catch (err) {
      toast.error(`保存失败: ${extractErrorMessage(err)}`)
    } finally {
      setSaving(false)
    }
  }

  const getShortName = (model: string) => {
    return model.replace('claude-', '')
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>模型价格设置 ($/1M tokens)</DialogTitle>
        </DialogHeader>

        {loading ? (
          <div className="flex items-center justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : (
          <div className="space-y-3">
            {/* Header */}
            <div className="grid grid-cols-5 gap-2 text-xs font-medium text-muted-foreground px-1">
              <div>模型</div>
              <div>Input</div>
              <div>Output</div>
              <div>Cache Read</div>
              <div>Cache Write</div>
            </div>

            {MODEL_LIST.map((model) => (
              <div key={model} className="grid grid-cols-5 gap-2 items-center">
                <span className="text-xs font-mono truncate" title={model}>
                  {getShortName(model)}
                </span>
                <Input
                  type="number"
                  step="0.01"
                  min="0"
                  className="h-8 text-xs"
                  value={prices[model]?.input ?? 0}
                  onChange={(e) => handleChange(model, 'input', e.target.value)}
                  disabled={saving}
                />
                <Input
                  type="number"
                  step="0.01"
                  min="0"
                  className="h-8 text-xs"
                  value={prices[model]?.output ?? 0}
                  onChange={(e) => handleChange(model, 'output', e.target.value)}
                  disabled={saving}
                />
                <Input
                  type="number"
                  step="0.01"
                  min="0"
                  className="h-8 text-xs"
                  value={prices[model]?.cache_read ?? 0}
                  onChange={(e) => handleChange(model, 'cache_read', e.target.value)}
                  disabled={saving}
                />
                <Input
                  type="number"
                  step="0.01"
                  min="0"
                  className="h-8 text-xs"
                  value={prices[model]?.cache_write ?? 0}
                  onChange={(e) => handleChange(model, 'cache_write', e.target.value)}
                  disabled={saving}
                />
              </div>
            ))}

            <p className="text-xs text-muted-foreground pt-1">
              价格用于计算各凭据的使用费用，单位为美元/百万 tokens
            </p>
          </div>
        )}

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={saving}
          >
            取消
          </Button>
          <Button type="button" onClick={handleSave} disabled={saving || loading}>
            {saving ? '保存中...' : '保存'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
