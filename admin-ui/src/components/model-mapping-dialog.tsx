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
import { Plus, Trash2 } from 'lucide-react'
import { useModelMappings, useSetModelMappings } from '@/hooks/use-credentials'
import { extractErrorMessage } from '@/lib/utils'
import type { ModelMappingItem } from '@/types/api'

interface ModelMappingDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function ModelMappingDialog({ open, onOpenChange }: ModelMappingDialogProps) {
  const { data, isLoading } = useModelMappings()
  const { mutate: save, isPending } = useSetModelMappings()

  const [mappings, setMappings] = useState<ModelMappingItem[]>([])
  const [freeMappings, setFreeMappings] = useState<ModelMappingItem[]>([])

  useEffect(() => {
    if (open && data) {
      setMappings(data.mappings.map(m => ({ ...m })))
      setFreeMappings((data.freeModelMappings || []).map(m => ({ ...m })))
    }
  }, [open, data])

  const handleAdd = () => {
    setMappings([...mappings, { from: '', to: '' }])
  }

  const handleRemove = (index: number) => {
    setMappings(mappings.filter((_, i) => i !== index))
  }

  const handleChange = (index: number, field: 'from' | 'to', value: string) => {
    const updated = [...mappings]
    updated[index] = { ...updated[index], [field]: value }
    setMappings(updated)
  }

  const handleAddFreeMapping = () => {
    setFreeMappings([...freeMappings, { from: '', to: '' }])
  }

  const handleRemoveFreeMapping = (index: number) => {
    setFreeMappings(freeMappings.filter((_, i) => i !== index))
  }

  const handleFreeMappingChange = (index: number, field: 'from' | 'to', value: string) => {
    const updated = [...freeMappings]
    updated[index] = { ...updated[index], [field]: value }
    setFreeMappings(updated)
  }

  const handleSave = () => {
    for (let i = 0; i < mappings.length; i++) {
      if (!mappings[i].from.trim() || !mappings[i].to.trim()) {
        toast.error(`第 ${i + 1} 行的模型 ID 不能为空`)
        return
      }
    }

    const validFreeMappings = freeMappings.filter(m => m.from.trim() || m.to.trim())
    for (let i = 0; i < validFreeMappings.length; i++) {
      if (!validFreeMappings[i].from.trim() || !validFreeMappings[i].to.trim()) {
        toast.error(`Free 映射第 ${i + 1} 行的模型 ID 不能为空`)
        return
      }
    }

    save({ mappings, freeModelMappings: validFreeMappings }, {
      onSuccess: () => {
        toast.success('模型映射已更新，下一次请求生效')
        onOpenChange(false)
      },
      onError: (error) => {
        toast.error(`保存失败: ${extractErrorMessage(error)}`)
      },
    })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl max-h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>模型映射</DialogTitle>
        </DialogHeader>

        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : (
          <div className="space-y-4 overflow-y-auto">
            {/* 模型映射 */}
            <div className="space-y-3">
              <div className="grid grid-cols-[1fr_1fr_auto] gap-2 text-xs text-muted-foreground px-1">
                <span>用户请求模型</span>
                <span>实际转发模型</span>
                <span className="w-8"></span>
              </div>
              <div className="max-h-48 overflow-y-auto space-y-2">
                {mappings.map((m, i) => (
                  <div key={i} className="grid grid-cols-[1fr_1fr_auto] gap-2 items-center">
                    <Input
                      value={m.from}
                      onChange={(e) => handleChange(i, 'from', e.target.value)}
                      placeholder="claude-opus-4-7"
                      disabled={isPending}
                    />
                    <Input
                      value={m.to}
                      onChange={(e) => handleChange(i, 'to', e.target.value)}
                      placeholder="claude-opus-4.6"
                      disabled={isPending}
                    />
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => handleRemove(i)}
                      disabled={isPending}
                      className="h-8 w-8"
                    >
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </div>
                ))}
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={handleAdd}
                disabled={isPending}
                className="w-full"
              >
                <Plus className="h-4 w-4 mr-1" />
                添加映射
              </Button>
            </div>

            {/* Free 模型映射 */}
            <div className="space-y-3 border-t pt-4">
              <div className="text-sm font-medium">Free 账号模型映射</div>
              <div className="grid grid-cols-[1fr_1fr_auto] gap-2 text-xs text-muted-foreground px-1">
                <span>用户请求模型</span>
                <span>实际转发模型</span>
                <span className="w-8"></span>
              </div>
              <div className="max-h-32 overflow-y-auto space-y-2">
                {freeMappings.map((m, i) => (
                  <div key={i} className="grid grid-cols-[1fr_1fr_auto] gap-2 items-center">
                    <Input
                      value={m.from}
                      onChange={(e) => handleFreeMappingChange(i, 'from', e.target.value)}
                      placeholder="claude-haiku-4-5"
                      disabled={isPending}
                    />
                    <Input
                      value={m.to}
                      onChange={(e) => handleFreeMappingChange(i, 'to', e.target.value)}
                      placeholder="claude-haiku-4.5"
                      disabled={isPending}
                    />
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => handleRemoveFreeMapping(i)}
                      disabled={isPending}
                      className="h-8 w-8"
                    >
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </div>
                ))}
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={handleAddFreeMapping}
                disabled={isPending}
                className="w-full"
              >
                <Plus className="h-4 w-4 mr-1" />
                添加 Free 映射
              </Button>
              <p className="text-xs text-muted-foreground">
                Free 账号只能处理左侧匹配的模型请求，转发为右侧模型。不在此列表中的模型不会分配到 Free 凭据。
              </p>
            </div>
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
