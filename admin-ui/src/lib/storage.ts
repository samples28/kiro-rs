const API_KEY_STORAGE_KEY = 'adminApiKey'
const PROXY_STORAGE_KEY = 'lastProxySettings'

interface ProxySettings {
  proxyUrl: string
  proxyUsername: string
  proxyPassword: string
}

export const storage = {
  getApiKey: () => localStorage.getItem(API_KEY_STORAGE_KEY),
  setApiKey: (key: string) => localStorage.setItem(API_KEY_STORAGE_KEY, key),
  removeApiKey: () => localStorage.removeItem(API_KEY_STORAGE_KEY),

  getProxySettings: (): ProxySettings | null => {
    const raw = localStorage.getItem(PROXY_STORAGE_KEY)
    if (!raw) return null
    try { return JSON.parse(raw) } catch { return null }
  },
  setProxySettings: (settings: ProxySettings) =>
    localStorage.setItem(PROXY_STORAGE_KEY, JSON.stringify(settings)),
}
