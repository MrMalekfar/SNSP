# VLESS JSON Converter — GitHub list-driven

این نسخه Outboundها را فقط از `list.json` می‌سازد. هر رکورد `{ "ip", "sni" }` دقیقاً یک `AutoOut_N` ایجاد می‌کند.

## Routing

خروجی با `routing.domainStrategy = "AsIs"` تولید می‌شود و شامل:

- DNSهای مشخص‌شده برای Balancer/Direct
- مسدودسازی UDP/443
- مسدودسازی `geosite:category-ads-all`
- مسدودسازی IPهای مشخص‌شده
- Direct برای `geoip:private` و `geosite:private`
- Direct برای `geoip:ir` و دامنه‌های `.ir` / `geosite:category-ir`
- Direct برای `workers.dev` فقط در مسیر `/QR/...`
- Direct برای BitTorrent
- Rule نهایی برای ارسال باقی‌ماندهٔ ترافیک به Balancer `all`

Balancer:

```json
{
  "tag": "all",
  "selector": ["AutoOut_"],
  "strategy": { "type": "leastLoad" },
  "fallbackTag": "AutoOut_1"
}
```

### Important

`list.json` باید یک آرایهٔ JSON معتبر باشد:

```json
[
  { "ip": "104.17.141.179", "sni": "aosabook.org" },
  { "ip": "172.67.242.89", "sni": "akamaized.net" }
]
```

برای GitHub Pages، `list.json` باید در کنار `index.html` و `script.js` قرار داشته باشد.
