# VLESS → JSON Converter

A static, client-side GitHub Pages app for turning one `vless://` URL into an Xray JSON configuration.

## SNI/IP source

The proxy outbound list is read directly from `list.json` in the same GitHub repository. **The web page no longer uses a user-entered outbound count or manually entered SNI/IP values.**

Example `list.json`:

```json
[
  { "ip": "104.17.141.179", "sni": "aosabook.org" },
  { "ip": "172.67.242.89", "sni": "akamaized.net" },
  { "ip": "104.19.156.170", "sni": "brew.sh" },
  { "ip": "104.17.57.87", "sni": "fastly.com" },
  { "ip": "172.67.198.76", "sni": "paypal.com" },
  { "ip": "172.65.208.28", "sni": "pypi.org" },
  { "ip": "104.16.80.16", "sni": "python.org" },
  { "ip": "104.24.186.83", "sni": "speedtest.net" },
  { "ip": "104.19.144.45", "sni": "v16m-default.akamaized.net" }
]
```

Each item creates exactly one generated outbound:

- `fakeSni` = the item's `sni`
- `spoofIp` = the item's `ip`
- `targetPort` = `443`
- tag = `AutoOut_1`, `AutoOut_2`, ...

So if `list.json` contains 9 entries, the generated config contains 9 proxy outbounds (plus `direct` and `block`).

## GitHub Pages

Keep `index.html`, `style.css`, `script.js`, and `list.json` in the same directory of the repository. The browser fetches `./list.json` from the GitHub Pages origin with cache disabled for the request.

Everything runs locally in the browser; the VLESS URL is not uploaded to a backend.

## Important

The Generate action reloads `list.json` every time. The number of proxy outbounds is exactly the number of valid records in `list.json`; there is no HTML outbound-count input and no fallback to three outbounds.
