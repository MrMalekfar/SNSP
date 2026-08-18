# VLESS → JSON Converter

A static, client-side GitHub Pages app for turning one `vless://` URL into an Xray JSON configuration with multiple VLESS outbounds.

## Multiple outbounds

One VLESS URL can generate any number of proxy outbounds (1–50). The generated tags are:

- `AutoOut_1`
- `AutoOut_2`
- `AutoOut_3`
- and so on.

Each outbound can have its own `fakeSni`, `spoofIp`, and target port. The local proxy starting port is incremented for each generated outbound (`41105`, `41106`, `41107`, ... by default).

## Burst Observatory

The generated config includes `burstObservatory` with a configurable prefix selector. The default is `AutoOut_`, which matches all of the generated `AutoOut_*` tags under Xray's prefix-matching behavior.

The page uses the current Xray field name `httpMethod` in `pingConfig`. The example values are:

```json
"burstObservatory": {
  "subjectSelector": ["AutoOut_"],
  "pingConfig": {
    "destination": "http://edge.microsoft.com/captiveportal/generate_204",
    "connectivity": "",
    "interval": "20m",
    "sampling": 3,
    "timeout": "3s",
    "httpMethod": "HEAD"
  }
}
```

Xray documents `subjectSelector` as prefix matching and documents `httpMethod` for the burst ping configuration.

## GitHub Pages

Upload `index.html`, `style.css`, and `script.js` to the repository root, then enable GitHub Pages from **Settings → Pages → Deploy from a branch → main → / (root)**.

Everything runs locally in the browser; the VLESS URL is not uploaded to a backend.
