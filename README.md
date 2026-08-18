# VLESS → JSON Converter

A static, client-side converter for GitHub Pages.

## What it does

Paste a `vless://` link and click **Generate JSON**.

The app:

- parses the VLESS UUID, server, port, transport, TLS/SNI, WebSocket host/path, ALPN, fingerprint, encryption, `allowInsecure`, flow, and URL fragment/remark;
- inserts those values into the JSON structure shown in the requested template;
- keeps the DNS, SOCKS inbound, policy, routing, direct/block outbounds, and other fixed template sections;
- exposes the template-specific `proxyAddress`, `proxyPort`, `fakeSni`, `spoofIp`, `targetPort`, and log level as editable options;
- runs completely in the browser. No API or backend is required.

## GitHub Pages

1. Create a GitHub repository.
2. Upload `index.html`, `style.css`, and `script.js` to the repository root.
3. Open **Settings → Pages**.
4. Under **Build and deployment**, choose **Deploy from a branch**.
5. Select the branch containing these files (usually `main`) and the `/ (root)` folder.
6. Save. GitHub will publish the static site.

## Important implementation note

The example target JSON contains values that are not present in the VLESS URL itself, such as the local VLESS endpoint `127.0.0.1:41105` and the `sniSpoof` values. Those are therefore treated as template values in the UI rather than guessed from the VLESS link.

For security/privacy, the page does not send the VLESS URL anywhere. It is processed locally by JavaScript.
