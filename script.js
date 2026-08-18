const sampleVless =
  "vless://d8c2de37-2ca6-4a64-a2bf-205999996350@188.114.98.224:443?path=%2FUrn8f6B57GWK_g_1%3Fed%3D2560&security=tls&alpn=h3&encryption=none&insecure=0&host=TEST1.talaEibala.WORKERs.dEV&fp=chrome&type=ws&allowInsecure=0&sni=TEST1.talaEibala.WORKERs.dEV#1%20-%F0%9F%8F%85TEST1";

function $(id) {
  return document.getElementById(id);
}

const els = {
  input: $("vlessInput"),
  generate: $("generateBtn"),
  sample: $("sampleBtn"),
  copy: $("copyBtn"),
  download: $("downloadBtn"),
  output: $("output"),
  status: $("status"),
  fields: $("fields"),
  proxyAddress: $("proxyAddress"),
  proxyPort: $("proxyPort"),
  logLevel: $("logLevel"),
  outboundRows: $("outboundRows"),
  observatorySelector: $("observatorySelector"),
  observatoryDestination: $("observatoryDestination"),
  observatoryConnectivity: $("observatoryConnectivity"),
  observatoryInterval: $("observatoryInterval"),
  observatorySampling: $("observatorySampling"),
  observatoryTimeout: $("observatoryTimeout"),
  observatoryHttpMethod: $("observatoryHttpMethod")
};

function valueOf(el, fallback = "") {
  return el && typeof el.value === "string" ? el.value : fallback;
}

function numberValueOf(el, fallback = 0) {
  const value = Number(valueOf(el, fallback));
  return Number.isFinite(value) ? value : fallback;
}

let lastConfig = null;

let sniList = [];

async function loadSniList() {
  const url = `./list.json?v=${Date.now()}`;
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`Unable to load list.json (HTTP ${res.status}).`);

  const data = await res.json();
  if (!Array.isArray(data)) {
    throw new Error("list.json must contain a JSON array of { ip, sni } objects.");
  }

  const cleaned = data.map((item, index) => ({
    ip: String(item?.ip ?? "").trim(),
    sni: String(item?.sni ?? "").trim()
  }));

  const invalid = cleaned.findIndex((item) => !item.ip || !item.sni);
  if (invalid >= 0) {
    throw new Error(`list.json item ${invalid + 1} must contain both "ip" and "sni".`);
  }

  if (!cleaned.length) throw new Error("list.json is empty; no proxy outbounds can be generated.");
  sniList = cleaned;
  return sniList;
}


const staticDnsHosts = {
  "domain:googleapis.cn": "googleapis.com",
  "dns.alidns.com": ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
  "one.one.one.one": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
  "dns.cloudflare.com": ["104.16.132.229", "104.16.133.229", "2606:4700::6810:84e5", "2606:4700::6810:85e5"],
  "cloudflare-dns.com": ["104.16.248.249", "104.16.249.249", "2606:4700::6810:f8f9", "2606:4700::6810:f9f9"],
  "dot.pub": ["1.12.12.12", "120.53.53.53"],
  "dns.google": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
  "dns.quad9.net": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
  "common.dot.dns.yandex.net": ["77.88.8.8", "77.88.8.1", "2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff"]
};

function setStatus(message, kind = "") {
  if (!els.status) return;
  els.status.textContent = message;
  els.status.className = `status ${kind}`.trim();
}

function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[char]));
}

function parseVless(raw) {
  const value = raw.trim();
  if (!value) throw new Error("Paste a VLESS URL first.");
  if (!value.toLowerCase().startsWith("vless://")) {
    throw new Error("The input must start with vless://");
  }

  const hashIndex = value.indexOf("#");
  const withoutFragment = hashIndex >= 0 ? value.slice(0, hashIndex) : value;
  const fragment = hashIndex >= 0 ? value.slice(hashIndex + 1) : "";

  const atIndex = withoutFragment.indexOf("@", 8);
  if (atIndex < 0) throw new Error("Invalid VLESS URL: missing @ separator.");

  const userPart = withoutFragment.slice(8, atIndex);
  const serverPart = withoutFragment.slice(atIndex + 1);
  const queryIndex = serverPart.indexOf("?");
  const serverNoQuery = queryIndex >= 0 ? serverPart.slice(0, queryIndex) : serverPart;
  const queryPart = queryIndex >= 0 ? serverPart.slice(queryIndex + 1) : "";

  let address = serverNoQuery;
  let portText = "";
  if (serverNoQuery.startsWith("[")) {
    const close = serverNoQuery.indexOf("]");
    if (close < 0) throw new Error("Invalid IPv6 server address.");
    address = serverNoQuery.slice(1, close);
    if (serverNoQuery.slice(close + 1, close + 2) === ":") {
      portText = serverNoQuery.slice(close + 2);
    }
  } else {
    const colon = serverNoQuery.lastIndexOf(":");
    if (colon >= 0 && serverNoQuery.indexOf(":") === colon) {
      address = serverNoQuery.slice(0, colon);
      portText = serverNoQuery.slice(colon + 1);
    }
  }

  const port = Number(portText || 443);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Invalid VLESS server port.");
  }

  const params = new URLSearchParams(queryPart);
  const uuid = decodeURIComponent(userPart).trim();
  const transport = params.get("type") || "tcp";
  const security = params.get("security") || "none";
  const sni = params.get("sni") || params.get("host") || address;
  const wsHost = params.get("host") || sni;
  const wsPath = params.get("path") || "/";
  const alpn = (params.get("alpn") || "").split(",").map((x) => x.trim()).filter(Boolean);
  const fingerprint = params.get("fp") || "";
  const encryption = params.get("encryption") || "none";
  const insecureRaw = params.get("allowInsecure") ?? params.get("insecure") ?? "0";
  const allowInsecure = ["1", "true", "yes"].includes(String(insecureRaw).toLowerCase());
  const flow = params.get("flow") || "";
  const remark = decodeURIComponent(fragment.replace(/\+/g, " "));

  if (!uuid) throw new Error("Missing VLESS UUID.");

  return {
    uuid,
    address,
    port,
    transport,
    security,
    sni,
    wsHost,
    wsPath,
    alpn,
    fingerprint,
    encryption,
    allowInsecure,
    flow,
    remark
  };
}

function setDetectedFields(parsed) {
  const mapping = [
    ["UUID", parsed.uuid],
    ["Address", parsed.address],
    ["Port", parsed.port],
    ["Transport", parsed.transport],
    ["Security", parsed.security],
    ["SNI", parsed.sni],
    ["WS Host", parsed.wsHost],
    ["WS Path", parsed.wsPath],
    ["Remark", parsed.remark || "—"]
  ];

  if (!els.fields) return;
  els.fields.innerHTML = mapping.map(([name, value]) =>
    `<div><dt>${escapeHtml(name)}</dt><dd>${escapeHtml(value)}</dd></div>`
  ).join("");
}

function renderOutboundRows() {
  if (!els.outboundRows) return;
  els.outboundRows.innerHTML = "";

  sniList.forEach((item, index) => {
    const row = document.createElement("div");
    row.className = "outbound-row list-driven-row";
    row.innerHTML = `
      <div class="tag-cell">AutoOut_${index + 1}</div>
      <div><span class="field-label">Fake SNI</span><code>${escapeHtml(item.sni)}</code></div>
      <div><span class="field-label">Spoof IP</span><code>${escapeHtml(item.ip)}</code></div>
      <div><span class="field-label">Target port</span><code>443</code></div>
    `;
    els.outboundRows.appendChild(row);
  });

}

function getListDrivenOverrides() {
  if (!sniList.length) throw new Error("list.json is empty; load it before generating JSON.");
  return sniList.map((item, index) => ({
    tag: `AutoOut_${index + 1}`,
    fakeSni: item.sni,
    spoofIp: item.ip,
    targetPort: 443
  }));
}


function buildOutbound(parsed, override, index) {
  const proxyPort = numberValueOf(els.proxyPort, 41105) + index;

  return {
    mux: {
      concurrency: -1,
      enabled: false
    },
    protocol: "vless",
    settings: {
      vnext: [
        {
          address: valueOf(els.proxyAddress, "127.0.0.1").trim(),
          port: proxyPort,
          users: [
            {
              encryption: parsed.encryption || "none",
              flow: parsed.flow || "",
              id: parsed.uuid,
              level: 8
            }
          ]
        }
      ]
    },
    sniSpoof: {
      active: true,
      fakeSni: override.fakeSni,
      spoofIp: override.spoofIp,
      targetPort: override.targetPort
    },
    streamSettings: {
      network: parsed.transport,
      security: parsed.security,
      tlsSettings: {
        allowInsecure: parsed.allowInsecure,
        ...(parsed.alpn.length ? { alpn: parsed.alpn } : {}),
        ...(parsed.fingerprint ? { fingerprint: parsed.fingerprint } : {}),
        serverName: parsed.sni,
        show: false
      },
      ...(parsed.transport === "ws" ? {
        wsSettings: {
          headers: { Host: parsed.wsHost },
          path: parsed.wsPath
        }
      } : {})
    },
    tag: override.tag
  };
}

function buildConfig(parsed, listEntries) {
  const proxyAddress = valueOf(els.proxyAddress, "127.0.0.1").trim();
  const proxyStartPort = numberValueOf(els.proxyPort, 41105);
  const targetCount = listEntries.length;
  const selector = valueOf(els.observatorySelector, "AutoOut_").trim();
  const sampling = numberValueOf(els.observatorySampling, 3);

  if (!proxyAddress) throw new Error("Local proxy address cannot be empty.");
  if (!Number.isInteger(proxyStartPort) || proxyStartPort < 1 || proxyStartPort + targetCount - 1 > 65535) {
    throw new Error("The starting local proxy port range is invalid.");
  }
  if (!selector) throw new Error("Burst Observatory subject selector cannot be empty.");
  if (!Number.isInteger(sampling) || sampling < 1) throw new Error("Sampling must be at least 1.");
  if (!valueOf(els.observatoryDestination, "http://edge.microsoft.com/captiveportal/generate_204").trim()) throw new Error("Burst Observatory destination cannot be empty.");
  if (!valueOf(els.observatoryInterval, "20m").trim()) throw new Error("Burst Observatory interval cannot be empty.");
  if (!valueOf(els.observatoryTimeout, "3s").trim()) throw new Error("Burst Observatory timeout cannot be empty.");

  return {
    dns: {
      hosts: staticDnsHosts,
      servers: [
        "1.1.1.1",
        {
          address: "223.5.5.5",
          domains: [],
          skipFallback: true,
          tag: "domestic-dns0"
        }
      ],
      tag: "dns-module"
    },
    inbounds: [
      {
        listen: "127.0.0.1",
        port: 10808,
        protocol: "socks",
        settings: {
          auth: "noauth",
          udp: true,
          userLevel: 8
        },
        sniffing: {
          destOverride: ["http", "tls"],
          enabled: true,
          routeOnly: false
        },
        tag: "socks"
      }
    ],
    log: {
      loglevel: valueOf(els.logLevel, "warning")
    },
    burstObservatory: {
      subjectSelector: [selector],
      pingConfig: {
        destination: valueOf(els.observatoryDestination, "http://edge.microsoft.com/captiveportal/generate_204").trim(),
        connectivity: valueOf(els.observatoryConnectivity).trim(),
        interval: valueOf(els.observatoryInterval, "20m").trim(),
        sampling,
        timeout: valueOf(els.observatoryTimeout, "3s").trim(),
        httpMethod: valueOf(els.observatoryHttpMethod, "HEAD")
      }
    },
    outbounds: [
      ...listEntries.map((entry, index) => buildOutbound(parsed, entry, index)),
      {
        protocol: "freedom",
        settings: {
          domainStrategy: "UseIP"
        },
        tag: "direct"
      },
      {
        protocol: "blackhole",
        settings: {
          response: {
            type: "http"
          }
        },
        tag: "block"
      }
    ],
    policy: {
      levels: {
        "8": {
          connIdle: 300,
          downlinkOnly: 1,
          handshake: 4,
          uplinkOnly: 1
        }
      },
      system: {
        statsOutboundUplink: true,
        statsOutboundDownlink: true
      }
    },
    remarks: parsed.remark,
    routing: {
      // Keep routing domain handling exactly as requested: do not resolve domains
      // to IPs just to perform a second routing pass.
      domainStrategy: "IPIfNonMatch",
      rules: [
        {
          ip: [
            "8.8.8.8",
            "8.8.4.4",
            "2001:4860:4860::8888"
          ],
          balancerTag: "all",
          port: "53",
          type: "field",
          "enabled": true
        },
        {
          ip: [
            "2620:119:35::35"
          ],
          outboundTag: "direct",
          port: "53",
          type: "field",
          "enabled": true
        },
        {
          outboundTag: "block",
          port: "443",
          network: "udp",
          type: "field",
          "enabled": true
        },
        {
          outboundTag: "block",
          domain: [
            "geosite:category-ads-all"
          ],
          type: "field",
          "enabled": true
        },
        {
          outboundTag: "block",
          ip: [
            "10.10.34.0/24",
            "2001:4188:2:600:10:10:34:36",
            "2001:4188:2:600:10:10:34:35",
            "2001:4188:2:600:10:10:34:34"
          ],
          type: "field",
          "enabled": true
        },
        {
          outboundTag: "direct",
          ip: [
            "geoip:private"
          ],
          type: "field",
          "enabled": true
        },
        {
          outboundTag: "direct",
          domain: [
            "geosite:private"
          ],
          type: "field",
          "enabled": true
        },
        {
          outboundTag: "direct",
          ip: [
            "geoip:ir"
          ],
          type: "field",
          "enabled": true
        },
        {
          outboundTag: "direct",
          domain: [
            "domain:.ir",
            "geosite:category-ir"
          ],
          type: "field",
          "enabled": true
        },
        {
          outboundTag: "direct",
          domain: [
            "domain:workers.dev"
          ],
        "path": [
          "regexp:^/QR/.*"
          ],
          type: "field"
        },
        {
          outboundTag: "direct",
          protocol: [
            "bittorrent"
          ],
          type: "field",
          "enabled": true
        },
        {
          balancerTag: "all",
          port: "0-65535"
        }
      ],
      balancers: [
        {
          tag: "all",
          selector: [
            "AutoOut_"
          ],
          strategy: {
            type: "leastLoad"
          },
          fallbackTag: "AutoOut_1"
        }
      ]
    },
    stats: {}
  };
}

async function generate() {
  try {
    // Always reload the repository list before generating so stale in-memory data cannot be used.
    await loadSniList();
    renderOutboundRows();
    const parsed = parseVless(valueOf(els.input));
    const entries = getListDrivenOverrides();
    const config = buildConfig(parsed, entries);
    lastConfig = config;
    setDetectedFields(parsed);
    if (els.output) els.output.innerHTML = `<code>${escapeHtml(JSON.stringify(config, null, 2))}</code>`;
    console.info("Generated list-driven proxy outbounds:", entries);
    setStatus(`Generated ${entries.length} proxy outbounds directly from list.json: ${entries.map((x) => `${x.tag} (${x.fakeSni} → ${x.spoofIp})`).join(", ")}.`, "success");
  } catch (error) {
    lastConfig = null;
    setStatus(error instanceof Error ? error.message : "Invalid input.", "error");
  }
}

async function copyJson() {
  if (!lastConfig) {
    setStatus("Generate JSON first.", "error");
    return;
  }
  try {
    await navigator.clipboard.writeText(JSON.stringify(lastConfig, null, 2));
    setStatus("Copied JSON to clipboard.", "success");
  } catch {
    setStatus("Clipboard access was blocked by the browser.", "error");
  }
}

function downloadJson() {
  if (!lastConfig) {
    setStatus("Generate JSON first.", "error");
    return;
  }
  const blob = new Blob([JSON.stringify(lastConfig, null, 2)], {
    type: "application/json;charset=utf-8"
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "xray-multi-vless-config.json";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  setStatus("JSON file downloaded.", "success");
}

if (els.generate) els.generate.addEventListener("click", () => { void generate(); });
if (els.copy) els.copy.addEventListener("click", copyJson);
if (els.download) els.download.addEventListener("click", downloadJson);
if (els.sample) els.sample.addEventListener("click", async () => {
  if (els.input) els.input.value = sampleVless;
  try {
    await loadSniList();
    renderOutboundRows();
    await generate();
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "Unable to load list.json.", "error");
  }
});
if (els.input) els.input.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") void generate();
});

(async () => {
  try {
    await loadSniList();
    renderOutboundRows();
    setStatus(`Loaded ${sniList.length} SNI/IP pairs from list.json.`, "success");
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "Unable to load list.json.", "error");
  }
})();
