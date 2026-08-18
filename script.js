const sampleVless =
  "vless://d8c2de37-2ca6-4a64-a2bf-205999996350@188.114.98.224:443?path=%2FUrn8f6B57GWK_g_1%3Fed%3D2560&security=tls&alpn=h3&encryption=none&insecure=0&host=TEST1.talaEibala.WORKERs.dEV&fp=chrome&type=ws&allowInsecure=0&sni=TEST1.talaEibala.WORKERs.dEV#1%20-%F0%9F%8F%85TEST1";

const els = {
  input: document.getElementById("vlessInput"),
  generate: document.getElementById("generateBtn"),
  sample: document.getElementById("sampleBtn"),
  copy: document.getElementById("copyBtn"),
  download: document.getElementById("downloadBtn"),
  output: document.getElementById("output"),
  status: document.getElementById("status"),
  fields: document.getElementById("fields"),
  proxyAddress: document.getElementById("proxyAddress"),
  proxyPort: document.getElementById("proxyPort"),
  outboundCount: document.getElementById("outboundCount"),
  targetPort: document.getElementById("targetPort"),
  logLevel: document.getElementById("logLevel"),
  applyCount: document.getElementById("applyCountBtn"),
  outboundRows: document.getElementById("outboundRows"),
  observatorySelector: document.getElementById("observatorySelector"),
  observatoryDestination: document.getElementById("observatoryDestination"),
  observatoryConnectivity: document.getElementById("observatoryConnectivity"),
  observatoryInterval: document.getElementById("observatoryInterval"),
  observatorySampling: document.getElementById("observatorySampling"),
  observatoryTimeout: document.getElementById("observatoryTimeout"),
  observatoryHttpMethod: document.getElementById("observatoryHttpMethod")
};

let lastConfig = null;

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

  els.fields.innerHTML = mapping.map(([name, value]) =>
    `<div><dt>${escapeHtml(name)}</dt><dd>${escapeHtml(value)}</dd></div>`
  ).join("");
}

function renderOutboundRows(count) {
  const safeCount = Math.min(50, Math.max(1, Number(count) || 1));
  els.outboundCount.value = safeCount;
  els.outboundRows.innerHTML = "";

  for (let i = 1; i <= safeCount; i += 1) {
    const row = document.createElement("div");
    row.className = "outbound-row";
    row.innerHTML = `
      <div class="tag-cell">AutoOut_${i}</div>
      <label>Fake SNI<input data-field="fakeSni" value="hcaptcha.com" /></label>
      <label>Spoof IP<input data-field="spoofIp" value="104.19.229.21" /></label>
      <label>Target port<input data-field="targetPort" type="number" min="1" max="65535" value="443" /></label>
    `;
    els.outboundRows.appendChild(row);
  }
}

function readOutboundRows() {
  const rows = [...els.outboundRows.querySelectorAll(".outbound-row")];
  return rows.map((row, index) => {
    const fakeSni = row.querySelector('[data-field="fakeSni"]').value.trim();
    const spoofIp = row.querySelector('[data-field="spoofIp"]').value.trim();
    const targetPort = Number(row.querySelector('[data-field="targetPort"]').value);

    if (!fakeSni) throw new Error(`AutoOut_${index + 1}: Fake SNI cannot be empty.`);
    if (!spoofIp) throw new Error(`AutoOut_${index + 1}: Spoof IP cannot be empty.`);
    if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
      throw new Error(`AutoOut_${index + 1}: target port must be between 1 and 65535.`);
    }

    return {
      tag: `AutoOut_${index + 1}`,
      fakeSni,
      spoofIp,
      targetPort
    };
  });
}

function buildOutbound(parsed, override, index) {
  const proxyPort = Number(els.proxyPort.value) + index;

  return {
    mux: {
      concurrency: -1,
      enabled: false
    },
    protocol: "vless",
    settings: {
      vnext: [
        {
          address: els.proxyAddress.value.trim(),
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

function buildConfig(parsed, overrides) {
  const proxyAddress = els.proxyAddress.value.trim();
  const proxyStartPort = Number(els.proxyPort.value);
  const targetCount = overrides.length;
  const selector = els.observatorySelector.value.trim();
  const sampling = Number(els.observatorySampling.value);

  if (!proxyAddress) throw new Error("Local proxy address cannot be empty.");
  if (!Number.isInteger(proxyStartPort) || proxyStartPort < 1 || proxyStartPort + targetCount - 1 > 65535) {
    throw new Error("The starting local proxy port range is invalid.");
  }
  if (!selector) throw new Error("Burst Observatory subject selector cannot be empty.");
  if (!Number.isInteger(sampling) || sampling < 1) throw new Error("Sampling must be at least 1.");
  if (!els.observatoryDestination.value.trim()) throw new Error("Burst Observatory destination cannot be empty.");
  if (!els.observatoryInterval.value.trim()) throw new Error("Burst Observatory interval cannot be empty.");
  if (!els.observatoryTimeout.value.trim()) throw new Error("Burst Observatory timeout cannot be empty.");

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
      loglevel: els.logLevel.value
    },
    burstObservatory: {
      subjectSelector: [selector],
      pingConfig: {
        destination: els.observatoryDestination.value.trim(),
        connectivity: els.observatoryConnectivity.value.trim(),
        interval: els.observatoryInterval.value.trim(),
        sampling,
        timeout: els.observatoryTimeout.value.trim(),
        httpMethod: els.observatoryHttpMethod.value
      }
    },
    outbounds: [
      ...overrides.map((override, index) => buildOutbound(parsed, override, index)),
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
      domainStrategy: "AsIs",
      rules: [
        {
          ip: ["8.8.8.8"],
          outboundTag: "direct",
          port: "53",
          type: "field"
        },
        {
          ip: ["1.1.1.1"],
          outboundTag: "AutoOut_1",
          port: "53",
          type: "field"
        },
        {
          ip: ["223.5.5.5"],
          outboundTag: "direct",
          port: "53",
          type: "field"
        }
      ]
    },
    stats: {}
  };
}

function generate() {
  try {
    const parsed = parseVless(els.input.value);
    const overrides = readOutboundRows();
    const config = buildConfig(parsed, overrides);
    lastConfig = config;
    setDetectedFields(parsed);
    els.output.innerHTML = `<code>${escapeHtml(JSON.stringify(config, null, 2))}</code>`;
    setStatus(`Generated ${overrides.length} proxy outbounds: ${overrides.map((x) => x.tag).join(", ")}.`, "success");
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

els.generate.addEventListener("click", generate);
els.applyCount.addEventListener("click", () => renderOutboundRows(els.outboundCount.value));
els.copy.addEventListener("click", copyJson);
els.download.addEventListener("click", downloadJson);
els.sample.addEventListener("click", () => {
  els.input.value = sampleVless;
  renderOutboundRows(els.outboundCount.value);
  generate();
});
els.outboundCount.addEventListener("change", () => renderOutboundRows(els.outboundCount.value));
els.input.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") generate();
});

renderOutboundRows(els.outboundCount.value);
