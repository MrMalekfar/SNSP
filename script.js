const MAX_V2BOX_CONFIGS = 10;
const ADVANCED_OUTBOUND_COUNT = 20;
const ADVANCED_ADDRESS_SOURCE = 'https://raw.githubusercontent.com/MrMalekfar/Lists/main/merged_lists.json';
let sourceListCount = 0;

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
  advancedOutput: $("advancedOutput"),
  advancedCopy: $("advancedCopy"),
  v2boxConfigs: $("v2boxConfigs"),
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
let lastAdvancedConfig = null;
let lastV2boxConfigs = [];

const ADVANCED_FINGERPRINT = "unsafe";
const ADVANCED_CIPHER_SUITES =
  "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:" +
  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:" +
  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:" +
  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:" +
  "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:" +
  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";

const ADVANCED_FINALMASK = {
  tcp: [
    {
      type: "fragment",
      settings: {
        packets: "tlshello",
        lengths: ["5", "94", "1"],
        delays: ["0"],
        maxSplit: "0"
      }
    },
    {
      type: "fragment",
      settings: {
        packets: "1-1",
        lengths: ["109", "1"],
        delays: ["1"],
        maxSplit: "355"
      }
    }
  ]
};

let sniList = [];

async function loadAdvancedAddresses() {
  const res = await fetch(`${ADVANCED_ADDRESS_SOURCE}?v=${Date.now()}`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Could not load the Advanced address list from GitHub (HTTP ${res.status}).`);
  }

  const data = await res.json();
  const addresses = Array.isArray(data?.merged)
    ? data.merged
        .map((value) => String(value ?? "").trim())
        .filter(isValidIpAddress)
    : [];

  if (addresses.length < ADVANCED_OUTBOUND_COUNT) {
    throw new Error(`The GitHub "merged" list must contain at least ${ADVANCED_OUTBOUND_COUNT} addresses.`);
  }

  return shuffle(addresses).slice(0, ADVANCED_OUTBOUND_COUNT);
}

function isValidIpAddress(value) {
  const ipv4Parts = value.split(".");
  if (ipv4Parts.length === 4 && ipv4Parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)) {
    return true;
  }

  if (!value.includes(":") || !/^[0-9A-Fa-f:]+$/.test(value)) {
    return false;
  }

  const groups = value.split(":");
  const hasCompression = value.includes("::");
  const nonEmptyGroups = groups.filter(Boolean);

  return nonEmptyGroups.length <= 8 &&
    nonEmptyGroups.every((group) => /^[0-9A-Fa-f]{1,4}$/.test(group)) &&
    (hasCompression ? groups.length <= 9 : groups.length === 8);
}

function shuffle(values) {
  const copy = [...values];
  for (let index = copy.length - 1; index > 0; index -= 1) {
    const randomIndex = Math.floor(Math.random() * (index + 1));
    [copy[index], copy[randomIndex]] = [copy[randomIndex], copy[index]];
  }
  return copy;
}

async function loadSniList() {
  const url = `./list.json?v=${Date.now()}`;
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`Could not load list.json (HTTP ${res.status}).`);

  const data = await res.json();
  if (!Array.isArray(data)) {
    throw new Error("list.json must contain a JSON array of objects with both ip and sni fields.");
  }

  const cleaned = data.map((item, index) => ({
    ip: String(item?.ip ?? "").trim(),
    sni: String(item?.sni ?? "").trim()
  }));

  const invalid = cleaned.findIndex((item) => !item.ip || !item.sni);
  if (invalid >= 0) {
    throw new Error(`list.json entry ${invalid + 1} must contain both "ip" and "sni".`);
  }

  if (!cleaned.length) throw new Error("list.json is empty. Add at least one outbound source before generating configurations.");
  sourceListCount = cleaned.length;
  sniList = cleaned.slice(0, MAX_V2BOX_CONFIGS);
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
  if (!value) throw new Error("Paste a VLESS link to continue.");
  if (!value.toLowerCase().startsWith("vless://")) {
    throw new Error("The input must start with vless://.");
  }

  const hashIndex = value.indexOf("#");
  const withoutFragment = hashIndex >= 0 ? value.slice(0, hashIndex) : value;
  const fragment = hashIndex >= 0 ? value.slice(hashIndex + 1) : "";

  const atIndex = withoutFragment.indexOf("@", 8);
  if (atIndex < 0) throw new Error("Invalid VLESS link: the server separator (@) is missing.");

  const userPart = withoutFragment.slice(8, atIndex);
  const serverPart = withoutFragment.slice(atIndex + 1);
  const queryIndex = serverPart.indexOf("?");
  const serverNoQuery = queryIndex >= 0 ? serverPart.slice(0, queryIndex) : serverPart;
  const queryPart = queryIndex >= 0 ? serverPart.slice(queryIndex + 1) : "";

  let address = serverNoQuery;
  let portText = "";
  if (serverNoQuery.startsWith("[")) {
    const close = serverNoQuery.indexOf("]");
    if (close < 0) throw new Error("Invalid VLESS link: the IPv6 server address is not valid.");
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
    throw new Error("Invalid VLESS link: the server port is not valid.");
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

  if (!uuid) throw new Error("Invalid VLESS link: the UUID is missing.");

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
  const mapping = {
    uuid: parsed.uuid,
    address: parsed.address,
    port: parsed.port,
    transport: parsed.transport,
    security: parsed.security,
    sni: parsed.sni,
    wsHost: parsed.wsHost,
    wsPath: parsed.wsPath,
    remark: parsed.remark || ""
  };

  Object.entries(mapping).forEach(([field, value]) => {
    const el = els.fields?.querySelector(`[data-field="${field}"]`);
    if (el) el.value = String(value ?? "");
  });
}

function getEditedParsedFields(parsed) {
  const get = (field, fallback) => {
    const el = els.fields?.querySelector(`[data-field="${field}"]`);
    const value = el ? String(el.value ?? "").trim() : "";
    return value || fallback;
  };

  const port = Number(get("port", parsed.port));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Port must be an integer between 1 and 65535.");
  }

  return {
    ...parsed,
    uuid: get("uuid", parsed.uuid),
    address: get("address", parsed.address),
    port,
    transport: get("transport", parsed.transport),
    security: get("security", parsed.security),
    sni: get("sni", parsed.sni),
    wsHost: get("wsHost", parsed.wsHost),
    wsPath: get("wsPath", parsed.wsPath),
    remark: get("remark", parsed.remark)
  };
}

function renderOutboundRows() {
  if (!els.outboundRows) return;
  els.outboundRows.innerHTML = "";

  sniList.forEach((item, index) => {
    const row = document.createElement("div");
    row.className = "outbound-row list-driven-row";
    row.innerHTML = `
      <label>
        Tag
        <input data-outbound-field="tag" data-index="${index}" value="AutoOut_${index + 1}" />
      </label>
      <label>
        Fake SNI
        <input data-outbound-field="fakeSni" data-index="${index}" value="${escapeHtml(item.sni)}" />
      </label>
      <label>
        Spoof IP
        <input data-outbound-field="spoofIp" data-index="${index}" value="${escapeHtml(item.ip)}" />
      </label>
      <label>
        Target port
        <input data-outbound-field="targetPort" data-index="${index}" type="number" min="1" max="65535" value="443" />
      </label>
    `;
    els.outboundRows.appendChild(row);
  });
}

function getListDrivenOverrides() {
  if (!sniList.length) throw new Error("No outbound sources are available. Load a valid list.json before generating.");

  return sniList.map((item, index) => {
    const read = (field, fallback) => {
      const el = els.outboundRows?.querySelector(`[data-outbound-field="${field}"][data-index="${index}"]`);
      return el ? String(el.value ?? "").trim() : fallback;
    };

    const tag = read("tag", `AutoOut_${index + 1}`);
    const fakeSni = read("fakeSni", item.sni);
    const spoofIp = read("spoofIp", item.ip);
    const targetPort = Number(read("targetPort", "443"));

    if (!tag) throw new Error(`Outbound ${index + 1} tag is required.`);
    if (!fakeSni) throw new Error(`Outbound ${index + 1} SNI value is required.`);
    if (!spoofIp) throw new Error(`Outbound ${index + 1} IP value is required.`);
    if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
      throw new Error(`Outbound ${index + 1} target port must be between 1 and 65535.`);
    }

    return { tag, fakeSni, spoofIp, targetPort };
  });
}


function buildOutbound(parsed, override, index) {
  const proxyPort = numberValueOf(els.proxyPort, 41105);

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

function buildSingleRouting() {
  return {
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
        outboundTag: "proxy",
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
  };
}

function buildSingleV2boxConfig(parsed, entry, index) {
  const proxyAddress = valueOf(els.proxyAddress, "127.0.0.1").trim();
  const proxyPort = numberValueOf(els.proxyPort, 41105);

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
    outbounds: [
      buildOutbound(parsed, {
        tag: "proxy",
        fakeSni: entry.sni,
        spoofIp: entry.ip,
        targetPort: 443
      }, index),
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
    routing: buildSingleRouting(),
    stats: {}
  };
}

function buildV2boxConfigs(parsed) {
  return sniList.map((entry, index) => ({
    entry,
    config: buildSingleV2boxConfig(parsed, entry, index)
  }));
}

function renderV2boxConfigs() {
  if (!els.v2boxConfigs) return;

  if (!lastV2boxConfigs.length) {
    els.v2boxConfigs.innerHTML = `
      <div class="v2box-empty">
        <p>Generate the configurations to build the individual V2Box profiles.</p>
      </div>
    `;
    return;
  }

  els.v2boxConfigs.innerHTML = lastV2boxConfigs.map((item, index) => `
    <article class="v2box-config-card">
      <div class="v2box-config-head">
        <div>
          <div class="v2box-config-title">V2Box profile ${index + 1}</div>
          <div class="v2box-config-meta">
            <span>SNI: <code>${escapeHtml(item.entry.sni)}</code></span>
            <span>IP: <code>${escapeHtml(item.entry.ip)}</code></span>
          </div>
        </div>
        <button class="secondary v2box-copy-btn" type="button" data-index="${index}">Copy profile</button>
      </div>
      <pre class="v2box-config-json"><code>${escapeHtml(JSON.stringify(item.config, null, 2))}</code></pre>
    </article>
  `).join("");
}

async function copyV2boxConfig(index) {
  const item = lastV2boxConfigs[index];
  if (!item) {
    setStatus("This V2Box profile is not available.", "error");
    return;
  }

  try {
    await navigator.clipboard.writeText(JSON.stringify(item.config, null, 2));
    setStatus(`V2Box profile ${index + 1} copied to the clipboard.`, "success");
  } catch {
    setStatus("The browser blocked clipboard access.", "error");
  }
}

function buildConfig(parsed, listEntries) {
  const proxyAddress = valueOf(els.proxyAddress, "127.0.0.1").trim();
  const proxyStartPort = numberValueOf(els.proxyPort, 41105);
  const targetCount = listEntries.length;
  const selector = valueOf(els.observatorySelector, "AutoOut_").trim();
  const sampling = numberValueOf(els.observatorySampling, 3);

  if (!proxyAddress) throw new Error("Local proxy address is required.");
  if (!Number.isInteger(proxyStartPort) || proxyStartPort < 1 || proxyStartPort + targetCount - 1 > 65535) {
    throw new Error("The starting local proxy port is not valid.");
  }
  if (!selector) throw new Error("Burst Observatory subject selector is required.");
  if (!Number.isInteger(sampling) || sampling < 1) throw new Error("Sampling must be at least 1.");
  if (!valueOf(els.observatoryDestination, "http://edge.microsoft.com/captiveportal/generate_204").trim()) throw new Error("Burst Observatory destination is required.");
  if (!valueOf(els.observatoryInterval, "5m").trim()) throw new Error("Burst Observatory interval is required.");
  if (!valueOf(els.observatoryTimeout, "3s").trim()) throw new Error("Burst Observatory timeout is required.");

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
        interval: valueOf(els.observatoryInterval, "1m").trim(),
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
      // Preserve domain-based routing for the first match; do not resolve domains to IPs
      // merely to perform a second routing pass.
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


async function buildAdvancedConfig(parsed) {
  if (parsed.security !== "tls") {
    throw new Error("The advanced Xray profile requires security=tls in the input link.");
  }

  const advancedAddresses = await loadAdvancedAddresses();
  const advancedOutbounds = advancedAddresses.map((address, index) => ({
    mux: {
      concurrency: -1,
      enabled: false
    },
    protocol: "vless",
    settings: {
      vnext: [
        {
          address,
          port: parsed.port,
          users: [
            {
              encryption: parsed.encryption || "none",
              ...(parsed.flow ? { flow: parsed.flow } : {}),
              id: parsed.uuid,
              level: 8
            }
          ]
        }
      ]
    },
    streamSettings: {
      network: parsed.transport,
      security: "tls",
      tlsSettings: {
        allowInsecure: false,
        alpn: ["http/1.1"],//parsed.alpn.length ? parsed.alpn : ["http/1.1"],
        fingerprint: ADVANCED_FINGERPRINT,
        serverName: parsed.sni,
        cipherSuites: ADVANCED_CIPHER_SUITES,
        show: false
      },
      ...(parsed.transport === "ws" ? {
        wsSettings: {
          headers: { Host: parsed.wsHost },
          path: parsed.wsPath
        }
      } : {}),
      finalmask: JSON.parse(JSON.stringify(ADVANCED_FINALMASK))
    },
    tag: `AutoOut_${index + 1}`
  }));

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
      subjectSelector: [valueOf(els.observatorySelector, "AutoOut_").trim()],
      pingConfig: {
        destination: valueOf(els.observatoryDestination, "http://edge.microsoft.com/captiveportal/generate_204").trim(),
        connectivity: valueOf(els.observatoryConnectivity).trim(),
        interval: valueOf(els.observatoryInterval, "1m").trim(),
        sampling: numberValueOf(els.observatorySampling, 3),
        timeout: valueOf(els.observatoryTimeout, "3s").trim(),
        httpMethod: valueOf(els.observatoryHttpMethod, "HEAD")
      }
    },
    outbounds: [
      ...advancedOutbounds,
      {
        protocol: "freedom",
        settings: { domainStrategy: "UseIP" },
        tag: "direct"
      },
      {
        protocol: "blackhole",
        settings: { response: { type: "http" } },
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
      domainStrategy: "IPIfNonMatch",
      rules: [
        {
          ip: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888"],
          balancerTag: "all",
          port: "53",
          type: "field",
          enabled: true
        },
        {
          ip: ["2620:119:35::35"],
          outboundTag: "direct",
          port: "53",
          type: "field",
          enabled: true
        },
        {
          outboundTag: "block",
          port: "443",
          network: "udp",
          type: "field",
          enabled: true
        },
        {
          outboundTag: "block",
          domain: ["geosite:category-ads-all"],
          type: "field",
          enabled: true
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
          enabled: true
        },
        {
          outboundTag: "direct",
          ip: ["geoip:private"],
          type: "field",
          enabled: true
        },
        {
          outboundTag: "direct",
          domain: ["geosite:private"],
          type: "field",
          enabled: true
        },
        {
          outboundTag: "direct",
          ip: ["geoip:ir"],
          type: "field",
          enabled: true
        },
        {
          outboundTag: "direct",
          domain: ["domain:.ir", "geosite:category-ir"],
          type: "field",
          enabled: true
        },
        {
          type: "field",
          domain: ["domain:workers.dev"],
          path: ["regexp:^/QR/.*"],
          outboundTag: "direct"
        },
        {
          outboundTag: "direct",
          protocol: ["bittorrent"],
          type: "field",
          enabled: true
        },
        {
          balancerTag: "all",
          port: "0-65535"
        }
      ],
      balancers: [
        {
          tag: "all",
          selector: ["AutoOut_"],
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

function renderAdvancedConfig() {
  if (!els.advancedOutput) return;

  const config = lastAdvancedConfig ?? {
    message: "Paste a VLESS link, then generate the configurations."
  };

  els.advancedOutput.innerHTML = `<code>${escapeHtml(JSON.stringify(config, null, 2))}</code>`;
}

async function copyAdvancedJson() {
  if (!lastAdvancedConfig) {
    setStatus("Generate the configurations first.", "error");
    return;
  }

  try {
    await navigator.clipboard.writeText(JSON.stringify(lastAdvancedConfig, null, 2));
    setStatus("Advanced Xray configuration copied to the clipboard.", "success");
  } catch {
    setStatus("The browser blocked clipboard access.", "error");
  }
}

async function generate() {
  try {
    // Refresh the source list before each generation so stale in-memory data is never reused.
    await loadSniList();
    renderOutboundRows();
    const rawInput = valueOf(els.input);
    const parsedBase = parseVless(rawInput);
    const parsed = rawInput === generate._lastInput ? getEditedParsedFields(parsedBase) : parsedBase;
    const entries = getListDrivenOverrides();
    generate._lastInput = rawInput;
    const config = buildConfig(parsed, entries);
    const advancedConfig = await buildAdvancedConfig(parsed);

    lastConfig = config;
    lastAdvancedConfig = advancedConfig;
    lastV2boxConfigs = buildV2boxConfigs(parsed);
    setDetectedFields(parsed);
    if (els.output) els.output.innerHTML = `<code>${escapeHtml(JSON.stringify(config, null, 2))}</code>`;
    renderAdvancedConfig();
    renderV2boxConfigs();
    console.info("Generated outbound entries:", entries);
    console.info("Generated advanced AutoOut addresses:", advancedConfig.outbounds.slice(0, ADVANCED_OUTBOUND_COUNT).map((outbound) => outbound.settings.vnext[0].address));
    const capped = sourceListCount > MAX_V2BOX_CONFIGS ? ` (showing first ${MAX_V2BOX_CONFIGS} of ${sourceListCount})` : "";
    setStatus(`Generated ${entries.length} outbound entries, an advanced Xray profile, and ${lastV2boxConfigs.length} V2Box profiles from list.json${capped}.`, "success");
  } catch (error) {
    lastConfig = null;
    lastAdvancedConfig = null;
    lastV2boxConfigs = [];
    renderAdvancedConfig();
    renderV2boxConfigs();
    setStatus(error instanceof Error ? error.message : "Invalid input.", "error");
  }
}

async function copyJson() {
  if (!lastConfig) {
    setStatus("Generate the configurations first.", "error");
    return;
  }
  try {
    await navigator.clipboard.writeText(JSON.stringify(lastConfig, null, 2));
    setStatus("Generated configuration copied to the clipboard.", "success");
  } catch {
    setStatus("The browser blocked clipboard access.", "error");
  }
}

function downloadJson() {
  if (!lastConfig) {
    setStatus("Generate the configurations first.", "error");
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
  setStatus("JSON file downloaded successfully.", "success");
}

if (els.generate) els.generate.addEventListener("click", () => { void generate(); });
if (els.copy) els.copy.addEventListener("click", copyJson);
if (els.advancedCopy) els.advancedCopy.addEventListener("click", copyAdvancedJson);
if (els.download) els.download.addEventListener("click", downloadJson);
if (els.v2boxConfigs) {
  els.v2boxConfigs.addEventListener("click", (event) => {
    const button = event.target.closest(".v2box-copy-btn");
    if (!button) return;
    const index = Number(button.dataset.index);
    if (Number.isInteger(index)) void copyV2boxConfig(index);
  });
}
if (els.sample) els.sample.addEventListener("click", async () => {
  if (els.input) els.input.value = sampleVless;
  try {
    await loadSniList();
    renderOutboundRows();
    await generate();
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "Could not load list.json.", "error");
  }
});
if (els.input) els.input.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") void generate();
});

(async () => {
  try {
    await loadSniList();
    renderOutboundRows();
    renderAdvancedConfig();
    renderV2boxConfigs();
    const limitNote = sourceListCount > MAX_V2BOX_CONFIGS ? ` Showing the first ${MAX_V2BOX_CONFIGS} of ${sourceListCount}.` : "";
    setStatus(`Loaded ${sniList.length} outbound source entries from list.json.${limitNote}`, "success");
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "Could not load list.json.", "error");
  }
})();
