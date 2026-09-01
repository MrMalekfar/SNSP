"use strict";

const MAX_V2BOX_CONFIGS = 10;
const ADVANCED_OUTBOUND_COUNT = 20;
const ADVANCED_ADDRESS_SOURCE = "https://raw.githubusercontent.com/MrMalekfar/Lists/main/merged_lists.json";
const DEFAULT_OUTPUT_MESSAGE = "Paste a VLESS link, then generate the configurations.";
const DEFAULT_REMARK = "EpoVpn";

const DEFAULTS = Object.freeze({
  proxyAddress: "127.0.0.1",
  proxyPort: 41105,
  logLevel: "warning",
  observatorySelector: "AutoOut_",
  observatoryDestination: "http://edge.microsoft.com/captiveportal/generate_204",
  observatoryConnectivity: "",
  observatoryInterval: "5m",
  observatorySampling: 3,
  observatoryTimeout: "3s",
  observatoryHttpMethod: "HEAD"
});

const SAMPLE_VLESS =
  "vless://d72bc3eb-755a-415d-9999-08bf5987ccf2@188.114.98.224:443?path=%2FUrn8f6B57GWK_g_1%3Fed%3D2560&security=tls&alpn=h3&encryption=none&insecure=0&host=WORKERs.dEV&fp=chrome&type=ws&allowInsecure=0&sni=WORKERs.dEV#1%20-%F0%9F%8F%85";

// Current Xray TLS baseline used by the V2 profiles.
// Keep cipherSuites limited to TLS 1.2-era suites; TLS 1.3 suites are selected automatically.
const ADVANCED_FINGERPRINT = "chrome";
const ADVANCED_CIPHER_SUITES =
  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:" +
  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:" +
  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";

const ADVANCED_FINALMASK = Object.freeze({
  tcp: [
    {
      type: "fragment",
      settings: {
        packets: "tlshello",
        lengths: ["5-12", "30-60", "1-3"],
        delays: ["0-1", "1-3"],
        maxSplit: "3-6"
      }
    }
  ]
});

const STATIC_DNS_HOSTS = Object.freeze({
  "domain:googleapis.cn": "googleapis.com",
  "dns.alidns.com": ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
  "one.one.one.one": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
  "dns.cloudflare.com": ["104.16.132.229", "104.16.133.229", "2606:4700::6810:84e5", "2606:4700::6810:85e5"],
  "cloudflare-dns.com": ["104.16.248.249", "104.16.249.249", "2606:4700::6810:f8f9", "2606:4700::6810:f9f9"],
  "dot.pub": ["1.12.12.12", "120.53.53.53"],
  "dns.google": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
  "dns.quad9.net": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
  "common.dot.dns.yandex.net": ["77.88.8.8", "77.88.8.1", "2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff"]
});

function byId(id) {
  return document.getElementById(id);
}

const els = Object.freeze({
  input: byId("vlessInput"),
  generate: byId("generateBtn"),
  sample: byId("sampleBtn"),
  copy: byId("copyBtn"),
  download: byId("downloadBtn"),
  output: byId("output"),
  advancedOutput: byId("advancedOutput"),
  advancedCopy: byId("advancedCopy"),
  v2boxConfigs: byId("v2boxConfigs"),
  status: byId("status"),
  fields: byId("fields"),
  proxyAddress: byId("proxyAddress"),
  proxyPort: byId("proxyPort"),
  logLevel: byId("logLevel"),
  outboundRows: byId("outboundRows"),
  observatorySelector: byId("observatorySelector"),
  observatoryDestination: byId("observatoryDestination"),
  observatoryConnectivity: byId("observatoryConnectivity"),
  observatoryInterval: byId("observatoryInterval"),
  observatorySampling: byId("observatorySampling"),
  observatoryTimeout: byId("observatoryTimeout"),
  observatoryHttpMethod: byId("observatoryHttpMethod")
});

const state = {
  sourceListCount: 0,
  sniList: [],
  lastConfig: null,
  lastAdvancedConfig: null,
  lastV2boxConfigs: [],
  lastInput: "",
  generating: false
};

function valueOf(element, fallback = "") {
  return element && typeof element.value === "string" ? element.value : fallback;
}

function numberValueOf(element, fallback = 0) {
  const value = Number(valueOf(element, String(fallback)));
  return Number.isFinite(value) ? value : fallback;
}

function setStatus(message, kind = "") {
  if (!els.status) return;
  els.status.textContent = message;
  els.status.className = `status ${kind}`.trim();
}

function setGenerating(isGenerating) {
  state.generating = isGenerating;
  if (els.generate) {
    els.generate.disabled = isGenerating;
    els.generate.textContent = isGenerating ? "Generating…" : "Generate configurations";
  }
  if (els.sample) els.sample.disabled = isGenerating;
  updateActionStates();
}

function updateActionStates() {
  if (els.copy) els.copy.disabled = state.generating || !state.lastConfig;
  if (els.download) els.download.disabled = state.generating || !state.lastConfig;
  if (els.advancedCopy) els.advancedCopy.disabled = state.generating || !state.lastAdvancedConfig;
}

function jsonText(value) {
  return JSON.stringify(value, null, 2);
}

function renderJson(element, value) {
  if (!element) return;
  element.textContent = jsonText(value ?? { message: DEFAULT_OUTPUT_MESSAGE });
}

function clearGeneratedState() {
  state.lastConfig = null;
  state.lastAdvancedConfig = null;
  state.lastV2boxConfigs = [];
  renderGeneratedOutputs();
}

function renderGeneratedOutputs() {
  renderJson(els.output, state.lastConfig);
  renderJson(els.advancedOutput, state.lastAdvancedConfig);
  renderV2boxConfigs();
  updateActionStates();
}

async function fetchJson(url, failureLabel) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`${failureLabel} (HTTP ${response.status}).`);
  }
  return response.json();
}

async function loadAdvancedAddresses() {
  const data = await fetchJson(
    `${ADVANCED_ADDRESS_SOURCE}?v=${Date.now()}`,
    "Could not load the Advanced address list from GitHub"
  );

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

async function loadSniList() {
  const data = await fetchJson(
    `./list.json?v=${Date.now()}`,
    "Could not load list.json"
  );

  if (!Array.isArray(data)) {
    throw new Error("list.json must contain a JSON array of objects with both ip and sni fields.");
  }

  const cleaned = data.map((item) => ({
    ip: String(item?.ip ?? "").trim(),
    sni: String(item?.sni ?? "").trim()
  }));

  const invalidIndex = cleaned.findIndex((item) => !item.ip || !item.sni);
  if (invalidIndex >= 0) {
    throw new Error(`list.json entry ${invalidIndex + 1} must contain both "ip" and "sni".`);
  }
  if (!cleaned.length) {
    throw new Error("list.json is empty. Add at least one outbound source before generating configurations.");
  }

  state.sourceListCount = cleaned.length;
  state.sniList = cleaned.slice(0, MAX_V2BOX_CONFIGS);
  return state.sniList;
}

function isValidIpAddress(value) {
  const ipv4Parts = value.split(".");
  if (
    ipv4Parts.length === 4 &&
    ipv4Parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
  ) {
    return true;
  }

  if (!value.includes(":") || !/^[0-9A-Fa-f:]+$/.test(value)) {
    return false;
  }

  const groups = value.split(":");
  const hasCompression = value.includes("::");
  const nonEmptyGroups = groups.filter(Boolean);

  return (
    nonEmptyGroups.length <= 8 &&
    nonEmptyGroups.every((group) => /^[0-9A-Fa-f]{1,4}$/.test(group)) &&
    (hasCompression ? groups.length <= 9 : groups.length === 8)
  );
}

function shuffle(values) {
  const copy = [...values];
  for (let index = copy.length - 1; index > 0; index -= 1) {
    const randomIndex = Math.floor(Math.random() * (index + 1));
    [copy[index], copy[randomIndex]] = [copy[randomIndex], copy[index]];
  }
  return copy;
}

function parseVless(raw) {
  const value = String(raw ?? "").trim();
  if (!value) throw new Error("Paste a VLESS link to continue.");
  if (!value.toLowerCase().startsWith("vless://")) {
    throw new Error("The input must start with vless://.");
  }

  const hashIndex = value.indexOf("#");
  const withoutFragment = hashIndex >= 0 ? value.slice(0, hashIndex) : value;
  const fragment = hashIndex >= 0 ? value.slice(hashIndex + 1) : "";

  const atIndex = withoutFragment.indexOf("@", 8);
  if (atIndex < 0) {
    throw new Error("Invalid VLESS link: the server separator (@) is missing.");
  }

  const userPart = withoutFragment.slice(8, atIndex);
  const serverPart = withoutFragment.slice(atIndex + 1);
  const queryIndex = serverPart.indexOf("?");
  const serverNoQuery = queryIndex >= 0 ? serverPart.slice(0, queryIndex) : serverPart;
  const queryPart = queryIndex >= 0 ? serverPart.slice(queryIndex + 1) : "";

  let address = serverNoQuery;
  let portText = "";

  if (serverNoQuery.startsWith("[")) {
    const close = serverNoQuery.indexOf("]");
    if (close < 0) {
      throw new Error("Invalid VLESS link: the IPv6 server address is not valid.");
    }
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
  const alpn = (params.get("alpn") || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
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

function detectedField(field) {
  return els.fields?.querySelector(`[data-field="${field}"]`) ?? null;
}

function setDetectedFields(parsed) {
  const values = {
    uuid: parsed.uuid,
    address: parsed.address,
    port: parsed.port,
    transport: parsed.transport,
    security: parsed.security,
    sni: parsed.sni,
    wsHost: parsed.wsHost,
    wsPath: parsed.wsPath,
    remark: DEFAULT_REMARK
  };

  Object.entries(values).forEach(([field, value]) => {
    const element = detectedField(field);
    if (element) element.value = String(value ?? "");
  });
}

function getEditedParsedFields(parsed) {
  const readField = (field, fallback) => {
    const value = String(detectedField(field)?.value ?? "").trim();
    return value || fallback;
  };

  const port = Number(readField("port", parsed.port));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Port must be an integer between 1 and 65535.");
  }

  return {
    ...parsed,
    uuid: readField("uuid", parsed.uuid),
    address: readField("address", parsed.address),
    port,
    transport: readField("transport", parsed.transport),
    security: readField("security", parsed.security),
    sni: readField("sni", parsed.sni),
    wsHost: readField("wsHost", parsed.wsHost),
    wsPath: readField("wsPath", parsed.wsPath),
    remark: readField("remark", parsed.remark)
  };
}

function outboundInput(field, index) {
  return els.outboundRows?.querySelector(
    `[data-outbound-field="${field}"][data-index="${index}"]`
  ) ?? null;
}

function collectOutboundDrafts() {
  return state.sniList.map((item, index) => ({
    tag: String(outboundInput("tag", index)?.value ?? `AutoOut_${index + 1}`),
    fakeSni: String(outboundInput("fakeSni", index)?.value ?? item.sni),
    spoofIp: String(outboundInput("spoofIp", index)?.value ?? item.ip),
    targetPort: String(outboundInput("targetPort", index)?.value ?? "443")
  }));
}

function createOutboundField(labelText, field, index, value, options = {}) {
  const label = document.createElement("label");
  label.append(document.createTextNode(labelText));

  const input = document.createElement("input");
  input.dataset.outboundField = field;
  input.dataset.index = String(index);
  input.value = value;

  if (options.type) input.type = options.type;
  if (options.min != null) input.min = String(options.min);
  if (options.max != null) input.max = String(options.max);

  label.appendChild(input);
  return label;
}

function renderOutboundRows(drafts = []) {
  if (!els.outboundRows) return;

  const fragment = document.createDocumentFragment();
  state.sniList.forEach((item, index) => {
    const draft = drafts[index] ?? {};
    const row = document.createElement("div");
    row.className = "outbound-row list-driven-row";

    row.append(
      createOutboundField("Tag", "tag", index, draft.tag ?? `AutoOut_${index + 1}`),
      createOutboundField("Fake SNI", "fakeSni", index, draft.fakeSni ?? item.sni),
      createOutboundField("Spoof IP", "spoofIp", index, draft.spoofIp ?? item.ip),
      createOutboundField("Target port", "targetPort", index, draft.targetPort ?? "443", {
        type: "number",
        min: 1,
        max: 65535
      })
    );

    fragment.appendChild(row);
  });

  els.outboundRows.replaceChildren(fragment);
}

function getListDrivenOverrides() {
  if (!state.sniList.length) {
    throw new Error("No outbound sources are available. Load a valid list.json before generating.");
  }

  return state.sniList.map((item, index) => {
    const read = (field, fallback) => {
      const element = outboundInput(field, index);
      return element ? String(element.value ?? "").trim() : fallback;
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

function buildDnsConfig() {
  return {
    hosts: STATIC_DNS_HOSTS,
    servers: [
      "1.1.1.1",
      {
        address: "223.5.5.5",
        domains: [
          "domain:.ir",
          "geosite:category-ir"
        ],
        skipFallback: true,
        tag: "domestic-dns0"
      }
    ],
    queryStrategy: "UseIP",
    disableCache: false,
    serveStale: true,
    serveExpiredTTL: 86400,
    enableParallelQuery: false,
    tag: "dns-module"
  };
}

function buildSocksInbounds() {
  return [
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
        destOverride: ["http", "tls", "quic"],
        enabled: true,
        routeOnly: false
      },
      tag: "socks"
    }
  ];
}

function buildLogConfig() {
  return {
    loglevel: valueOf(els.logLevel, DEFAULTS.logLevel)
  };
}

function buildPolicy() {
  return {
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
  };
}

function buildDirectOutbound() {
  return {
    protocol: "freedom",
    settings: {
      domainStrategy: "UseIP"
    },
    tag: "direct"
  };
}

function buildBlockOutbound() {
  return {
    protocol: "blackhole",
    settings: {
      response: {
        type: "http"
      }
    },
    tag: "block"
  };
}

function readObservatorySettings() {
  const settings = {
    selector: valueOf(els.observatorySelector, DEFAULTS.observatorySelector).trim(),
    destination: valueOf(els.observatoryDestination, DEFAULTS.observatoryDestination).trim(),
    connectivity: valueOf(els.observatoryConnectivity, DEFAULTS.observatoryConnectivity).trim(),
    interval: valueOf(els.observatoryInterval, DEFAULTS.observatoryInterval).trim(),
    sampling: numberValueOf(els.observatorySampling, DEFAULTS.observatorySampling),
    timeout: valueOf(els.observatoryTimeout, DEFAULTS.observatoryTimeout).trim(),
    httpMethod: valueOf(els.observatoryHttpMethod, DEFAULTS.observatoryHttpMethod)
  };

  if (!settings.selector) throw new Error("Burst Observatory subject selector is required.");
  if (!settings.destination) throw new Error("Burst Observatory destination is required.");
  if (!settings.interval) throw new Error("Burst Observatory interval is required.");
  if (!settings.timeout) throw new Error("Burst Observatory timeout is required.");
  if (!Number.isInteger(settings.sampling) || settings.sampling < 1) {
    throw new Error("Sampling must be at least 1.");
  }

  return settings;
}

function buildBurstObservatory(settings) {
  return {
    subjectSelector: [settings.selector],
    pingConfig: {
      destination: settings.destination,
      connectivity: settings.connectivity,
      interval: settings.interval,
      sampling: settings.sampling,
      timeout: settings.timeout,
      httpMethod: settings.httpMethod
    }
  };
}

function buildBalancedRouting() {
  return {
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
        outboundTag: "direct",
        domain: ["domain:workers.dev"],
        path: ["regexp:^/QR/.*"],
        type: "field"
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
          type: "leastLoad",
          settings: {
            expected: 2,
            maxRTT: "1s",
            tolerance: 0.1,
            baselines: ["1s"]
          }
        },
        fallbackTag: "AutoOut_1"
      }
    ]
  };
}

function buildSingleRouting() {
  return {
    domainStrategy: "IPIfNonMatch",
    rules: [
      {
        ip: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888"],
        outboundTag: "proxy",
        port: "53",
        type: "field"
      },
      {
        ip: ["2620:119:35::35"],
        outboundTag: "direct",
        port: "53",
        type: "field"
      },
      {
        outboundTag: "block",
        port: "443",
        network: "udp",
        type: "field"
      },
      {
        outboundTag: "block",
        domain: ["geosite:category-ads-all"],
        type: "field"
      },
      {
        outboundTag: "block",
        ip: ["10.10.34.0/24"],
        type: "field"
      },
      {
        outboundTag: "direct",
        ip: ["geoip:private"],
        type: "field"
      },
      {
        outboundTag: "direct",
        domain: ["geosite:private"],
        type: "field"
      },
      {
        outboundTag: "direct",
        ip: ["geoip:ir"],
        type: "field"
      },
      {
        outboundTag: "direct",
        domain: ["domain:.ir", "geosite:category-ir"],
        type: "field"
      },
      {
        outboundTag: "direct",
        protocol: ["bittorrent"],
        type: "field"
      },
      {
        outboundTag: "proxy",
        port: "0-65535"
      }
    ]
  };
}

function buildOutbound(parsed, override) {
  const proxyPort = numberValueOf(els.proxyPort, DEFAULTS.proxyPort);
  const isTls = parsed.security === "tls";

  return {
    mux: {
      concurrency: -1,
      enabled: false
    },
    protocol: "vless",
    settings: {
      vnext: [
        {
          address: valueOf(els.proxyAddress, DEFAULTS.proxyAddress).trim(),
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
      ...(isTls
        ? {
            tlsSettings: {
              minVersion: "1.2",
              maxVersion: "1.3",
              fingerprint: ADVANCED_FINGERPRINT,
              cipherSuites: ADVANCED_CIPHER_SUITES,
              serverName: parsed.sni,
              show: false
            }
          }
        : {}),
      ...(parsed.transport === "ws"
        ? {
            wsSettings: {
              headers: { Host: parsed.wsHost },
              path: parsed.wsPath
            }
          }
        : {}),
      ...(isTls ? { finalmask: cloneAdvancedFinalmask() } : {})
    },
    tag: override.tag
  };
}

function buildSingleV2boxConfig(parsed, entry, index) {
  return {
    dns: buildDnsConfig(),
    inbounds: buildSocksInbounds(),
    log: buildLogConfig(),
    outbounds: [
      buildOutbound(parsed, {
        tag: "proxy",
        fakeSni: entry.sni,
        spoofIp: entry.ip,
        targetPort: 443
      }),
      buildDirectOutbound(),
      buildBlockOutbound()
    ],
    policy: buildPolicy(),
    remarks: `${index + 1} - EpoVpn Sni_Spoof V2`,
    routing: buildSingleRouting(),
    stats: {}
  };
}

function buildV2boxConfigs(parsed) {
  return state.sniList.map((entry, index) => ({
    entry,
    config: buildSingleV2boxConfig(parsed, entry, index)
  }));
}

function validateMainProxySettings(targetCount) {
  const proxyAddress = valueOf(els.proxyAddress, DEFAULTS.proxyAddress).trim();
  const proxyStartPort = numberValueOf(els.proxyPort, DEFAULTS.proxyPort);

  if (!proxyAddress) throw new Error("Local proxy address is required.");
  if (
    !Number.isInteger(proxyStartPort) ||
    proxyStartPort < 1 ||
    proxyStartPort + targetCount - 1 > 65535
  ) {
    throw new Error("The starting local proxy port is not valid.");
  }
}

function buildConfig(parsed, listEntries) {
  validateMainProxySettings(listEntries.length);
  const observatory = readObservatorySettings();

  return {
    dns: buildDnsConfig(),
    inbounds: buildSocksInbounds(),
    log: buildLogConfig(),
    burstObservatory: buildBurstObservatory(observatory),
    outbounds: [
      ...listEntries.map((entry) => buildOutbound(parsed, entry)),
      buildDirectOutbound(),
      buildBlockOutbound()
    ],
    policy: buildPolicy(),
    remarks: "EpoVpn Sni_Spoof V2",
    routing: buildBalancedRouting(),
    stats: {}
  };
}

function cloneAdvancedFinalmask() {
  return JSON.parse(JSON.stringify(ADVANCED_FINALMASK));
}

function buildAdvancedOutbound(parsed, address, index) {
  return {
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
        minVersion: "1.2",
        maxVersion: "1.3",
        alpn: ["http/1.1"],
        fingerprint: ADVANCED_FINGERPRINT,
        serverName: parsed.sni,
        cipherSuites: ADVANCED_CIPHER_SUITES,
        show: false
      },
      ...(parsed.transport === "ws"
        ? {
            wsSettings: {
              headers: { Host: parsed.wsHost },
              path: parsed.wsPath
            }
          }
        : {}),
      finalmask: cloneAdvancedFinalmask()
    },
    tag: `AutoOut_${index + 1}`
  };
}

async function buildAdvancedConfig(parsed) {
  if (parsed.security !== "tls") {
    throw new Error("The advanced Xray profile requires security=tls in the input link.");
  }

  const observatory = readObservatorySettings();
  const advancedAddresses = await loadAdvancedAddresses();
  const advancedOutbounds = advancedAddresses.map((address, index) =>
    buildAdvancedOutbound(parsed, address, index)
  );

  return {
    dns: buildDnsConfig(),
    inbounds: buildSocksInbounds(),
    log: buildLogConfig(),
    burstObservatory: buildBurstObservatory(observatory),
    outbounds: [
      ...advancedOutbounds,
      buildDirectOutbound(),
      buildBlockOutbound()
    ],
    policy: buildPolicy(),
    remarks: "EpoVpn Advanced V2",
    routing: buildBalancedRouting(),
    stats: {}
  };
}

function createV2boxProfileCard(item, index) {
  const article = document.createElement("article");
  article.className = "v2box-config-card";

  const head = document.createElement("div");
  head.className = "v2box-config-head";

  const info = document.createElement("div");
  const title = document.createElement("div");
  title.className = "v2box-config-title";
  title.textContent = `V2Box profile ${index + 1}`;

  const meta = document.createElement("div");
  meta.className = "v2box-config-meta";

  const sni = document.createElement("span");
  sni.append("SNI: ");
  const sniCode = document.createElement("code");
  sniCode.textContent = item.entry.sni;
  sni.appendChild(sniCode);

  const ip = document.createElement("span");
  ip.append("IP: ");
  const ipCode = document.createElement("code");
  ipCode.textContent = item.entry.ip;
  ip.appendChild(ipCode);

  meta.append(sni, ip);
  info.append(title, meta);

  const copyButton = document.createElement("button");
  copyButton.className = "secondary v2box-copy-btn";
  copyButton.type = "button";
  copyButton.dataset.index = String(index);
  copyButton.textContent = "Copy profile";

  head.append(info, copyButton);

  const pre = document.createElement("pre");
  pre.className = "v2box-config-json";
  pre.tabIndex = 0;
  pre.textContent = jsonText(item.config);

  article.append(head, pre);
  return article;
}

function renderV2boxConfigs() {
  if (!els.v2boxConfigs) return;

  if (!state.lastV2boxConfigs.length) {
    const empty = document.createElement("div");
    empty.className = "v2box-empty";

    const message = document.createElement("p");
    message.textContent = "Generate the configurations to build the individual V2Box profiles.";
    empty.appendChild(message);

    els.v2boxConfigs.replaceChildren(empty);
    return;
  }

  const fragment = document.createDocumentFragment();
  state.lastV2boxConfigs.forEach((item, index) => {
    fragment.appendChild(createV2boxProfileCard(item, index));
  });
  els.v2boxConfigs.replaceChildren(fragment);
}

async function copyConfig(config, successMessage, missingMessage = "Generate the configurations first.") {
  if (!config) {
    setStatus(missingMessage, "error");
    return;
  }

  try {
    await navigator.clipboard.writeText(jsonText(config));
    setStatus(successMessage, "success");
  } catch {
    setStatus("The browser blocked clipboard access.", "error");
  }
}

function copyMainConfig() {
  return copyConfig(state.lastConfig, "Generated configuration copied to the clipboard.");
}

function copyAdvancedConfig() {
  return copyConfig(
    state.lastAdvancedConfig,
    "Advanced Xray configuration copied to the clipboard."
  );
}

function copyV2boxConfig(index) {
  const item = state.lastV2boxConfigs[index];
  return copyConfig(
    item?.config ?? null,
    `V2Box profile ${index + 1} copied to the clipboard.`,
    "This V2Box profile is not available."
  );
}

function downloadMainConfig() {
  if (!state.lastConfig) {
    setStatus("Generate the configurations first.", "error");
    return;
  }

  const blob = new Blob([jsonText(state.lastConfig)], {
    type: "application/json;charset=utf-8"
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "xray-multi-vless-config.json";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  setStatus("JSON file downloaded successfully.", "success");
}

async function generate() {
  if (state.generating) return;
  setGenerating(true);
  setStatus("Generating configurations…");

  try {
    const outboundDrafts = collectOutboundDrafts();
    await loadSniList();
    renderOutboundRows(outboundDrafts);

    const rawInput = valueOf(els.input);
    const parsedBase = parseVless(rawInput);
    const parsed = rawInput === state.lastInput
      ? getEditedParsedFields(parsedBase)
      : parsedBase;
    const entries = getListDrivenOverrides();

    const config = buildConfig(parsed, entries);
    const advancedConfig = await buildAdvancedConfig(parsed);

    state.lastInput = rawInput;
    state.lastConfig = config;
    state.lastAdvancedConfig = advancedConfig;
    state.lastV2boxConfigs = buildV2boxConfigs(parsed);

    setDetectedFields(parsed);
    renderGeneratedOutputs();

    const capped = state.sourceListCount > MAX_V2BOX_CONFIGS
      ? ` (showing first ${MAX_V2BOX_CONFIGS} of ${state.sourceListCount})`
      : "";
    setStatus(
      `Generated ${entries.length} outbound entries, an advanced Xray profile, and ${state.lastV2boxConfigs.length} V2Box profiles from list.json${capped}.`,
      "success"
    );
  } catch (error) {
    clearGeneratedState();
    setStatus(error instanceof Error ? error.message : "Invalid input.", "error");
  } finally {
    setGenerating(false);
  }
}

function handleV2boxClick(event) {
  if (!(event.target instanceof Element)) return;
  const button = event.target.closest(".v2box-copy-btn");
  if (!button) return;

  const index = Number(button.dataset.index);
  if (Number.isInteger(index)) {
    void copyV2boxConfig(index);
  }
}

function handleInputKeydown(event) {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    event.preventDefault();
    void generate();
  }
}

function bindEvents() {
  els.generate?.addEventListener("click", () => void generate());
  els.copy?.addEventListener("click", () => void copyMainConfig());
  els.advancedCopy?.addEventListener("click", () => void copyAdvancedConfig());
  els.download?.addEventListener("click", downloadMainConfig);
  els.v2boxConfigs?.addEventListener("click", handleV2boxClick);
  els.input?.addEventListener("keydown", handleInputKeydown);
  els.sample?.addEventListener("click", () => {
    if (els.input) els.input.value = SAMPLE_VLESS;
    void generate();
  });
}

async function initialize() {
  updateActionStates();
  renderGeneratedOutputs();

  try {
    await loadSniList();
    renderOutboundRows();

    const limitNote = state.sourceListCount > MAX_V2BOX_CONFIGS
      ? ` Showing the first ${MAX_V2BOX_CONFIGS} of ${state.sourceListCount}.`
      : "";
    setStatus(
      `Loaded ${state.sniList.length} outbound source entries from list.json.${limitNote}`,
      "success"
    );
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "Could not load list.json.", "error");
  }
}

bindEvents();
void initialize();
