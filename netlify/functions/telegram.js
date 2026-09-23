const crypto = require("crypto");
const dns = require("dns").promises;
const tls = require("tls");

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const ADMIN_USER_ID = process.env.ADMIN_USER_ID || "";

const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;

// ============================================================
// CYBERBOT V4
// V2 + V3 + V4
// Defensive / authorized security toolkit
// ============================================================

const MAX_FILE_SIZE = 5 * 1024 * 1024;

// Simple in-memory storage.
// NOTE: Netlify functions are serverless, so this data can disappear
// between invocations. Replace these with persistent storage later.
const users = new Map();
const activityLogs = [];
const monitoredDomains = new Set();


// ============================================================
// TELEGRAM API
// ============================================================

async function telegram(method, data = {}) {
  const response = await fetch(`${TELEGRAM_API}/${method}`, {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify(data)
  });

  return response.json();
}


async function sendMessage(chatId, text) {
  return telegram("sendMessage", {
    chat_id: chatId,
    text
  });
}


// ============================================================
// LOGGING
// ============================================================

function logActivity(message, command = "") {
  const user = message.from || {};

  activityLogs.push({
    time: new Date().toISOString(),
    userId: String(user.id || ""),
    username: user.username || "",
    command
  });

  // Keep memory under control.
  if (activityLogs.length > 100) {
    activityLogs.shift();
  }
}


function registerUser(message) {
  const user = message.from || {};
  const id = String(user.id || "");

  if (!id) return;

  users.set(id, {
    id,
    username: user.username || "",
    firstName: user.first_name || "",
    lastSeen: new Date().toISOString()
  });
}


function isAdmin(message) {
  if (!ADMIN_USER_ID) return false;

  return String(message.from?.id) === String(ADMIN_USER_ID);
}


// ============================================================
// HELPERS
// ============================================================

function getArg(text) {
  return (text || "")
    .trim()
    .split(/\s+/)
    .slice(1)
    .join(" ")
    .trim();
}


function hostnameFromInput(input) {
  if (!input) return "";

  let value = input.trim();

  if (!value.includes("://")) {
    value = `https://${value}`;
  }

  try {
    return new URL(value).hostname;
  } catch {
    return value
      .replace(/^https?:\/\//i, "")
      .split("/")[0]
      .split(":")[0];
  }
}


function normalizeUrl(input) {
  if (!input) return null;

  let value = input.trim();

  if (!/^https?:\/\//i.test(value)) {
    value = `https://${value}`;
  }

  try {
    return new URL(value).toString();
  } catch {
    return null;
  }
}


function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "Unknown";

  if (bytes < 1024) {
    return `${bytes} B`;
  }

  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(2)} KB`;
  }

  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}


// ============================================================
// DNS
// ============================================================

async function dnsLookup(hostname) {
  return dns.lookup(hostname, {
    all: true
  });
}


// ============================================================
// HASHING
// ============================================================

function hashText(text) {
  return {
    sha256: crypto
      .createHash("sha256")
      .update(text)
      .digest("hex"),

    sha512: crypto
      .createHash("sha512")
      .update(text)
      .digest("hex"),

    md5: crypto
      .createHash("md5")
      .update(text)
      .digest("hex")
  };
}


function sha256Text(text) {
  return crypto
    .createHash("sha256")
    .update(text)
    .digest("hex");
}


// ============================================================
// PASSWORD
// ============================================================

function passwordStrength(password) {
  let score = 0;

  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  let strength = "Very weak";

  if (score >= 6) strength = "Very strong";
  else if (score >= 5) strength = "Strong";
  else if (score >= 4) strength = "Good";
  else if (score >= 3) strength = "Weak";

  return {
    length: password.length,
    score,
    strength
  };
}


// ============================================================
// HTTP HEADERS
// ============================================================

async function httpsHeaders(url) {
  const response = await fetch(url, {
    method: "GET",
    redirect: "manual"
  });

  const headers = {};

  for (const [key, value] of response.headers.entries()) {
    headers[key] = value;
  }

  return {
    status: response.status,
    statusText: response.statusText,
    headers
  };
}


// ============================================================
// TLS
// ============================================================

function tlsInfo(hostname) {
  return new Promise((resolve, reject) => {

    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false,
      timeout: 8000
    });

    socket.on("secureConnect", () => {

      const cipher = socket.getCipher();

      resolve({
        protocol: socket.getProtocol(),
        cipher: cipher ? cipher.name : "Unknown",
        authorized: socket.authorized
      });

      socket.end();
    });

    socket.on("error", reject);

    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("TLS connection timed out"));
    });
  });
}


// ============================================================
// REDIRECTS
// ============================================================

async function checkRedirects(url) {
  const response = await fetch(url, {
    method: "GET",
    redirect: "manual"
  });

  return {
    status: response.status,
    location: response.headers.get("location") || "No redirect"
  };
}


// ============================================================
// ROBOTS.TXT
// ============================================================

async function getRobots(hostname) {

  const url = `https://${hostname}/robots.txt`;

  const response = await fetch(url);

  if (!response.ok) {
    return {
      exists: false,
      status: response.status
    };
  }

  return {
    exists: true,
    status: response.status,
    content: (await response.text()).slice(0, 3000)
  };
}


// ============================================================
// SECURITY.TXT
// ============================================================

async function getSecurityTxt(hostname) {

  const url =
    `https://${hostname}/.well-known/security.txt`;

  const response = await fetch(url);

  if (!response.ok) {
    return {
      exists: false,
      status: response.status
    };
  }

  return {
    exists: true,
    status: response.status,
    content: (await response.text()).slice(0, 3000)
  };
}


// ============================================================
// BASE64
// ============================================================

function base64Encode(text) {
  return Buffer
    .from(text, "utf8")
    .toString("base64");
}


function base64Decode(text) {
  return Buffer
    .from(text, "base64")
    .toString("utf8");
}


// ============================================================
// FILE HASHING
// ============================================================

async function fileHash(fileId, fileName, fileSize) {

  if (fileSize && fileSize > MAX_FILE_SIZE) {
    return {
      error: "File is larger than the 5 MB limit."
    };
  }

  const fileInfo = await telegram("getFile", {
    file_id: fileId
  });

  if (
    !fileInfo.ok ||
    !fileInfo.result ||
    !fileInfo.result.file_path
  ) {
    throw new Error("Unable to retrieve Telegram file.");
  }

  const filePath = fileInfo.result.file_path;

  const fileUrl =
    `https://api.telegram.org/file/bot${BOT_TOKEN}/${filePath}`;

  const response = await fetch(fileUrl);

  if (!response.ok) {
    throw new Error("Unable to download the file.");
  }

  const arrayBuffer = await response.arrayBuffer();
  const buffer = Buffer.from(arrayBuffer);

  if (buffer.length > MAX_FILE_SIZE) {
    return {
      error: "File exceeds the 5 MB safety limit."
    };
  }

  return {
    fileName,
    size: buffer.length,

    sha256: crypto
      .createHash("sha256")
      .update(buffer)
      .digest("hex"),

    sha512: crypto
      .createHash("sha512")
      .update(buffer)
      .digest("hex"),

    md5: crypto
      .createHash("md5")
      .update(buffer)
      .digest("hex")
  };
}


// ============================================================
// BASIC SECURITY HEADER ANALYSIS
// ============================================================

function analyzeSecurityHeaders(headers) {

  const recommended = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy"
  ];

  const present = [];
  const missing = [];

  for (const header of recommended) {

    if (headers[header]) {
      present.push(header);
    } else {
      missing.push(header);
    }
  }

  return {
    present,
    missing
  };
}


// ============================================================
// DOMAIN SECURITY SCAN
// ============================================================

async function performScan(hostname) {

  const result = {
    hostname,
    dns: null,
    tls: null,
    https: null
  };


  // DNS

  try {

    const records = await dnsLookup(hostname);

    result.dns =
      records.map(record => record.address);

  } catch {
    result.dns = [];
  }


  // TLS

  try {

    result.tls = await tlsInfo(hostname);

  } catch {

    result.tls = null;
  }


  // HTTPS + security headers

  try {

    const response =
      await httpsHeaders(`https://${hostname}`);

    const headerAnalysis =
      analyzeSecurityHeaders(response.headers);

    result.https = {
      status: response.status,
      headers: headerAnalysis
    };

  } catch {

    result.https = null;
  }

  return result;
}


// ============================================================
// COMMAND HANDLER
// ============================================================

async function handleCommand(message) {

  const chatId = message.chat.id;
  const text = message.text || "";

  registerUser(message);


  // ==========================================================
  // FILE UPLOAD
  // ==========================================================

  if (message.document) {

    logActivity(message, "FILE_HASH");

    try {

      const result = await fileHash(
        message.document.file_id,
        message.document.file_name || "unknown",
        message.document.file_size || 0
      );

      if (result.error) {
        return sendMessage(
          chatId,
          `❌ ${result.error}`
        );
      }

      return sendMessage(
        chatId,
        `📁 FILE HASH REPORT
━━━━━━━━━━━━━━━━

📄 File:
${result.fileName}

📦 Size:
${formatBytes(result.size)}

🔐 SHA-256
${result.sha256}

🔐 SHA-512
${result.sha512}

🔑 MD5
${result.md5}

━━━━━━━━━━━━━━━━
🛡️ CyberBot V4`
      );

    } catch (error) {

      return sendMessage(
        chatId,
        `❌ File hashing failed.

${error.message}`
      );
    }
  }


  if (!text.startsWith("/")) {
    return;
  }


  const command =
    text
      .split(/\s+/)[0]
      .toLowerCase()
      .split("@")[0];

  const arg = getArg(text);

  logActivity(message, command);


  // ==========================================================
  // START
  // ==========================================================

  if (command === "/start") {

    return sendMessage(
      chatId,
      `🛡️ CYBERBOT V4

Welcome.

Defensive cybersecurity toolkit for authorized security testing.

Use /help to view all commands.`
    );
  }


  // ==========================================================
  // HELP
  // ==========================================================

  if (command === "/help") {

    return sendMessage(
      chatId,
      `🛡️ CYBERBOT V4
━━━━━━━━━━━━━━━━

🌐 NETWORK
/dns example.com
/ip example.com
/tls example.com
/headers https://example.com
/scan example.com
/redirects https://example.com
/robots example.com
/securitytxt example.com
/urlcheck https://example.com

🔐 SECURITY
/password MyPassword123!
/generate 20
/hash hello world
/sha256 hello world

🔄 ENCODING
/base64 encode hello
/base64 decode aGVsbG8=

🧰 UTILITIES
/uuid
/timestamp

📁 FILE SECURITY
Send a file directly to the bot.

📡 MONITORING
/monitor example.com
/monitors
/unmonitor example.com

👨‍💼 ADMIN
/status
/users
/logs
/broadcast message

ℹ️ SYSTEM
/whoami
/help

━━━━━━━━━━━━━━━━

Only use security functions on systems and data you own or are authorized to assess.`
    );
  }


  // ==========================================================
  // WHOAMI
  // ==========================================================

  if (command === "/whoami") {

    return sendMessage(
      chatId,
      `👤 TELEGRAM IDENTITY
━━━━━━━━━━━━━━━━

ID:
${message.from.id}

Name:
${message.from.first_name || "Unknown"}

Username:
@${message.from.username || "none"}

Admin:
${isAdmin(message) ? "Yes" : "No"}`
    );
  }


  // ==========================================================
  // STATUS
  // ==========================================================

  if (command === "/status") {

    if (!isAdmin(message)) {
      return sendMessage(
        chatId,
        "⛔ Admin only."
      );
    }

    return sendMessage(
      chatId,
      `🛡️ CYBERBOT V4 STATUS
━━━━━━━━━━━━━━━━

🟢 Bot: Online
🟢 Telegram: Connected
🟢 DNS: Available
🟢 TLS: Available
🟢 File hashing: Enabled
🟢 Monitoring: Enabled
🟢 Logging: Enabled

Users:
${users.size}

Monitored domains:
${monitoredDomains.size}

Activity records:
${activityLogs.length}

Version:
4.0`
    );
  }


  // ==========================================================
  // DNS
  // ==========================================================

  if (command === "/dns") {

    if (!arg) {
      return sendMessage(
        chatId,
        "Usage:\n/dns example.com"
      );
    }

    try {

      const hostname =
        hostnameFromInput(arg);

      const records =
        await dnsLookup(hostname);

      let output =
        `🌐 DNS LOOKUP
━━━━━━━━━━━━━━━━

Domain:
${hostname}

`;

      for (const record of records) {

        output +=
          `${record.family === 6 ? "IPv6" : "IPv4"}: ${record.address}\n`;
      }

      return sendMessage(chatId, output);

    } catch {

      return sendMessage(
        chatId,
        "❌ DNS lookup failed."
      );
    }
  }


  // ==========================================================
  // IP
  // ==========================================================

  if (command === "/ip") {

    if (!arg) {
      return sendMessage(
        chatId,
        "Usage:\n/ip example.com"
      );
    }

    try {

      const hostname =
        hostnameFromInput(arg);

      const records =
        await dnsLookup(hostname);

      const addresses =
        [...new Set(
          records.map(record => record.address)
        )];

      return sendMessage(
        chatId,
        `📡 IP ADDRESS
━━━━━━━━━━━━━━━━

Host:
${hostname}

${addresses.join("\n")}`
      );

    } catch {

      return sendMessage(
        chatId,
        "❌ Could not resolve host."
      );
    }
  }


  // ==========================================================
  // TLS
  // ==========================================================

  if (command === "/tls") {

    if (!arg) {
      return sendMessage(
        chatId,
        "Usage:\n/tls example.com"
      );
    }

    try {

      const hostname =
        hostnameFromInput(arg);

      const info =
        await tlsInfo(hostname);

      return sendMessage(
        chatId,
        `🔐 TLS INFORMATION
━━━━━━━━━━━━━━━━

Host:
${hostname}

Protocol:
${info.protocol}

Cipher:
${info.cipher}

Certificate trusted:
${info.authorized ? "Yes" : "No"}`
      );

    } catch (error) {

      return sendMessage(
        chatId,
        `❌ TLS check failed.

${error.message}`
      );
    }
  }


  // ==========================================================
  // HEADERS
  // ==========================================================

  if (command === "/headers") {

    const url =
      normalizeUrl(arg);

    if (!url) {
      return sendMessage(
        chatId,
        "Usage:\n/headers https://example.com"
      );
    }

    try {

      const result =
        await httpsHeaders(url);

      let output =
        `📋 HTTP HEADERS
━━━━━━━━━━━━━━━━

Status:
${result.status} ${result.statusText}

`;

      for (
        const [key, value]
        of Object.entries(result.headers)
      ) {
        output += `${key}: ${value}\n`;
      }

      return sendMessage(
        chatId,
        output.slice(0, 4000)
      );

    } catch {

      return sendMessage(
        chatId,
        "❌ Unable to retrieve headers."
      );
    }
  }


  // ==========================================================
  // URL CHECK
  // ==========================================================

  if (command === "/urlcheck") {

    const url =
      normalizeUrl(arg);

    if (!url) {
      return sendMessage(
        chatId,
        "Usage:\n/urlcheck https://example.com"
      );
    }

    const parsed =
      new URL(url);

    return sendMessage(
      chatId,
      `🔎 URL ANALYSIS
━━━━━━━━━━━━━━━━

Protocol:
${parsed.protocol}

Hostname:
${parsed.hostname}

Port:
${parsed.port || "Default"}

Path:
${parsed.pathname}

Query:
${parsed.search || "None"}`
    );
  }


  // ==========================================================
  // REDIRECTS
  // ==========================================================

  if (command === "/redirects") {

    const url =
      normalizeUrl(arg);

    if (!url) {
      return sendMessage(
        chatId,
        "Usage:\n/redirects https://example.com"
      );
    }

    try {

      const result =
        await checkRedirects(url);

      return sendMessage(
        chatId,
        `↪️ REDIRECT CHECK
━━━━━━━━━━━━━━━━

Status:
${result.status}

Location:
${result.location}`
      );

    } catch {

      return sendMessage(
        chatId,
        "❌ Redirect check failed."
      );
    }
  }


  // ==========================================================
  // ROBOTS
  // ==========================================================

  if (command === "/robots") {

    if (!arg) {
      return sendMessage(
        chatId,
        "Usage:\n/robots example.com"
      );
    }

    try {

      const hostname =
        hostnameFromInput(arg);

      const result =
        await getRobots(hostname);

      if (!result.exists) {

        return sendMessage(
          chatId,
          `🤖 ROBOTS.TXT

Not found.

HTTP:
${result.status}`
        );
      }

      return sendMessage(
        chatId,
        `🤖 ROBOTS.TXT

${result.content}`
      );

    } catch {

      return sendMessage(
        chatId,
        "❌ Could not retrieve robots.txt."
      );
    }
  }


  // ==========================================================
  // SECURITY.TXT
  // ==========================================================

  if (command === "/securitytxt") {

    if (!arg) {
      return sendMessage(
        chatId,
        "Usage:\n/securitytxt example.com"
      );
    }

    try {

      const hostname =
        hostnameFromInput(arg);

      const result =
        await getSecurityTxt(hostname);

      if (!result.exists) {

        return sendMessage(
          chatId,
          `🔐 SECURITY.TXT

Not found.

HTTP:
${result.status}`
        );
      }

      return sendMessage(
        chatId,
        `🔐 SECURITY.TXT

${result.content}`
      );

    } catch {

      return sendMessage(
        chatId,
        "❌ Could not retrieve security.txt."
      );
    }
  }


  // ==========================================================
  // HASH
  // ==========================================================

  if (command === "/hash") {

    if (!arg) {

      return sendMessage(
        chatId,
        "Usage:\n/hash hello world"
      );
    }

    const result =
      hashText(arg);

    return sendMessage(
      chatId,
      `🔐 HASH REPORT
━━━━━━━━━━━━━━━━

SHA-256:
${result.sha256}

SHA-512:
${result.sha512}

MD5:
${result.md5}`
    );
  }


  // ==========================================================
  // SHA256
  // ==========================================================

  if (command === "/sha256") {

    if (!arg) {

      return sendMessage(
        chatId,
        "Usage:\n/sha256 hello world"
      );
    }

    return sendMessage(
      chatId,
      `🔐 SHA-256

${sha256Text(arg)}`
    );
  }


  // ==========================================================
  // PASSWORD
  // ==========================================================

  if (command === "/password") {

    if (!arg) {

      return sendMessage(
        chatId,
        "Usage:\n/password MyPassword123!"
      );
    }

    const result =
      passwordStrength(arg);

    return sendMessage(
      chatId,
      `🔐 PASSWORD CHECK
━━━━━━━━━━━━━━━━

Length:
${result.length}

Score:
${result.score}/6

Strength:
${result.strength}

Tip:
Use long, unique passwords and avoid reusing them.`
    );
  }


  // ==========================================================
  // GENERATE
  // ==========================================================

  if (command === "/generate") {

    const length =
      parseInt(arg, 10);

    if (
      !Number.isInteger(length) ||
      length < 8 ||
      length > 128
    ) {

      return sendMessage(
        chatId,
        "Usage:\n/generate 20\n\nLength must be between 8 and 128."
      );
    }

    const chars =
      "ABCDEFGHJKLMNPQRSTUVWXYZ" +
      "abcdefghijkmnopqrstuvwxyz" +
      "23456789" +
      "!@#$%^&*";

    let password = "";

    for (let i = 0; i < length; i++) {

      password +=
        chars[
          crypto.randomInt(0, chars.length)
        ];
    }

    return sendMessage(
      chatId,
      `🔑 GENERATED PASSWORD

${password}

Length:
${length}`
    );
  }


  // ==========================================================
  // BASE64
  // ==========================================================

  if (command === "/base64") {

    const parts =
      arg.split(/\s+/);

    if (parts.length < 2) {

      return sendMessage(
        chatId,
        `Usage:

/base64 encode hello

/base64 decode aGVsbG8=`
      );
    }

    const mode =
      parts.shift().toLowerCase();

    const value =
      parts.join(" ");

    try {

      if (mode === "encode") {

        return sendMessage(
          chatId,
          `🔄 BASE64 ENCODE

${base64Encode(value)}`
        );
      }


      if (mode === "decode") {

        return sendMessage(
          chatId,
          `🔄 BASE64 DECODE

${base64Decode(value)}`
        );
      }


      return sendMessage(
        chatId,
        "Use encode or decode."
      );

    } catch {

      return sendMessage(
        chatId,
        "❌ Base64 operation failed."
      );
    }
  }


  // ==========================================================
  // UUID
  // ==========================================================

  if (command === "/uuid") {

    return sendMessage(
      chatId,
      `🆔 UUID

${crypto.randomUUID()}`
    );
  }


  // ==========================================================
  // TIMESTAMP
  // ==========================================================

  if (command === "/timestamp") {

    const now =
      Date.now();

    return sendMessage(
      chatId,
      `🕐 TIMESTAMP

Unix:
${Math.floor(now / 1000)}

Milliseconds:
${now}

UTC:
${new Date(now).toISOString()}`
    );
  }


  // ==========================================================
  // SCAN
  // ==========================================================

  if (command === "/scan") {

    if (!arg) {

      return sendMessage(
        chatId,
        "Usage:\n/scan example.com"
      );
    }

    const hostname =
      hostnameFromInput(arg);

    const result =
      await performScan(hostname);


    const dnsOutput =
      result.dns?.length
        ? result.dns.join(", ")
        : "Failed";


    const tlsOutput =
      result.tls
        ? `${result.tls.protocol} / ${result.tls.cipher}`
        : "Failed";


    let httpsOutput =
      "Failed";


    if (result.https) {

      const count =
        result.https.headers.present.length;

      const total =
        count +
        result.https.headers.missing.length;

      httpsOutput =
        `HTTP ${result.https.status}\n` +
        `${count}/${total} common security headers present`;
    }


    return sendMessage(
      chatId,
      `🛡️ SECURITY REPORT
━━━━━━━━━━━━━━━━

🌐 Target
${hostname}

📡 DNS
${dnsOutput}

🔐 TLS
${tlsOutput}

🌍 HTTPS
${httpsOutput}

━━━━━━━━━━━━━━━━
Defensive assessment only.`
    );
  }


  // ==========================================================
  // MONITOR
  // ==========================================================

  if (command === "/monitor") {

    if (!isAdmin(message)) {

      return sendMessage(
        chatId,
        "⛔ Admin only."
      );
    }

    if (!arg) {

      return sendMessage(
        chatId,
        "Usage:\n/monitor example.com"
      );
    }

    const hostname =
      hostnameFromInput(arg);

    monitoredDomains.add(hostname);

    return sendMessage(
      chatId,
      `📡 MONITORING ENABLED

Target:
${hostname}

The domain has been added to your monitoring list.`
    );
  }


  // ==========================================================
  // MONITORS
  // ==========================================================

  if (command === "/monitors") {

    if (!isAdmin(message)) {

      return sendMessage(
        chatId,
        "⛔ Admin only."
      );
    }

    if (monitoredDomains.size === 0) {

      return sendMessage(
        chatId,
        "📡 No monitored domains."
      );
    }

    return sendMessage(
      chatId,
      `📡 MONITORED DOMAINS

${[...monitoredDomains]
  .map((domain, index) =>
    `${index + 1}. ${domain}`)
  .join("\n")}`
    );
  }


  // ==========================================================
  // UNMONITOR
  // ==========================================================

  if (command === "/unmonitor") {

    if (!isAdmin(message)) {

      return sendMessage(
        chatId,
        "⛔ Admin only."
      );
    }

    if (!arg) {

      return sendMessage(
        chatId,
        "Usage:\n/unmonitor example.com"
      );
    }

    const hostname =
      hostnameFromInput(arg);

    const removed =
      monitoredDomains.delete(hostname);

    return sendMessage(
      chatId,
      removed
        ? `🗑️ Removed ${hostname} from monitoring.`
        : `ℹ️ ${hostname} was not being monitored.`
    );
  }


  // ==========================================================
  // USERS
  // ==========================================================

  if (command === "/users") {

    if (!isAdmin(message)) {

      return sendMessage(
        chatId,
        "⛔ Admin only."
      );
    }

    return sendMessage(
      chatId,
      `👥 CYBERBOT USERS

Known users:
${users.size}`
    );
  }


  // ==========================================================
  // LOGS
  // ==========================================================

  if (command === "/logs") {

    if (!isAdmin(message)) {

      return sendMessage(
        chatId,
        "⛔ Admin only."
      );
    }

    if (activityLogs.length === 0) {

      return sendMessage(
        chatId,
        "📝 No activity logs yet."
      );
    }

    const recent =
      activityLogs
        .slice(-15)
        .reverse();

    let output =
      "📝 RECENT ACTIVITY\n━━━━━━━━━━━━━━━━\n\n";

    for (const log of recent) {

      output +=
        `${log.time}\n` +
        `User: ${log.userId}\n` +
        `Command: ${log.command}\n\n`;
    }

    return sendMessage(
      chatId,
      output.slice(0, 4000)
    );
  }


  // ==========================================================
  // BROADCAST
  // ==========================================================

  if (command === "/broadcast") {

    if (!isAdmin(message)) {

      return sendMessage(
        chatId,
        "⛔ Admin only."
      );
    }

    if (!arg) {

      return sendMessage(
        chatId,
        "Usage:\n/broadcast Your message here"
      );
    }

    let sent = 0;

    for (const user of users.values()) {

      try {

        await sendMessage(
          user.id,
          `📢 CYBERBOT ANNOUNCEMENT

${arg}`
        );

        sent++;

      } catch {
        // Ignore users who cannot receive messages.
      }
    }

    return sendMessage(
      chatId,
      `📢 Broadcast complete.

Sent:
${sent}

Known users:
${users.size}`
    );
  }


  // ==========================================================
  // UNKNOWN COMMAND
  // ==========================================================

  return sendMessage(
    chatId,
    `❓ Unknown command.

Use /help to see available commands.`
  );
}


// ============================================================
// NETLIFY HANDLER
// ============================================================

exports.handler = async (event) => {

  // Browser test
  if (event.httpMethod === "GET") {

    return {
      statusCode: 200,

      headers: {
        "content-type": "text/plain"
      },

      body: "CyberBot V4 is running."
    };
  }


  if (event.httpMethod !== "POST") {

    return {
      statusCode: 405,
      body: "Method Not Allowed"
    };
  }


  if (!BOT_TOKEN) {

    return {
      statusCode: 500,
      body: "TELEGRAM_BOT_TOKEN is not configured."
    };
  }


  try {

    const update =
      JSON.parse(event.body || "{}");

    if (update.message) {
      await handleCommand(update.message);
    }

    return {
      statusCode: 200,
      body: "OK"
    };

  } catch (error) {

    console.error(
      "CyberBot error:",
      error
    );

    // Always return 200 to Telegram
    // so it does not repeatedly retry
    // the webhook update.

    return {
      statusCode: 200,
      body: "OK"
    };
  }
};
