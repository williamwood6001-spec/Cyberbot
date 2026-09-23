const crypto = require("crypto");
const dns = require("dns").promises;
const tls = require("tls");

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const ADMIN_USER_ID = process.env.ADMIN_USER_ID || "";

const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;

async function telegram(method, body = {}) {
  const response = await fetch(`${TELEGRAM_API}/${method}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  return response.json();
}

async function sendMessage(chatId, text) {
  return telegram("sendMessage", {
    chat_id: chatId,
    text,
    parse_mode: "HTML"
  });
}

function isAdmin(userId) {
  return ADMIN_USER_ID && String(userId) === String(ADMIN_USER_ID);
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

async function dnsLookup(hostname) {
  try {
    const addresses = await dns.lookup(hostname, {
      all: true
    });

    return addresses;
  } catch (error) {
    return null;
  }
}

async function checkTls(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      443,
      hostname,
      {
        servername: hostname,
        timeout: 7000
      },
      () => {
        try {
          const certificate = socket.getPeerCertificate();

          resolve({
            authorized: socket.authorized,
            subject: certificate.subject || {},
            issuer: certificate.issuer || {},
            validFrom: certificate.valid_from,
            validTo: certificate.valid_to
          });

          socket.end();
        } catch (error) {
          resolve(null);
        }
      }
    );

    socket.on("error", () => {
      resolve(null);
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve(null);
    });
  });
}

async function getHeaders(url) {
  try {
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
      headers
    };
  } catch (error) {
    return null;
  }
}

async function analyzeUrl(url) {
  try {
    const parsed = new URL(url);

    const result = {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || "default",
      pathname: parsed.pathname || "/",
      secure: parsed.protocol === "https:"
    };

    return result;
  } catch (error) {
    return null;
  }
}

function generatePassword(length = 20) {
  const chars =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";

  let password = "";

  for (let i = 0; i < length; i++) {
    password += chars[crypto.randomInt(chars.length)];
  }

  return password;
}

function passwordStrength(password) {
  let score = 0;

  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  if (score <= 2) return "Weak";
  if (score <= 4) return "Medium";
  return "Strong";
}

async function websiteScan(hostname) {
  const cleanHost = hostname
    .replace(/^https?:\/\//i, "")
    .split("/")[0];

  const dnsResult = await dnsLookup(cleanHost);
  const tlsResult = await checkTls(cleanHost);

  let headersResult = null;

  try {
    headersResult = await getHeaders(`https://${cleanHost}`);
  } catch (error) {}

  let score = 0;
  const findings = [];

  if (dnsResult) {
    score += 20;
    findings.push("DNS resolution is working.");
  } else {
    findings.push("DNS resolution failed.");
  }

  if (tlsResult) {
    score += 30;
    findings.push("TLS/HTTPS connection is available.");
  } else {
    findings.push("Could not establish a TLS connection.");
  }

  if (headersResult) {
    score += 20;
    findings.push(`Website responded with HTTP ${headersResult.status}.`);

    const headers = headersResult.headers;

    if (headers["strict-transport-security"]) {
      score += 10;
      findings.push("HSTS header detected.");
    } else {
      findings.push("HSTS header was not detected.");
    }

    if (headers["content-security-policy"]) {
      score += 10;
      findings.push("Content-Security-Policy detected.");
    } else {
      findings.push("Content-Security-Policy was not detected.");
    }

    if (headers["x-content-type-options"]) {
      score += 5;
      findings.push("X-Content-Type-Options detected.");
    }

    if (headers["x-frame-options"]) {
      score += 5;
      findings.push("X-Frame-Options detected.");
    }
  }

  return {
    hostname: cleanHost,
    score,
    dns: dnsResult,
    tls: tlsResult,
    headers: headersResult,
    findings
  };
}

async function handleCommand(message) {
  if (!message || !message.chat) {
    return;
  }

  const chatId = message.chat.id;
  const userId = message.from ? message.from.id : "";
  const text = (message.text || "").trim();

  if (!text) {
    return;
  }

  const parts = text.split(/\s+/);
  const command = parts[0].toLowerCase();
  const argument = parts.slice(1).join(" ").trim();

  if (command === "/start") {
    await sendMessage(
      chatId,
      `<b>🛡 CyberBot is online</b>

Welcome to your defensive cybersecurity assistant.

Use /help to see the available commands.

⚠️ Only use security tools on systems you own or are authorized to test.`
    );

    return;
  }

  if (command === "/help") {
    await sendMessage(
      chatId,
      `<b>🛡 CyberBot Commands</b>

<b>Website / Network</b>
/dns example.com
/ip example.com
/tls example.com
/headers https://example.com
/scan example.com

<b>URL Analysis</b>
/urlcheck https://example.com

<b>Password Tools</b>
/password MyPassword123!
/generate 20

<b>Hashing</b>
/hash hello world

<b>Account</b>
/whoami

<b>Admin</b>
/status

Use these only for systems and data you are authorized to assess.`
    );

    return;
  }

  if (command === "/whoami") {
    await sendMessage(
      chatId,
      `<b>👤 Your Telegram Information</b>

User ID: <code>${escapeHtml(userId)}</code>
Chat ID: <code>${escapeHtml(chatId)}</code>
Name: <code>${escapeHtml(
        message.from?.first_name || "Unknown"
      )}</code>

Admin: ${isAdmin(userId) ? "Yes" : "No"}`
    );

    return;
  }

  if (command === "/hash") {
    if (!argument) {
      await sendMessage(
        chatId,
        "Usage:\n<code>/hash hello world</code>"
      );
      return;
    }

    const sha256 = crypto
      .createHash("sha256")
      .update(argument)
      .digest("hex");

    const sha512 = crypto
      .createHash("sha512")
      .update(argument)
      .digest("hex");

    const md5 = crypto
      .createHash("md5")
      .update(argument)
      .digest("hex");

    await sendMessage(
      chatId,
      `<b>🔐 Hash Result</b>

<b>Input:</b>
<code>${escapeHtml(argument)}</code>

<b>SHA-256:</b>
<code>${sha256}</code>

<b>SHA-512:</b>
<code>${sha512}</code>

<b>MD5:</b>
<code>${md5}</code>

SHA-256 is recommended for modern integrity checks.`
    );

    return;
  }

  if (command === "/password") {
    if (!argument) {
      await sendMessage(
        chatId,
        "Usage:\n<code>/password MyPassword123!</code>"
      );
      return;
    }

    const strength = passwordStrength(argument);

    await sendMessage(
      chatId,
      `<b>🔑 Password Security Check</b>

Length: ${argument.length}
Strength: <b>${strength}</b>

Uppercase: ${/[A-Z]/.test(argument) ? "Yes" : "No"}
Lowercase: ${/[a-z]/.test(argument) ? "Yes" : "No"}
Numbers: ${/[0-9]/.test(argument) ? "Yes" : "No"}
Special characters: ${
        /[^A-Za-z0-9]/.test(argument) ? "Yes" : "No"
      }

⚠️ Do not send real passwords or passwords you currently use.`
    );

    return;
  }

  if (command === "/generate") {
    let length = parseInt(argument, 10);

    if (!Number.isInteger(length)) {
      length = 20;
    }

    if (length < 8) length = 8;
    if (length > 100) length = 100;

    const password = generatePassword(length);

    await sendMessage(
      chatId,
      `<b>🔐 Generated Password</b>

Length: ${length}

<code>${password}</code>

Store it safely and never share it publicly.`
    );

    return;
  }

  if (command === "/dns" || command === "/ip") {
    if (!argument) {
      await sendMessage(
        chatId,
        `Usage:\n<code>${command} example.com</code>`
      );
      return;
    }

    const hostname = argument
      .replace(/^https?:\/\//i, "")
      .split("/")[0];

    const result = await dnsLookup(hostname);

    if (!result) {
      await sendMessage(
        chatId,
        `❌ Could not resolve <code>${escapeHtml(
          hostname
        )}</code>.`
      );
      return;
    }

    const addresses = result
      .map((item) => `${item.address} (${item.family})`)
      .join("\n");

    await sendMessage(
      chatId,
      `<b>🌐 DNS / IP Information</b>

Host:
<code>${escapeHtml(hostname)}</code>

Addresses:
<code>${escapeHtml(addresses)}</code>`
    );

    return;
  }

  if (command === "/tls") {
    if (!argument) {
      await sendMessage(
        chatId,
        "Usage:\n<code>/tls example.com</code>"
      );
      return;
    }

    const hostname = argument
      .replace(/^https?:\/\//i, "")
      .split("/")[0];

    const result = await checkTls(hostname);

    if (!result) {
      await sendMessage(
        chatId,
        `❌ Could not inspect TLS for <code>${escapeHtml(
          hostname
        )}</code>.`
      );
      return;
    }

    await sendMessage(
      chatId,
      `<b>🔒 TLS Certificate</b>

Host:
<code>${escapeHtml(hostname)}</code>

Authorized:
${result.authorized ? "Yes" : "No"}

Valid From:
${escapeHtml(result.validFrom || "Unknown")}

Valid To:
${escapeHtml(result.validTo || "Unknown")}

Issuer:
<code>${escapeHtml(
        result.issuer?.O || result.issuer?.CN || "Unknown"
      )}</code>`
    );

    return;
  }

  if (command === "/headers") {
    if (!argument) {
      await sendMessage(
        chatId,
        "Usage:\n<code>/headers https://example.com</code>"
      );
      return;
    }

    const result = await getHeaders(argument);

    if (!result) {
      await sendMessage(
        chatId,
        "❌ Could not retrieve the website headers."
      );
      return;
    }

    const interesting = [
      "strict-transport-security",
      "content-security-policy",
      "x-content-type-options",
      "x-frame-options",
      "referrer-policy",
      "permissions-policy",
      "server"
    ];

    let output = `<b>📋 HTTP Headers</b>

Status: <b>${result.status}</b>

`;

    for (const name of interesting) {
      if (result.headers[name]) {
        output += `${name}: <code>${escapeHtml(
          result.headers[name]
        )}</code>\n`;
      }
    }

    await sendMessage(chatId, output);

    return;
  }

  if (command === "/urlcheck") {
    if (!argument) {
      await sendMessage(
        chatId,
        "Usage:\n<code>/urlcheck https://example.com</code>"
      );
      return;
    }

    const result = await analyzeUrl(argument);

    if (!result) {
      await sendMessage(chatId, "❌ Invalid URL.");
      return;
    }

    await sendMessage(
      chatId,
      `<b>🔎 URL Analyzer</b>

Protocol:
<code>${escapeHtml(result.protocol)}</code>

Hostname:
<code>${escapeHtml(result.hostname)}</code>

Port:
<code>${escapeHtml(result.port)}</code>

Path:
<code>${escapeHtml(result.pathname)}</code>

HTTPS:
${result.secure ? "Yes 🔒" : "No ⚠️"}`
    );

    return;
  }

  if (command === "/scan") {
    if (!argument) {
      await sendMessage(
        chatId,
        "Usage:\n<code>/scan example.com</code>"
      );
      return;
    }

    await sendMessage(
      chatId,
      "🔎 Starting defensive website scan..."
    );

    const result = await websiteScan(argument);

    let report = `<b>🛡 Security Scan</b>

Target:
<code>${escapeHtml(result.hostname)}</code>

Score:
<b>${result.score}/100</b>

<b>Findings</b>
`;

    for (const finding of result.findings) {
      report += `• ${escapeHtml(finding)}\n`;
    }

    report += `

⚠️ This is a basic defensive check, not a full penetration test.`;

    await sendMessage(chatId, report);

    return;
  }

  if (command === "/status") {
    if (!isAdmin(userId)) {
      await sendMessage(
        chatId,
        "⛔ Admin access required."
      );
      return;
    }

    await sendMessage(
      chatId,
      `<b>🟢 CyberBot Status</b>

Bot: Online
Runtime: Netlify Functions
Node.js: Active
Telegram API: Connected
Security Mode: Defensive

Admin ID:
<code>${escapeHtml(ADMIN_USER_ID)}</code>`
    );

    return;
  }

  await sendMessage(
    chatId,
    `❓ Unknown command.

Use /help to see the available commands.`
  );
}

exports.handler = async function (event) {
  try {
    if (event.httpMethod !== "POST") {
      return {
        statusCode: 200,
        headers: {
          "Content-Type": "text/plain"
        },
        body: "CyberBot is running."
      };
    }

    if (!BOT_TOKEN) {
      return {
        statusCode: 500,
        body: "TELEGRAM_BOT_TOKEN is missing."
      };
    }

    const update = JSON.parse(event.body || "{}");

    if (update.message) {
      await handleCommand(update.message);
    }

    return {
      statusCode: 200,
      body: JSON.stringify({
        ok: true
      })
    };
  } catch (error) {
    console.error("CyberBot Error:", error);

    return {
      statusCode: 200,
      body: JSON.stringify({
        ok: false,
        error: error.message
      })
    };
  }
};
