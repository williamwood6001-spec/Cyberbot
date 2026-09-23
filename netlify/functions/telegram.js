const crypto = require("crypto");
const dns = require("dns").promises;
const tls = require("tls");

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const ADMIN_USER_ID = process.env.ADMIN_USER_ID || "";

const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;

/*
========================================================
CYBERBOT V5
V2 + V3 + V4 MERGED
Defensive Cybersecurity Telegram Bot
========================================================

IMPORTANT:
Only use this bot on systems/domains you own or are
authorized to assess.

This bot does NOT perform:
- credential theft
- brute forcing
- exploitation
- malware deployment
- unauthorized access
========================================================
*/


/* ======================================================
   BASIC TELEGRAM FUNCTIONS
====================================================== */

async function telegram(method, body = {}) {
  if (!BOT_TOKEN) {
    throw new Error("TELEGRAM_BOT_TOKEN is missing.");
  }

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
    parse_mode: "HTML",
    disable_web_page_preview: true
  });
}


function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}


function isAdmin(userId) {
  if (!ADMIN_USER_ID) {
    return false;
  }

  return String(userId) === String(ADMIN_USER_ID);
}


/* ======================================================
   USER / ACTIVITY MEMORY
====================================================== */

/*
These Maps work during the lifetime of a serverless
instance.

IMPORTANT:
Netlify Functions are serverless, so this is NOT permanent
database storage.

It is intentionally kept lightweight for this version.
*/

const users = new Map();
const activityLogs = [];

function registerUser(message) {
  if (!message || !message.from) {
    return;
  }

  const userId = String(message.from.id);

  users.set(userId, {
    id: userId,
    firstName: message.from.first_name || "",
    lastName: message.from.last_name || "",
    username: message.from.username || "",
    lastSeen: new Date().toISOString()
  });
}


function logActivity(message, command) {
  if (!message || !message.from) {
    return;
  }

  activityLogs.push({
    userId: String(message.from.id),
    username: message.from.username || "",
    command,
    time: new Date().toISOString()
  });

  // Keep memory under control.
  if (activityLogs.length > 500) {
    activityLogs.shift();
  }
}


/* ======================================================
   DNS / IP
====================================================== */

async function dnsLookup(hostname) {
  try {
    return await dns.lookup(hostname, {
      all: true
    });
  } catch {
    return null;
  }
}


/* ======================================================
   TLS CERTIFICATE CHECK
====================================================== */

async function checkTLS(hostname) {
  return new Promise((resolve) => {
    let finished = false;

    const finish = (result) => {
      if (finished) return;

      finished = true;
      resolve(result);
    };

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

          finish({
            authorized: socket.authorized,
            subject: certificate.subject || {},
            issuer: certificate.issuer || {},
            validFrom: certificate.valid_from || "Unknown",
            validTo: certificate.valid_to || "Unknown"
          });
        } catch {
          finish(null);
        }

        socket.end();
      }
    );

    socket.on("error", () => {
      finish(null);
    });

    socket.on("timeout", () => {
      socket.destroy();
      finish(null);
    });
  });
}


/* ======================================================
   HTTP HEADERS
====================================================== */

async function getHeaders(url) {
  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "manual"
    });

    const headers = {};

    for (const [key, value] of response.headers.entries()) {
      headers[key.toLowerCase()] = value;
    }

    return {
      status: response.status,
      headers
    };
  } catch {
    return null;
  }
}


/* ======================================================
   HOSTNAME CLEANER
====================================================== */

function cleanHostname(value) {
  return String(value)
    .replace(/^https?:\/\//i, "")
    .split("/")[0]
    .split("?")[0]
    .split("#")[0]
    .trim();
}


/* ======================================================
   URL ANALYZER
====================================================== */

function analyzeURL(value) {
  try {
    const url = new URL(value);

    return {
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || "default",
      pathname: url.pathname || "/",
      search: url.search || "",
      hash: url.hash || "",
      https: url.protocol === "https:"
    };
  } catch {
    return null;
  }
}


/* ======================================================
   PASSWORD STRENGTH
====================================================== */

function passwordStrength(password) {
  let score = 0;

  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;

  if (/[a-z]/.test(password)) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  if (score <= 2) return "Weak";
  if (score <= 4) return "Medium";
  if (score <= 6) return "Strong";

  return "Very Strong";
}


/* ======================================================
   SECURE PASSWORD GENERATOR
====================================================== */

function generatePassword(length = 20) {
  const characters =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";

  let result = "";

  for (let i = 0; i < length; i++) {
    result += characters[crypto.randomInt(characters.length)];
  }

  return result;
}


/* ======================================================
   TEXT HASHING
====================================================== */

function createHashes(text) {
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


/* ======================================================
   TELEGRAM FILE HASHING
====================================================== */

async function hashTelegramFile(fileId) {
  try {
    const fileInfo = await telegram("getFile", {
      file_id: fileId
    });

    if (!fileInfo.ok || !fileInfo.result?.file_path) {
      return null;
    }

    const filePath = fileInfo.result.file_path;

    const fileResponse = await fetch(
      `https://api.telegram.org/file/bot${BOT_TOKEN}/${filePath}`
    );

    if (!fileResponse.ok) {
      return null;
    }

    const arrayBuffer = await fileResponse.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    // Safety limit: 5 MB.
    if (buffer.length > 5 * 1024 * 1024) {
      return {
        tooLarge: true,
        size: buffer.length
      };
    }

    return {
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
  } catch {
    return null;
  }
}


/* ======================================================
   SECURITY HEADER ANALYSIS
====================================================== */

function analyzeSecurityHeaders(headers) {
  const checks = [];

  const securityHeaders = [
    {
      key: "strict-transport-security",
      name: "HSTS"
    },
    {
      key: "content-security-policy",
      name: "Content-Security-Policy"
    },
    {
      key: "x-content-type-options",
      name: "X-Content-Type-Options"
    },
    {
      key: "x-frame-options",
      name: "X-Frame-Options"
    },
    {
      key: "referrer-policy",
      name: "Referrer-Policy"
    },
    {
      key: "permissions-policy",
      name: "Permissions-Policy"
    }
  ];

  for (const item of securityHeaders) {
    checks.push({
      name: item.name,
      present: Boolean(headers[item.key]),
      value: headers[item.key] || null
    });
  }

  return checks;
}


/* ======================================================
   WEBSITE SECURITY SCAN
====================================================== */

async function websiteScan(target) {
  const hostname = cleanHostname(target);

  const result = {
    hostname,
    score: 0,
    findings: [],
    dns: null,
    tls: null,
    headers: null
  };

  /* DNS */

  result.dns = await dnsLookup(hostname);

  if (result.dns) {
    result.score += 20;

    result.findings.push(
      "✅ DNS resolution is working."
    );
  } else {
    result.findings.push(
      "⚠️ DNS resolution failed."
    );
  }


  /* TLS */

  result.tls = await checkTLS(hostname);

  if (result.tls) {
    result.score += 30;

    if (result.tls.authorized) {
      result.findings.push(
        "✅ TLS certificate is authorized."
      );
    } else {
      result.findings.push(
        "⚠️ TLS connection was established, but certificate authorization could not be confirmed."
      );
    }
  } else {
    result.findings.push(
      "❌ TLS connection could not be established."
    );
  }


  /* HTTP */

  result.headers = await getHeaders(
    `https://${hostname}`
  );

  if (result.headers) {
    result.score += 20;

    result.findings.push(
      `✅ Website responded with HTTP ${result.headers.status}.`
    );

    const checks = analyzeSecurityHeaders(
      result.headers.headers
    );

    for (const check of checks) {
      if (check.present) {
        result.score += 5;

        result.findings.push(
          `✅ ${check.name} detected.`
        );
      } else {
        result.findings.push(
          `⚠️ ${check.name} was not detected.`
        );
      }
    }

    // Cap score.
    if (result.score > 100) {
      result.score = 100;
    }
  } else {
    result.findings.push(
      "⚠️ HTTPS request could not be completed."
    );
  }

  return result;
}


/* ======================================================
   HELP
====================================================== */

async function showHelp(chatId) {
  await sendMessage(
    chatId,
    `<b>🛡 CYBERBOT V5</b>

<b>🌐 Network</b>

/dns example.com
/ip example.com
/tls example.com
/headers https://example.com

<b>🔎 Website Security</b>

/scan example.com
/urlcheck https://example.com

<b>🔐 Password Tools</b>

/password Example123!
/generate 20

<b>#️⃣ Hashing</b>

/hash hello world

<b>📁 File Hashing</b>

Send a file/document to the bot with the caption:
/filehash

<b>👤 Account</b>

/whoami

<b>👑 Admin</b>

/status
/users
/logs
/broadcast your message

<b>🚨 Monitoring</b>

/monitor example.com
/monitors

<b>ℹ️ System</b>

/help
/start

⚠️ <b>Defensive use only.</b>
Only assess systems and data you own or are authorized to test.`
  );
}


/* ======================================================
   COMMAND HANDLER
====================================================== */

async function handleCommand(message) {
  if (!message || !message.chat) {
    return;
  }

  registerUser(message);

  const chatId = message.chat.id;
  const userId = message.from?.id || "";

  const text = (message.text || "").trim();

  if (!text) {
    return;
  }

  const parts = text.split(/\s+/);

  const command = parts[0].toLowerCase();

  const argument = parts
    .slice(1)
    .join(" ")
    .trim();

  logActivity(message, command);


  /* START */

  if (command === "/start") {
    await sendMessage(
      chatId,
      `<b>🛡 CyberBot V5 is online.</b>

Your defensive cybersecurity assistant is ready.

Use /help to view all commands.`
    );

    return;
  }


  /* HELP */

  if (command === "/help") {
    await showHelp(chatId);
    return;
  }


  /* WHOAMI */

  if (command === "/whoami") {
    await sendMessage(
      chatId,
      `<b>👤 Telegram Information</b>

User ID:
<code>${escapeHtml(userId)}</code>

Chat ID:
<code>${escapeHtml(chatId)}</code>

Name:
<code>${escapeHtml(
        message.from?.first_name || "Unknown"
      )}</code>

Username:
<code>${escapeHtml(
        message.from?.username
          ? "@" + message.from.username
          : "None"
      )}</code>

Admin:
${isAdmin(userId) ? "✅ Yes" : "❌ No"}`
    );

    return;
  }


  /* DNS */

  if (
    command === "/dns" ||
    command === "/ip"
  ) {
    if (!argument) {
      await sendMessage(
        chatId,
        `Usage:\n<code>${command} example.com</code>`
      );

      return;
    }

    const hostname = cleanHostname(argument);

    const addresses = await dnsLookup(hostname);

    if (!addresses) {
      await sendMessage(
        chatId,
        `❌ Could not resolve <code>${escapeHtml(
          hostname
        )}</code>.`
      );

      return;
    }

    const output = addresses
      .map(
        (item) =>
          `${item.address} (IPv${item.family})`
      )
      .join("\n");

    await sendMessage(
      chatId,
      `<b>🌐 DNS / IP Result</b>

Host:
<code>${escapeHtml(hostname)}</code>

Addresses:
<code>${escapeHtml(output)}</code>`
    );

    return;
  }


  /* TLS */

  if (command === "/tls") {
    if (!argument) {
      await sendMessage(
        chatId,
        "Usage:\n<code>/tls example.com</code>"
      );

      return;
    }

    const hostname = cleanHostname(argument);

    const result = await checkTLS(hostname);

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
${result.authorized ? "✅ Yes" : "⚠️ No"}

Valid From:
<code>${escapeHtml(result.validFrom)}</code>

Valid To:
<code>${escapeHtml(result.validTo)}</code>

Issuer:
<code>${escapeHtml(
        result.issuer?.O ||
          result.issuer?.CN ||
          "Unknown"
      )}</code>`
    );

    return;
  }


  /* HEADERS */

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

    const checks = analyzeSecurityHeaders(
      result.headers
    );

    let output = `<b>📋 HTTP Security Headers</b>

HTTP Status:
<b>${result.status}</b>

`;

    for (const check of checks) {
      output += `${check.present ? "✅" : "⚠️"} ${
        check.name
      }\n`;

      if (check.present) {
        output += `<code>${escapeHtml(
          check.value
        )}</code>\n`;
      }

      output += "\n";
    }

    await sendMessage(chatId, output);

    return;
  }


  /* URL CHECK */

  if (command === "/urlcheck") {
    if (!argument) {
      await sendMessage(
        chatId,
        "Usage:\n<code>/urlcheck https://example.com</code>"
      );

      return;
    }

    const result = analyzeURL(argument);

    if (!result) {
      await sendMessage(
        chatId,
        "❌ Invalid URL."
      );

      return;
    }

    await sendMessage(
      chatId,
      `<b>🔎 URL Analysis</b>

Protocol:
<code>${escapeHtml(result.protocol)}</code>

Hostname:
<code>${escapeHtml(result.hostname)}</code>

Port:
<code>${escapeHtml(result.port)}</code>

Path:
<code>${escapeHtml(result.pathname)}</code>

Query:
<code>${escapeHtml(result.search || "None")}</code>

HTTPS:
${result.https ? "✅ Yes" : "⚠️ No"}`
    );

    return;
  }


  /* HASH */

  if (command === "/hash") {
    if (!argument) {
      await sendMessage(
        chatId,
        "Usage:\n<code>/hash hello world</code>"
      );

      return;
    }

    const hashes = createHashes(argument);

    await sendMessage(
      chatId,
      `<b>#️⃣ Hash Results</b>

Input:
<code>${escapeHtml(argument)}</code>

<b>SHA-256</b>
<code>${hashes.sha256}</code>

<b>SHA-512</b>
<code>${hashes.sha512}</code>

<b>MD5</b>
<code>${hashes.md5}</code>

ℹ️ SHA-256 is preferred for modern integrity checking.`
    );

    return;
  }


  /* PASSWORD CHECK */

  if (command === "/password") {
    if (!argument) {
      await sendMessage(
        chatId,
        "Usage:\n<code>/password Example123!</code>"
      );

      return;
    }

    const strength =
      passwordStrength(argument);

    await sendMessage(
      chatId,
      `<b>🔐 Password Security Check</b>

Length:
<b>${argument.length}</b>

Strength:
<b>${strength}</b>

Lowercase:
${/[a-z]/.test(argument) ? "✅" : "❌"}

Uppercase:
${/[A-Z]/.test(argument) ? "✅" : "❌"}

Numbers:
${/[0-9]/.test(argument) ? "✅" : "❌"}

Special characters:
${
        /[^A-Za-z0-9]/.test(argument)
          ? "✅"
          : "❌"
      }

⚠️ Never send passwords you actually use.`
    );

    return;
  }


  /* PASSWORD GENERATOR */

  if (command === "/generate") {
    let length = parseInt(argument, 10);

    if (!Number.isInteger(length)) {
      length = 20;
    }

    if (length < 8) {
      length = 8;
    }

    if (length > 100) {
      length = 100;
    }

    const password =
      generatePassword(length);

    await sendMessage(
      chatId,
      `<b>🔑 Secure Password Generated</b>

Length:
${length}

<code>${password}</code>

Store it securely.`
    );

    return;
  }


  /* WEBSITE SCAN */

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
      "🔎 <b>Starting defensive scan...</b>\n\nPlease wait."
    );

    const result =
      await websiteScan(argument);

    let report = `<b>🛡 WEBSITE SECURITY REPORT</b>

Target:
<code>${escapeHtml(result.hostname)}</code>

Score:
<b>${result.score}/100</b>

<b>Findings</b>
`;

    for (const finding of result.findings) {
      report += `\n${escapeHtml(finding)}`;
    }

    report += `

⚠️ This is a basic defensive assessment, not a full penetration test.`;

    await sendMessage(chatId, report);

    return;
  }


  /* FILE HASHING */

  if (command === "/filehash") {
    await sendMessage(
      chatId,
      "📁 Send the file/document you want to hash and use <code>/filehash</code> as its caption."
    );

    return;
  }


  /* ADMIN STATUS */

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
      `<b>🟢 CYBERBOT STATUS</b>

Bot:
✅ Online

Telegram API:
✅ Connected

Runtime:
Netlify Functions

Security Mode:
🛡 Defensive

Tracked users in current instance:
<b>${users.size}</b>

Activity records:
<b>${activityLogs.length}</b>

Admin:
<code>${escapeHtml(
        ADMIN_USER_ID
      )}</code>`
    );

    return;
  }


  /* ADMIN USERS */

  if (command === "/users") {
    if (!isAdmin(userId)) {
      await sendMessage(
        chatId,
        "⛔ Admin access required."
      );

      return;
    }

    if (users.size === 0) {
      await sendMessage(
        chatId,
        "👥 No users tracked in this server instance."
      );

      return;
    }

    let output = "<b>👥 Users</b>\n\n";

    let count = 0;

    for (const user of users.values()) {
      count++;

      output += `${count}. `;

      if (user.username) {
        output += `@${escapeHtml(user.username)}`;
      } else {
        output += escapeHtml(
          user.firstName || "Unknown"
        );
      }

      output += `\nID: <code>${escapeHtml(
        user.id
      )}</code>\n\n`;

      if (count >= 20) {
        break;
      }
    }

    await sendMessage(chatId, output);

    return;
  }


  /* ADMIN LOGS */

  if (command === "/logs") {
    if (!isAdmin(userId)) {
      await sendMessage(
        chatId,
        "⛔ Admin access required."
      );

      return;
    }

    if (activityLogs.length === 0) {
      await sendMessage(
        chatId,
        "📝 No activity logs available."
      );

      return;
    }

    const recent =
      activityLogs.slice(-15).reverse();

    let output =
      "<b>📝 Recent Activity</b>\n\n";

    for (const item of recent) {
      output += `👤 ${escapeHtml(
        item.username || item.userId
      )}\n`;

      output += `Command: <code>${escapeHtml(
        item.command
      )}</code>\n`;

      output += `${escapeHtml(
        item.time
      )}\n\n`;
    }

    await sendMessage(chatId, output);

    return;
  }


  /* ADMIN BROADCAST */

  if (command === "/broadcast") {
    if (!isAdmin(userId)) {
      await sendMessage(
        chatId,
        "⛔ Admin access required."
      );

      return;
    }

    if (!argument) {
      await sendMessage(
        chatId,
        "Usage:\n<code>/broadcast Your message</code>"
      );

      return;
    }

    let sent = 0;
    let failed = 0;

    for (const user of users.values()) {
      try {
        await sendMessage(
          user.id,
          `<b>📢 Admin Message</b>\n\n${escapeHtml(
            argument
          )}`
        );

        sent++;
      } catch {
        failed++;
      }
    }

    await sendMessage(
      chatId,
      `<b>📢 Broadcast Complete</b>

Sent:
${sent}

Failed:
${failed}`
    );

    return;
  }


  /* MONITOR */

  if (command === "/monitor") {
    if (!isAdmin(userId)) {
      await sendMessage(
        chatId,
        "⛔ Admin access required."
      );

      return;
    }

    if (!argument) {
      await sendMessage(
        chatId,
        "Usage:\n<code>/monitor example.com</code>"
      );

      return;
    }

    /*
    This performs an immediate defensive check.
    Persistent scheduled monitoring requires external
    storage/scheduling and is intentionally not faked here.
    */

    await sendMessage(
      chatId,
      `🔎 Monitoring check started for:

<code>${escapeHtml(
        cleanHostname(argument)
      )}</code>`
    );

    const result =
      await websiteScan(argument);

    await sendMessage(
      chatId,
      `<b>🚨 Monitoring Result</b>

Target:
<code>${escapeHtml(result.hostname)}</code>

Security score:
<b>${result.score}/100</b>

Status:
${result.headers ? "🟢 Responding" : "🔴 Not responding"}`
    );

    return;
  }


  /* MONITORS */

  if (command === "/monitors") {
    if (!isAdmin(userId)) {
      await sendMessage(
        chatId,
        "⛔ Admin access required."
      );

      return;
    }

    await sendMessage(
      chatId,
      `<b>🚨 Monitoring</b>

No persistent monitors are configured yet.

The current <code>/monitor</code> command performs an immediate defensive check.

Persistent scheduled monitoring will be added with proper storage/scheduling rather than temporary serverless memory.`
    );

    return;
  }


  /* UNKNOWN COMMAND */

  await sendMessage(
    chatId,
    `❓ Unknown command.

Use /help to see all available commands.`
  );
}


/* ======================================================
   TELEGRAM UPDATE HANDLER
====================================================== */

exports.handler = async function (event) {
  try {
    /*
    Browser GET request.
    */

    if (event.httpMethod !== "POST") {
      return {
        statusCode: 200,
        headers: {
          "Content-Type": "text/plain"
        },
        body: "CyberBot V5 is running."
      };
    }


    if (!BOT_TOKEN) {
      console.error(
        "TELEGRAM_BOT_TOKEN is missing."
      );

      return {
        statusCode: 500,
        body: "TELEGRAM_BOT_TOKEN is missing."
      };
    }


    const update = JSON.parse(
      event.body || "{}"
    );


    /*
    Normal Telegram message.
    */

    if (update.message) {
      /*
      File/document handling.
      */

      if (
        update.message.document &&
        update.message.caption === "/filehash"
      ) {
        const chatId =
          update.message.chat.id;

        await sendMessage(
          chatId,
          "🔐 Downloading file and calculating hashes..."
        );

        const result =
          await hashTelegramFile(
            update.message.document.file_id
          );

        if (!result) {
          await sendMessage(
            chatId,
            "❌ Could not process the file."
          );
        } else if (result.tooLarge) {
          await sendMessage(
            chatId,
            "⚠️ File is larger than the 5 MB safety limit."
          );
        } else {
          await sendMessage(
            chatId,
            `<b>📁 FILE HASH REPORT</b>

File:
<code>${escapeHtml(
              update.message.document.file_name ||
                "Unknown"
            )}</code>

Size:
${result.size} bytes

<b>SHA-256</b>
<code>${result.sha256}</code>

<b>SHA-512</b>
<code>${result.sha512}</code>

<b>MD5</b>
<code>${result.md5}</code>

SHA-256 is recommended for modern integrity verification.`
          );
        }

        return {
          statusCode: 200,
          body: JSON.stringify({
            ok: true
          })
        };
      }


      /*
      Normal commands.
      */

      await handleCommand(
        update.message
      );
    }


    return {
      statusCode: 200,
      body: JSON.stringify({
        ok: true
      })
    };
  } catch (error) {
    console.error(
      "CyberBot V5 error:",
      error
    );

    /*
    Return HTTP 200 to Telegram so Telegram doesn't
    repeatedly retry the same update.
    */

    return {
      statusCode: 200,
      body: JSON.stringify({
        ok: false
      })
    };
  }
};
