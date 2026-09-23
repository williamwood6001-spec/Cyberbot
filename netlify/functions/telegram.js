import { Handler } from "@netlify/functions";
import crypto from "crypto";
import dns from "dns/promises";
import https from "https";
import http from "http";
import tls from "tls";
import { URL } from "url";

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const ADMIN_USER_ID = process.env.ADMIN_USER_ID;

const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;

async function telegram(method, data = {}) {
  const response = await fetch(`${TELEGRAM_API}/${method}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
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

function getArg(text) {
  return text.split(" ").slice(1).join(" ").trim();
}

function hostnameFromInput(input) {
  if (!input) throw new Error("No domain supplied.");

  let value = input.trim();

  if (!value.startsWith("http://") && !value.startsWith("https://")) {
    value = "https://" + value;
  }

  const url = new URL(value);

  if (!url.hostname) {
    throw new Error("Invalid domain.");
  }

  return url.hostname;
}

function normalizeUrl(input) {
  if (!input) throw new Error("No URL supplied.");

  let value = input.trim();

  if (!value.startsWith("http://") && !value.startsWith("https://")) {
    value = "https://" + value;
  }

  const url = new URL(value);

  return url;
}

async function dnsLookup(hostname) {
  const results = await dns.lookup(hostname, {
    all: true
  });

  return results.map(x => x.address);
}

function hashText(text) {
  return {
    SHA256: crypto
      .createHash("sha256")
      .update(text)
      .digest("hex"),

    SHA512: crypto
      .createHash("sha512")
      .update(text)
      .digest("hex"),

    MD5: crypto
      .createHash("md5")
      .update(text)
      .digest("hex")
  };
}

function passwordStrength(password) {
  let score = 0;
  const suggestions = [];

  if (password.length >= 8) score++;
  else suggestions.push("Use at least 8 characters.");

  if (password.length >= 12) score++;

  if (/[a-z]/.test(password)) score++;
  else suggestions.push("Add lowercase letters.");

  if (/[A-Z]/.test(password)) score++;
  else suggestions.push("Add uppercase letters.");

  if (/[0-9]/.test(password)) score++;
  else suggestions.push("Add numbers.");

  if (/[^A-Za-z0-9]/.test(password)) score++;
  else suggestions.push("Add symbols.");

  if (score <= 2) return ["🔴 Weak", suggestions];
  if (score <= 4) return ["🟡 Moderate", suggestions];

  return ["🟢 Strong", suggestions];
}

async function httpsHeaders(url) {
  const response = await fetch(url, {
    method: "GET",
    redirect: "follow",
    headers: {
      "User-Agent": "CyberBot-Defensive-Scanner/2.0"
    }
  });

  const headers = {};

  for (const [key, value] of response.headers.entries()) {
    headers[key.toLowerCase()] = value;
  }

  return {
    status: response.status,
    headers
  };
}

async function tlsInfo(hostname) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: true
      },
      () => {
        const result = {
          protocol: socket.getProtocol(),
          cipher: socket.getCipher()?.name || "Unknown"
        };

        socket.end();
        resolve(result);
      }
    );

    socket.setTimeout(10000);

    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("TLS connection timed out."));
    });

    socket.on("error", reject);
  });
}

async function handleCommand(message) {
  const chatId = message.chat.id;
  const text = message.text || "";
  const command = text.split(" ")[0].toLowerCase();
  const arg = getArg(text);

  try {

    if (command === "/start") {
      return sendMessage(
        chatId,
`🛡️ CYBERBOT v2

Defensive cybersecurity assistant.

🌐 NETWORK
/dns example.com
/ip example.com
/tls example.com

🛡️ WEB SECURITY
/headers https://example.com
/scan example.com

🔗 URL
/urlcheck https://example.com

🔐 SECURITY
/password Example123!
/generate 20

🔢 HASH
/hash hello world

👤 ACCOUNT
/whoami
/status

Use this only on systems you own
or are authorized to assess.`
      );
    }

    if (command === "/help") {
      return sendMessage(
        chatId,
`🛡️ CYBERBOT COMMANDS

/dns example.com
/ip example.com
/tls example.com
/headers https://example.com
/scan example.com
/urlcheck https://example.com
/hash hello world
/password Example123!
/generate 20
/whoami
/status`
      );
    }

    if (command === "/whoami") {
      const user = message.from;

      return sendMessage(
        chatId,
`👤 TELEGRAM INFORMATION

Name: ${user.first_name || ""}
Username: ${user.username ? "@" + user.username : "None"}
User ID: ${user.id}`
      );
    }

    if (command === "/dns") {
      const hostname = hostnameFromInput(arg);
      const addresses = await dnsLookup(hostname);

      return sendMessage(
        chatId,
`🌐 DNS LOOKUP

Domain: ${hostname}

${addresses.map(x => "• " + x).join("\n")}`
      );
    }

    if (command === "/ip") {
      const hostname = hostnameFromInput(arg);
      const addresses = await dnsLookup(hostname);

      return sendMessage(
        chatId,
`🌐 IP INFORMATION

Host: ${hostname}

IPv4/IPv6:
${addresses.map(x => "• " + x).join("\n")}`
      );
    }

    if (command === "/tls") {
      const hostname = hostnameFromInput(arg);
      const info = await tlsInfo(hostname);

      return sendMessage(
        chatId,
`🔐 TLS CHECK

Host: ${hostname}

Protocol: ${info.protocol}
Cipher: ${info.cipher}

✅ TLS connection succeeded.`
      );
    }

    if (command === "/headers") {
      const url = normalizeUrl(arg);
      const result = await httpsHeaders(url.toString());

      const checks = [
        ["strict-transport-security", "HSTS"],
        ["content-security-policy", "CSP"],
        ["x-content-type-options", "X-Content-Type-Options"],
        ["x-frame-options", "X-Frame-Options"],
        ["referrer-policy", "Referrer-Policy"],
        ["permissions-policy", "Permissions-Policy"]
      ];

      let output =
`🛡️ SECURITY HEADERS

URL: ${url}

HTTP Status: ${result.status}

`;

      for (const [header, label] of checks) {
        output += result.headers[header]
          ? `✅ ${label}\n`
          : `⚠️ ${label} not detected\n`;
      }

      return sendMessage(chatId, output);
    }

    if (command === "/urlcheck") {
      const url = normalizeUrl(arg);

      let output =
`🔗 URL ANALYSIS

Scheme: ${url.protocol.replace(":", "")}
Hostname: ${url.hostname}
Port: ${url.port || "default"}
Username: ${url.username ? "⚠️ Present" : "None"}
Password: ${url.password ? "⚠️ Present" : "None"}

`;

      output += url.protocol === "https:"
        ? "✅ HTTPS is being used."
        : "⚠️ URL is not using HTTPS.";

      return sendMessage(chatId, output);
    }

    if (command === "/hash") {
      if (!arg) {
        return sendMessage(chatId, "Usage:\n/hash hello world");
      }

      const hashes = hashText(arg);

      return sendMessage(
        chatId,
`🔢 HASH RESULTS

Input: ${arg}

SHA-256:
${hashes.SHA256}

SHA-512:
${hashes.SHA512}

MD5:
${hashes.MD5}`
      );
    }

    if (command === "/password") {
      if (!arg) {
        return sendMessage(
          chatId,
          "Usage:\n/password Example123!\n\n⚠️ Don't send a real password."
        );
      }

      const [rating, suggestions] = passwordStrength(arg);

      let output =
`🔐 PASSWORD CHECK

Strength: ${rating}
Length: ${arg.length} characters
`;

      if (suggestions.length) {
        output += "\nSuggestions:\n";
        output += suggestions.map(x => "• " + x).join("\n");
      }

      output +=
`\n\n⚠️ Basic strength check only.
Do not use this as a password auditor.`;

      return sendMessage(chatId, output);
    }

    if (command === "/generate") {
      let length = parseInt(arg || "20", 10);

      if (Number.isNaN(length)) length = 20;

      length = Math.max(12, Math.min(length, 64));

      const alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
        "abcdefghijklmnopqrstuvwxyz" +
        "0123456789" +
        "!@#$%^&*_-+=";

      let password = "";

      for (let i = 0; i < length; i++) {
        password += alphabet[
          crypto.randomInt(0, alphabet.length)
        ];
      }

      return sendMessage(
        chatId,
`🔐 GENERATED PASSWORD

${password}

Length: ${length}

Store it in a password manager.`
      );
    }

    if (command === "/status") {
      if (
        !ADMIN_USER_ID ||
        String(message.from.id) !== String(ADMIN_USER_ID)
      ) {
        return sendMessage(chatId, "⛔ Admin command.");
      }

      return sendMessage(
        chatId,
`🟢 CYBERBOT STATUS

Bot: Online
Version: 2.0
Platform: Netlify Functions
Mode: Webhook`
      );
    }

    if (command === "/scan") {
      const hostname = hostnameFromInput(arg);

      await sendMessage(
        chatId,
        `🔎 Checking ${hostname}...`
      );

      let dnsResult = "❌ DNS failed";
      let ip = "";

      try {
        const addresses = await dnsLookup(hostname);
        ip = addresses[0];
        dnsResult = `✅ DNS resolved\nIP: ${addresses.join(", ")}`;
      } catch {}

      let tlsResult = "❌ TLS failed";

      try {
        const info = await tlsInfo(hostname);
        tlsResult =
          `✅ TLS: ${info.protocol}\nCipher: ${info.cipher}`;
      } catch {}

      let headerResult = "";

      try {
        const result = await httpsHeaders(
          `https://${hostname}`
        );

        const checks = [
          ["strict-transport-security", "HSTS"],
          ["content-security-policy", "CSP"],
          ["x-content-type-options", "X-Content-Type-Options"],
          ["x-frame-options", "X-Frame-Options"]
        ];

        for (const [header, label] of checks) {
          headerResult += result.headers[header]
            ? `✅ ${label}\n`
            : `⚠️ ${label} missing\n`;
        }
      } catch {
        headerResult = "⚠️ HTTPS headers unavailable";
      }

      return sendMessage(
        chatId,
`🛡️ CYBERBOT SECURITY REPORT

🎯 Target
${hostname}

🌐 DNS
${dnsResult}

🔐 TLS
${tlsResult}

🧱 SECURITY HEADERS
${headerResult}

ℹ️ This is a basic defensive
configuration check.`
      );
    }

    return sendMessage(
      chatId,
      "❓ Unknown command.\n\nUse /help"
    );

  } catch (error) {
    return sendMessage(
      chatId,
      `❌ Error:\n${error.message}`
    );
  }
}

export const handler = async (event) => {

  if (event.httpMethod !== "POST") {
    return {
      statusCode: 200,
      body: "CyberBot is running."
    };
  }

  if (!BOT_TOKEN) {
    return {
      statusCode: 500,
      body: "TELEGRAM_BOT_TOKEN is not configured."
    };
  }

  try {
    const update = JSON.parse(event.body);

    if (update.message) {
      await handleCommand(update.message);
    }

    return {
      statusCode: 200,
      body: "OK"
    };

  } catch (error) {
    console.error(error);

    return {
      statusCode: 500,
      body: "Internal error"
    };
  }
};
