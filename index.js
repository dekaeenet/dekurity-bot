const { default: makeWASocket, useSingleFileAuthState, DisconnectReason } = require('@adiwajshing/baileys')
const axios = require('axios')
const crypto = require('crypto')
const dns = require('dns').promises
const whois = require('whois')
const sslChecker = require('ssl-checker')
const portscanner = require('portscanner')
const { Boom } = require('@hapi/boom')
const { execSync } = require('child_process')

// ======================[ KONFIGURASI UTAMA ]======================
const DEKURITY_CONFIG = {
  BRAND: {
    NAME: '🛡️ Dekurity Bot',
    TAGLINE: 'Cybersecurity Made Simple',
    FOOTER: '_Diberdayakan oleh Dekurity Security Framework_',
    OWNER: '6281234567890@s.whatsapp.net',
    VERSION: '2.0.0'
  },
  API: {
    VIRUSTOTAL: 'YOUR_API_KEY',
    SHODAN: 'YOUR_API_KEY',
    HIBP: 'YOUR_API_KEY',
    SAFEBROWSING: 'YOUR_API_KEY',
    ABUSEIPDB: 'YOUR_API_KEY',
    IPAPI: 'YOUR_API_KEY'
  },
  SECURITY: {
    MAX_PASSWORD: 24,
    MAX_PORT_SCAN: 10,
    ENCRYPTION_KEY: 'dekurity-secure-key-123',
    SCAN_TIMEOUT: 30000
  }
}

const { state, saveState } = useSingleFileAuthState('./auth_info.json')
const adminCache = new Map()

// ======================[ UTILITAS ]======================
function formatResponse(title, content) {
  return `*${DEKURITY_CONFIG.BRAND.NAME}*\n` +
         `_${DEKURITY_CONFIG.BRAND.TAGLINE}_\n\n` +
         `📌 *${title}*\n` +
         `${content}\n\n` +
         `${DEKURITY_CONFIG.BRAND.FOOTER}`
}

async function isAdmin(sock, chatId, userId) {
  if (!adminCache.has(chatId)) {
    const metadata = await sock.groupMetadata(chatId)
    adminCache.set(chatId, metadata.participants.filter(p => p.admin).map(p => p.id))
  }
  return adminCache.get(chatId).includes(userId)
}

// ======================[ FITUR UTAMA ]======================

// 1. Keamanan Akun & Enkripsi
async function analisisPassword(password) {
  const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase()
  const { data } = await axios.get(`https://api.pwnedpasswords.com/range/${hash.slice(0,5)}`)
  const bocor = data.split('\n').some(line => line.startsWith(hash.slice(5)))
  
  const analisis = {
    panjang: password.length >= 12,
    kompleksitas: {
      hurufBesar: /[A-Z]/.test(password),
      hurufKecil: /[a-z]/.test(password),
      angka: /\d/.test(password),
      simbol: /[^\w\s]/.test(password)
    },
    entropy: crypto.randomBytes(16).toString('hex') // Simulasi perhitungan entropy
  }
  
  const skor = Object.values(analisis.kompleksitas).filter(Boolean).length + 
    (analisis.panjang ? 2 : 0)
  
  return {
    skor: Math.min(skor, 10),
    bocor,
    analisis
  }
}

function generatePasswordAdvanced(options = {}) {
  const defaults = {
    length: 16,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
    excludeSimilar: true
  }
  
  const config = { ...defaults, ...options }
  let chars = ''
  
  if (config.uppercase) chars += 'ABCDEFGHJKLMNPQRSTUVWXYZ'
  if (config.lowercase) chars += 'abcdefghijkmnpqrstuvwxyz'
  if (config.numbers) chars += '23456789'
  if (config.symbols) chars += '!@#$%^&*_+-='
  
  if (config.excludeSimilar) {
    chars = chars.replace(/[ilLI|`oO0]/g, '')
  }
  
  return Array.from(crypto.randomFillSync(new Uint32Array(config.length)))
    .map(x => chars[x % chars.length])
    .join('')
}

// 2. Pemindaian Keamanan
async function pemindaianMendalam(url) {
  try {
    const [sslData, headers, vulnScan] = await Promise.all([
      sslChecker(url.replace(/^https?:\/\//, '')),
      axios.head(url).then(res => res.headers),
      scanVulnerability(url)
    ])
    
    return {
      ssl: {
        valid: sslData.daysRemaining > 0,
        issuer: sslData.issuer,
        expiry: sslData.valid_to
      },
      headers: {
        security: {
          hsts: headers['strict-transport-security'] ? '✅' : '❌',
          csp: headers['content-security-policy'] ? '✅' : '❌',
          xss: headers['x-xss-protection'] ? '✅' : '❌'
        }
      },
      vulnerabilities: vulnScan
    }
  } catch (error) {
    throw new Error(`Gagal memindai: ${error.message}`)
  }
}

// 3. Analisis Malware
async function analisisFileMendalam(fileBuffer) {
  const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex')
  const [vtResult, exifData] = await Promise.all([
    axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { 'x-apikey': DEKURITY_CONFIG.API.VIRUSTOTAL }
    }),
    execSync(`exiftool -json -`).toString() // Membutuhkan instalasi exiftool
  ])
  
  return {
    hash,
    deteksiMalware: vtResult.data.data.attributes.last_analysis_stats,
    metadata: JSON.parse(exifData)[0]
  }
}

// 4. OSINT Lanjutan
async function osintMendalam(target) {
  const [whoisData, shodanResult, socialMedia] = await Promise.all([
    whoisPromisified(target),
    axios.get(`https://api.shodan.io/shodan/host/${target}?key=${DEKURITY_CONFIG.API.SHODAN}`),
    cekMediaSosial(target)
  ])
  
  return {
    whois: whoisData,
    shodan: shodanResult.data,
    socialMedia
  }
}

function whoisPromisified(domain) {
  return new Promise((resolve, reject) => {
    whois.lookup(domain, (err, data) => {
      err ? reject(err) : resolve(data)
    })
  })
}

// 5. DNS Lookup
async function dnsLookup(domain) {
  try {
    const records = await dns.resolveAny(domain)
    return records
  } catch (error) {
    throw new Error(`Gagal melakukan DNS Lookup: ${error.message}`)
  }
}

// 6. Dark Web Scan
async function darkWebScan(email) {
  try {
    const response = await axios.get(`https://api.dehashed.com/search?query=${email}`, {
      auth: { username: DEKURITY_CONFIG.API.HIBP, password: '' }
    })
    return response.data.entries
  } catch (error) {
    throw new Error(`Gagal melakukan Dark Web Scan: ${error.message}`)
  }
}

// 7. Integrasi Keamanan Web
async function webSecurityCheck(url) {
  try {
    const zapApi = 'http://zap/JSON/ascan/view/status/'
    const response = await axios.get(`${zapApi}?url=${encodeURIComponent(url)}`)
    return response.data
  } catch (error) {
    throw new Error(`Gagal melakukan pengecekan keamanan web: ${error.message}`)
  }
}

// 8. Log Aktivitas Bot
function logActivity(command, userId, chatId) {
  const timestamp = new Date().toISOString()
  console.log(`[${timestamp}] ${command} oleh ${userId} di ${chatId}`)
}

// ======================[ HANDLER PERINTAH ]======================
async function handleMessage(sock, message) {
  const text = message.message.conversation || message.message.extendedTextMessage?.text || ''
  const sender = message.key.participant || message.key.remoteJid
  const chatId = message.key.remoteJid
  const isGroup = chatId.endsWith('@g.us')

  if (!text.startsWith('!')) return

  const [cmd, ...args] = text.slice(1).split(' ')
  const command = cmd.toLowerCase()

  try {
    logActivity(command, sender, chatId)

    switch(command) {
      case 'passcheck':
        const passResult = await analisisPassword(args[0])
        const passReport = [
          `🔐 *Analisis Password*`,
          `*Skor Keamanan:* ${passResult.skor}/10`,
          `*Panjang:* ${passResult.analisis.panjang ? '✅ ≥12 karakter' : '❌ <12 karakter'}`,
          `*Kompleksitas:*`,
          `  - Huruf Besar: ${passResult.analisis.kompleksitas.hurufBesar ? '✅' : '❌'}`,
          `  - Huruf Kecil: ${passResult.analisis.kompleksitas.hurufKecil ? '✅' : '❌'}`,
          `  - Angka: ${passResult.analisis.kompleksitas.angka ? '✅' : '❌'}`,
          `  - Simbol: ${passResult.analisis.kompleksitas.simbol ? '✅' : '❌'}`,
          `*Kebocoran:* ${passResult.bocor ? '🚨 Ditemukan' : '✅ Aman'}`
        ].join('\n')
        
        await sock.sendMessage(chatId, {
          text: formatResponse('Analisis Password', passReport)
        })
        break

      case 'genpass':
        const options = {
          length: parseInt(args[0]) || 16,
          uppercase: !args.includes('--no-upper'),
          lowercase: !args.includes('--no-lower'),
          numbers: !args.includes('--no-number'),
          symbols: !args.includes('--no-symbol'),
          excludeSimilar: !args.includes('--include-similar')
        }
        
        const password = generatePasswordAdvanced(options)
        await sock.sendMessage(chatId, {
          text: formatResponse('Password Generated', 
            `🔐 *Password Aman:*\n\`${password}\`\n\n` +
            '*Konfigurasi:*\n' +
            `- Panjang: ${options.length}\n` +
            `- Huruf Besar: ${options.uppercase ? '✅' : '❌'}\n` +
            `- Simbol: ${options.symbols ? '✅' : '❌'}`
          )
        })
        break

      case 'deepscan':
        const scanResult = await pemindaianMendalam(args[0])
        const scanReport = [
          '🔍 *Hasil Pemindaian Mendalam:*',
          '',
          '🔐 *SSL/TLS:*',
          `- Valid: ${scanResult.ssl.valid ? '✅' : '❌'}`,
          `- Penerbit: ${scanResult.ssl.issuer}`,
          `- Kedaluwarsa: ${scanResult.ssl.expiry}`,
          '',
          '📌 *Header Keamanan:*',
          `- HSTS: ${scanResult.headers.security.hsts}`,
          `- CSP: ${scanResult.headers.security.csp}`,
          `- XSS Protection: ${scanResult.headers.security.xss}`,
          '',
          '🛡️ *Kerentanan:*',
          `- SQLi: ${scanResult.vulnerabilities.sql}`,
          `- XSS: ${scanResult.vulnerabilities.xss}`,
          `- LFI: ${scanResult.vulnerabilities.lfi}`
        ].join('\n')
        
        await sock.sendMessage(chatId, {
          text: formatResponse('Pemindaian Website', scanReport)
        })
        break

      case 'osint':
        const osintResult = await osintMendalam(args[0])
        const osintReport = [
          '🌐 *Informasi WHOIS:*',
          osintResult.whois.split('\n').slice(0, 10).join('\n'),
          '',
          '🔍 *Data Shodan:*',
          `- Port Terbuka: ${osintResult.shodan.ports.join(', ')}`,
          `- OS: ${osintResult.shodan.os || 'Tidak Diketahui'}`,
          '',
          '📱 *Media Sosial:*',
          `- Twitter: ${osintResult.socialMedia.twitter ? '✅' : '❌'}`,
          `- GitHub: ${osintResult.socialMedia.github ? '✅' : '❌'}`
        ].join('\n')
        
        await sock.sendMessage(chatId, {
          text: formatResponse('Hasil OSINT', osintReport)
        })
        break

      case 'dnslookup':
        const dnsRecords = await dnsLookup(args[0])
        const dnsReport = dnsRecords.map(record => 
          Object.entries(record).map(([key, value]) => `*${key}*: ${value}`).join('\n')
        ).join('\n\n')
        
        await sock.sendMessage(chatId, {
          text: formatResponse('DNS Lookup', dnsReport)
        })
        break

      case 'darkweb':
        const darkWebResults = await darkWebScan(args[0])
        const darkWebReport = darkWebResults.map(entry => 
          `*Sumber*: ${entry.source}\n*Data*: ${entry.data}\n`
        ).join('\n\n')
        
        await sock.sendMessage(chatId, {
          text: formatResponse('Dark Web Scan', darkWebReport)
        })
        break

      case 'webcheck':
        const webCheckResult = await webSecurityCheck(args[0])
        const webCheckReport = [
          '🔍 *Hasil Pengecekan Keamanan Web:*',
          `- Status: ${webCheckResult.status}`,
          `- Detail: ${webCheckResult.detail}`
        ].join('\n')
        
        await sock.sendMessage(chatId, {
          text: formatResponse('Web Security Check', webCheckReport)
        })
        break

      // Tambahkan handler lainnya di sini
    }
  } catch (error) {
    await sock.sendMessage(chatId, {
      text: formatResponse('Error', `❌ ${error.message}`)
    })
  }
}

// ======================[ MAIN EXECUTION ]======================
async function startBot() {
  const sock = makeWASocket({
    auth: state,
    printQRInTerminal: true
  })

  sock.ev.on('connection.update', (update) => {
    if (update.connection === 'open') {
      console.log(`\n${DEKURITY_CONFIG.BRAND.NAME} v${DEKURITY_CONFIG.BRAND.VERSION} Aktif!`)
    }
  })

  sock.ev.on('messages.upsert', async ({ messages }) => {
    await handleMessage(sock, messages[0])
  })

  sock.ev.on('creds.update', saveState)
}

startBot()