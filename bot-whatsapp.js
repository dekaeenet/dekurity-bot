const { WAConnection, MessageType, GroupSettingChange } = require('@adiwajshing/baileys');
const axios = require('axios');
const fs = require('fs');
const whois = require('whois-json');
const net = require('net');
const crypto = require('crypto');
const os = require('os');

const ownerNumber = 'owner_number@s.whatsapp.net'; // ganti dengan nomor owner
const virusTotalApiKey = 'YOUR_VIRUSTOTAL_API_KEY'; // ganti dengan API key dari VirusTotal
const geoApiKey = 'YOUR_GEO_API_KEY'; // ganti dengan API key dari layanan geolocation
const secretKey = 'your_secret_key'; // ganti dengan kunci rahasia untuk enkripsi dan dekripsi

let isPublic = true; // Default mode is public

const conn = new WAConnection();

conn.on('open', () => {
    console.log('Connected');
    const authInfo = conn.base64EncodedAuthInfo();
    fs.writeFileSync('./auth_info.json', JSON.stringify(authInfo, null, '\t'));
});

conn.on('chat-update', async (chat) => {
    if (!chat.hasNewMessage) return;
    const message = chat.messages.all()[0];
    if (!message.message) return;

    const from = message.key.remoteJid;
    const isGroup = from.endsWith('@g.us');
    const sender = message.key.participant || message.key.remoteJid;
    const isOwner = sender === ownerNumber;

    if (!isGroup && !isPublic && !isOwner) return;

    const groupMetadata = isGroup ? await conn.groupMetadata(from) : null;
    const groupAdmins = isGroup ? groupMetadata.participants.filter(participant => participant.isAdmin).map(admin => admin.jid) : [];
    const isAdmin = groupAdmins.includes(sender) || isOwner;

    const type = Object.keys(message.message)[0];
    const body = message.message.conversation || message.message[type].caption || message.message[type].text || '';

    if (!body.startsWith('!')) return;

    const command = body.slice(1).trim().split(' ')[0];
    const args = body.slice(1).trim().split(' ').slice(1);

    const generateHash = (text) => {
        return crypto.createHash('sha256').update(text).digest('hex');
    };

    const encrypt = (text) => {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-ctr', Buffer.from(secretKey, 'hex'), iv);
        const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
        return iv.toString('hex') + ':' + encrypted.toString('hex');
    };

    const decrypt = (hash) => {
        const parts = hash.split(':');
        const iv = Buffer.from(parts.shift(), 'hex');
        const encryptedText = Buffer.from(parts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv('aes-256-ctr', Buffer.from(secretKey, 'hex'), iv);
        const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
        return decrypted.toString();
    };

    const verifyPassword = (password, hash) => {
        return generateHash(password) === hash;
    };

    const scanPort = (host, port) => {
        return new Promise((resolve, reject) => {
            const socket = new net.Socket();
            socket.setTimeout(2000);
            socket.on('connect', () => {
                resolve(port);
                socket.destroy();
            });
            socket.on('timeout', () => {
                resolve(null);
                socket.destroy();
            });
            socket.on('error', (error) => {
                resolve(null);
                socket.destroy();
            });
            socket.connect(port, host);
        });
    };

    const scanWebserver = async (url) => {
        try {
            const response = await axios.get(url);
            return response.headers.server || 'Unknown server';
        } catch (error) {
            return 'Unable to detect webserver';
        }
    };

    const getWhois = async (domain) => {
        try {
            const data = await whois(domain);
            return JSON.stringify(data, null, 2);
        } catch (error) {
            return 'Unable to retrieve WHOIS information';
        }
    };

    const getIpGeoInfo = async (ip) => {
        try {
            const [ipInfoResponse, geoResponse] = await Promise.all([
                axios.get(`https://ipinfo.io/${ip}/json`),
                axios.get(`https://api.ipgeolocation.io/ipgeo?apiKey=${geoApiKey}&ip=${ip}`)
            ]);

            return {
                ipInfo: ipInfoResponse.data,
                geoInfo: geoResponse.data
            };
        } catch (error) {
            return 'Unable to retrieve IP geolocation information';
        }
    };

    const getSourceCode = async (url) => {
        try {
            const response = await axios.get(url);
            return response.data;
        } catch (error) {
            return 'Unable to retrieve source code';
        }
    };

    const getOsintData = async (username) => {
        const platforms = ['github', 'instagram', 'facebook', 'tiktok', 'twitter', 'linkedin', 'hackerone'];
        let osintResults = '';

        for (const platform of platforms) {
            try {
                const response = await axios.get(`https://osint.example.com/${platform}/${username}`);
                osintResults += `🔍 *${platform} data for ${username}:*\n${JSON.stringify(response.data, null, 2)}\n\n`;
            } catch (error) {
                osintResults += `❌ *Unable to retrieve ${platform} data for ${username}*\n\n`;
            }
        }
        return osintResults;
    };

    const getSystemInfo = () => {
        return {
            platform: os.platform(),
            cpu: os.cpus()[0].model,
            totalMemory: os.totalmem(),
            freeMemory: os.freemem(),
            uptime: os.uptime()
        };
    };

    switch (command) {
        case 'hash':
            const hash = generateHash(args.join(' '));
            conn.sendMessage(from, `🔒 *Hash:* ${hash}`, MessageType.text);
            break;

        case 'encrypt':
            const encrypted = encrypt(args.join(' '));
            conn.sendMessage(from, `🔒 *Encrypted:* ${encrypted}`, MessageType.text);
            break;

        case 'decrypt':
            try {
                const decrypted = decrypt(args.join(' '));
                conn.sendMessage(from, `🔓 *Decrypted:* ${decrypted}`, MessageType.text);
            } catch (error) {
                conn.sendMessage(from, `❌ *Invalid encrypted text*`, MessageType.text);
            }
            break;

        case 'verifypassword':
            const isValid = verifyPassword(args[0], args[1]);
            conn.sendMessage(from, `🔑 *Password is* ${isValid ? 'valid' : 'invalid'}`, MessageType.text);
            break;

        case 'verifyhash':
            const isHashValid = generateHash(args.slice(1).join(' ')) === args[0];
            conn.sendMessage(from, `🔑 *Hash is* ${isHashValid ? 'valid' : 'invalid'}`, MessageType.text);
            break;

        case 'scanport':
            const portResult = await scanPort(args[0], parseInt(args[1]));
            conn.sendMessage(from, `🔍 *Port ${args[1]} on ${args[0]} is* ${portResult ? 'open' : 'closed'}`, MessageType.text);
            break;

        case 'scanwebserver':
            const webserverResult = await scanWebserver(args[0]);
            conn.sendMessage(from, `🌐 *Webserver for ${args[0]} is* ${webserverResult}`, MessageType.text);
            break;

        case 'whois':
            const whoisResult = await getWhois(args[0]);
            conn.sendMessage(from, `ℹ️ *WHOIS information for ${args[0]}:*\n${whoisResult}`, MessageType.text);
            break;

        case 'ipgeo':
            const ipGeoResult = await getIpGeoInfo(args[0]);
            conn.sendMessage(from, `🌐 *IP information for ${args[0]}:*\n${JSON.stringify(ipGeoResult.ipInfo, null, 2)}\n\n🌍 *Geolocation information for ${args[0]}:*\n${JSON.stringify(ipGeoResult.geoInfo, null, 2)}`, MessageType.text);
            break;

        case 'sourceview':
            const sourceCodeResult = await getSourceCode(args[0]);
            conn.sendMessage(from, `📄 *Source code for ${args[0]}:*\n${sourceCodeResult}`, MessageType.text);
            break;

        case 'osint':
            const osintResult = await getOsintData(args[0]);
            conn.sendMessage(from, osintResult, MessageType.text);
            break;

        case 'block':
            if (isOwner) {
                await conn.blockUser(args[0], 'add');
                conn.sendMessage(from, `🚫 *Blocked* ${args[0]}`, MessageType.text);
            } else {
                conn.sendMessage(from, `❌ *You are not authorized to use this command*`, MessageType.text);
            }
            break;

        case 'unblock':
            if (isOwner) {
                await conn.blockUser(args[0], 'remove');
                conn.sendMessage(from, `✅ *Unblocked* ${args[0]}`, MessageType.text);
            } else {
                conn.sendMessage(from, `❌ *You are not authorized to use this command*`, MessageType.text);
            }
            break;

        case 'ping':
            conn.sendMessage(from, `🏓 *Pong!*`, MessageType.text);
            break;

        case 'self':
            if (isOwner) {
                isPublic = false;
                conn.sendMessage(from, `🔒 *Bot is now in self mode*`, MessageType.text);
            } else {
                conn.sendMessage(from, `❌ *You are not authorized to use this command*`, MessageType.text);
            }
            break;

        case 'public':
            if (isOwner) {
                isPublic = true;
                conn.sendMessage(from, `🔓 *Bot is now in public mode*`, MessageType.text);
            } else {
                conn.sendMessage(from, `❌ *You are not authorized to use this command*`, MessageType.text);
            }
            break;

        case 'system':
            if (isOwner) {
                const systemInfo = getSystemInfo();
                conn.sendMessage(from, `🖥️ *System Information:*\n\nPlatform: ${systemInfo.platform}\nCPU: ${systemInfo.cpu}\nTotal Memory: ${systemInfo.totalMemory}\nFree Memory: ${systemInfo.freeMemory}\nUptime: ${systemInfo.uptime}`, MessageType.text);
            } else {
                conn.sendMessage(from, `❌ *You are not authorized to use this command*`, MessageType.text);
            }
            break;

        case 'menu':
            const menu = `
📜 *Menu:*
- !hash <text>
- !encrypt <text>
- !decrypt <encrypted_text>
- !verifypassword <password> <hash>
- !verifyhash <hash> <text>
- !scanport <host> <port>
- !scanwebserver <url>
- !whois <domain>
- !ipgeo <ip>
- !sourceview <url>
- !osint <username>
- !block <number>
- !unblock <number>
- !ping
- !self
- !public
- !system
            `;
            const info = `
🤖 *Bot Information*
- Name: YourBotName
- Version: 1.0.0
- Description: This is a multi-functional WhatsApp bot.

👨‍💼 *Owner Information*
- Name: Owner Name
- Contact: owner_number

👨‍💻 *Developer Information*
- Name: Developer Name
- GitHub: https://github.com/developer_github
- Instagram: https://instagram.com/developer_instagram
- Contact: developer_contact
- Email: developer_email@example.com
            `;
            conn.sendMessage(from, menu, MessageType.text);
            conn.sendMessage(from, info, MessageType.text);
            break;
    }
});

fs.existsSync('./auth_info.json') && conn.loadAuthInfo('./auth_info.json');
conn.connect();