# 🤖 WhatsApp Bot - Struktur Profesional & Scalable

**Best Practices untuk Bot WhatsApp menggunakan Baileys**  
**Updated:** 2025-11-25

---

## 📁 **STRUKTUR FOLDER YANG DIREKOMENDASIKAN**

```
whatsapp-bot/
├── .env                      # ⚠️ RAHASIA - Variabel lingkungan
├── .gitignore                # File yang diabaikan Git
├── index.js                  # Entry point bot
├── package.json              # Dependencies & scripts
├── README.md                 # Dokumentasi
│
├── config/
│   └── index.js              # Konfigurasi dari .env
│
├── src/                      # Source code utama
│   ├── connect.js            # Koneksi Baileys
│   ├── handler.js            # Message handler
│   └── serializer.js         # Simplify message object
│
├── plugins/                  # Semua plugin bot
│   ├── commands/             # Command pengguna
│   │   ├── owner/            # Command owner only
│   │   │   ├── eval.js
│   │   │   └── shutdown.js
│   │   ├── general/          # Command umum
│   │   │   ├── menu.js
│   │   │   ├── ping.js
│   │   │   └── info.js
│   │   └── group/            # Command grup
│   │       ├── kick.js
│   │       ├── promote.js
│   │       └── welcome.js
│   │
│   └── events/               # Event listeners
│       ├── welcome.js        # Member join
│       ├── leave.js          # Member leave
│       └── promote.js        # Admin promoted
│
├── lib/                      # Helper functions
│   ├── functions.js          # Utility functions
│   ├── logger.js             # Logging system
│   └── database.js           # Database helpers
│
└── database/                 # Data storage
    ├── connect.js            # Database connection
    └── models/               # Data models
        ├── users.json        # User data
        └── groups.json       # Group settings
```

---

## 🔧 **FILE-FILE UTAMA**

### 1. `.env` - Environment Variables

```ini
# Bot Configuration
OWNER_NUMBER="62812xxxxxx@s.whatsapp.net"
BOT_NAME="My Awesome Bot"
PREFIX="!"
BOT_VERSION="1.0.0"

# API Keys (Optional)
OPENAI_API_KEY="sk-..."
GEMINI_API_KEY="..."

# Database (Optional - untuk production)
MONGODB_URI="mongodb://localhost:27017/whatsapp-bot"

# Features
ENABLE_WELCOME=true
ENABLE_ANTI_LINK=true
ENABLE_AUTO_READ=false

# Security
SESSION_FOLDER="./session"
MAX_COMMAND_COOLDOWN=3000
```

### 2. `.gitignore`

```gitignore
# Dependencies
node_modules/

# Environment
.env
.env.local
.env.production

# Session data (Baileys)
session/
*.session.json

# Database
database/models/*.json
*.db
*.sqlite

# Logs
logs/
*.log

# OS
.DS_Store
Thumbs.db

# IDE
.vscode/
.idea/
*.swp
```

### 3. `package.json`

```json
{
  "name": "whatsapp-bot",
  "version": "1.0.0",
  "description": "Professional WhatsApp Bot using Baileys",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js",
    "test": "node test.js"
  },
  "keywords": ["whatsapp", "bot", "baileys"],
  "author": "Your Name",
  "license": "MIT",
  "dependencies": {
    "@whiskeysockets/baileys": "^6.5.0",
    "dotenv": "^16.3.1",
    "pino": "^8.16.2",
    "qrcode-terminal": "^0.12.0",
    "axios": "^1.6.2",
    "moment-timezone": "^0.5.43"
  },
  "devDependencies": {
    "nodemon": "^3.0.2"
  }
}
```

### 4. `index.js` - Entry Point

```javascript
/**
 * WhatsApp Bot - Entry Point
 * Professional & Scalable Structure
 */

console.log('🤖 Starting WhatsApp Bot...');
console.log('📅 ' + new Date().toLocaleString());

// Load environment variables
require('dotenv').config();

// Load configuration
const config = require('./config');

// Validate configuration
if (!config.owner) {
    console.error('❌ OWNER_NUMBER not set in .env');
    process.exit(1);
}

// Start bot
require('./src/connect');

// Handle process errors
process.on('unhandledRejection', (err) => {
    console.error('❌ Unhandled Rejection:', err);
});

process.on('uncaughtException', (err) => {
    console.error('❌ Uncaught Exception:', err);
});

console.log('✅ Bot initialized successfully');
```

### 5. `config/index.js` - Configuration Manager

```javascript
/**
 * Configuration Manager
 * Loads and validates environment variables
 */

require('dotenv').config();

const config = {
    // Bot Info
    botName: process.env.BOT_NAME || 'WhatsApp Bot',
    prefix: process.env.PREFIX || '!',
    version: process.env.BOT_VERSION || '1.0.0',
    
    // Owner
    owner: process.env.OWNER_NUMBER,
    
    // Features
    features: {
        welcome: process.env.ENABLE_WELCOME === 'true',
        antiLink: process.env.ENABLE_ANTI_LINK === 'true',
        autoRead: process.env.ENABLE_AUTO_READ === 'true'
    },
    
    // API Keys
    apiKeys: {
        openai: process.env.OPENAI_API_KEY,
        gemini: process.env.GEMINI_API_KEY
    },
    
    // Database
    database: {
        mongodb: process.env.MONGODB_URI
    },
    
    // Security
    security: {
        sessionFolder: process.env.SESSION_FOLDER || './session',
        commandCooldown: parseInt(process.env.MAX_COMMAND_COOLDOWN) || 3000
    }
};

// Validate required config
if (!config.owner) {
    throw new Error('OWNER_NUMBER is required in .env');
}

module.exports = config;
```

### 6. `src/connect.js` - Baileys Connection

```javascript
/**
 * WhatsApp Connection Handler
 * Using @whiskeysockets/baileys
 */

const {
    default: makeWASocket,
    DisconnectReason,
    useMultiFileAuthState,
    makeInMemoryStore
} = require('@whiskeysockets/baileys');
const pino = require('pino');
const qrcode = require('qrcode-terminal');
const config = require('../config');
const handler = require('./handler');

// Create store for message history
const store = makeInMemoryStore({
    logger: pino().child({ level: 'silent', stream: 'store' })
});

async function connectToWhatsApp() {
    // Load auth state
    const { state, saveCreds } = await useMultiFileAuthState(config.security.sessionFolder);
    
    // Create socket
    const sock = makeWASocket({
        logger: pino({ level: 'silent' }),
        printQRInTerminal: true,
        auth: state,
        browser: ['WhatsApp Bot', 'Chrome', '1.0.0']
    });
    
    // Bind store
    store.bind(sock.ev);
    
    // Connection update
    sock.ev.on('connection.update', async (update) => {
        const { connection, lastDisconnect, qr } = update;
        
        if (qr) {
            console.log('📱 Scan QR Code:');
            qrcode.generate(qr, { small: true });
        }
        
        if (connection === 'close') {
            const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
            
            console.log('❌ Connection closed. Reconnecting:', shouldReconnect);
            
            if (shouldReconnect) {
                connectToWhatsApp();
            }
        } else if (connection === 'open') {
            console.log('✅ Connected to WhatsApp');
        }
    });
    
    // Save credentials
    sock.ev.on('creds.update', saveCreds);
    
    // Handle messages
    sock.ev.on('messages.upsert', async ({ messages, type }) => {
        if (type !== 'notify') return;
        
        const m = messages[0];
        if (!m.message) return;
        
        // Pass to handler
        await handler(sock, m, store);
    });
    
    // Group updates (member join/leave)
    sock.ev.on('group-participants.update', async (update) => {
        const { id, participants, action } = update;
        
        // Handle welcome/leave events
        if (action === 'add') {
            const welcomeEvent = require('../plugins/events/welcome');
            await welcomeEvent.handler(sock, { id, participants });
        }
    });
    
    return sock;
}

// Start connection
connectToWhatsApp();

module.exports = { connectToWhatsApp };
```

### 7. `src/handler.js` - Message Handler

```javascript
/**
 * Message Handler
 * Routes messages to appropriate commands/events
 */

const fs = require('fs');
const path = require('path');
const config = require('../config');
const { serialize } = require('./serializer');

// Load all commands
const commands = new Map();
const commandsPath = path.join(__dirname, '../plugins/commands');

function loadCommands(dir) {
    const files = fs.readdirSync(dir);
    
    for (const file of files) {
        const filePath = path.join(dir, file);
        const stat = fs.statSync(filePath);
        
        if (stat.isDirectory()) {
            loadCommands(filePath);
        } else if (file.endsWith('.js')) {
            const command = require(filePath);
            if (command.command) {
                commands.set(command.command, command);
                console.log(`✅ Loaded command: ${command.command}`);
            }
        }
    }
}

loadCommands(commandsPath);

// Cooldown tracker
const cooldowns = new Map();

async function handler(sock, m, store) {
    try {
        // Serialize message
        const msg = await serialize(sock, m, store);
        
        // Ignore if no text
        if (!msg.text) return;
        
        // Check if it's a command
        if (!msg.text.startsWith(config.prefix)) return;
        
        // Parse command
        const args = msg.text.slice(config.prefix.length).trim().split(/ +/);
        const commandName = args.shift().toLowerCase();
        
        // Get command
        const command = commands.get(commandName);
        if (!command) return;
        
        // Check cooldown
        const cooldownKey = `${msg.sender}-${commandName}`;
        if (cooldowns.has(cooldownKey)) {
            const expirationTime = cooldowns.get(cooldownKey) + config.security.commandCooldown;
            
            if (Date.now() < expirationTime) {
                const timeLeft = ((expirationTime - Date.now()) / 1000).toFixed(1);
                return msg.reply(`⏳ Tunggu ${timeLeft} detik sebelum menggunakan command ini lagi`);
            }
        }
        
        // Set cooldown
        cooldowns.set(cooldownKey, Date.now());
        setTimeout(() => cooldowns.delete(cooldownKey), config.security.commandCooldown);
        
        // Check owner only
        if (command.ownerOnly && msg.sender !== config.owner) {
            return msg.reply('❌ Command ini hanya untuk owner');
        }
        
        // Check group only
        if (command.groupOnly && !msg.isGroup) {
            return msg.reply('❌ Command ini hanya bisa digunakan di grup');
        }
        
        // Execute command
        console.log(`📝 Command: ${commandName} from ${msg.sender}`);
        await command.handler(sock, msg, { args, command: commandName });
        
    } catch (error) {
        console.error('❌ Handler error:', error);
        
        try {
            await sock.sendMessage(m.key.remoteJid, {
                text: '❌ Terjadi error saat memproses command'
            });
        } catch (e) {
            console.error('Failed to send error message:', e);
        }
    }
}

module.exports = handler;
```

---

## 📝 **CONTOH COMMAND**

### `plugins/commands/general/ping.js`

```javascript
/**
 * Ping Command
 * Check bot response time
 */

const command = {
    command: 'ping',
    category: 'general',
    description: 'Cek kecepatan respon bot',
    usage: '!ping',
    
    handler: async (sock, msg, { args }) => {
        const start = Date.now();
        
        const sent = await msg.reply('🏓 Pong!');
        
        const end = Date.now();
        const responseTime = end - start;
        
        await sock.sendMessage(msg.from, {
            text: `⚡ Response time: ${responseTime}ms`,
            edit: sent.key
        });
    }
};

module.exports = command;
```

### `plugins/commands/general/menu.js`

```javascript
/**
 * Menu Command
 * Display all available commands
 */

const config = require('../../../config');

const command = {
    command: 'menu',
    category: 'general',
    description: 'Tampilkan daftar command',
    usage: '!menu',
    
    handler: async (sock, msg, { args }) => {
        const menuText = `
╭━━━『 ${config.botName} 』━━━╮
│ 📱 WhatsApp Bot
│ 🤖 Version: ${config.version}
│ 👤 Owner: @${config.owner.split('@')[0]}
╰━━━━━━━━━━━━━━━━━━━╯

╭━━━『 GENERAL 』━━━╮
│ • ${config.prefix}menu
│ • ${config.prefix}ping
│ • ${config.prefix}info
╰━━━━━━━━━━━━━━━━━━━╯

╭━━━『 GROUP 』━━━╮
│ • ${config.prefix}kick @user
│ • ${config.prefix}promote @user
│ • ${config.prefix}welcome on/off
╰━━━━━━━━━━━━━━━━━━━╯

╭━━━『 OWNER 』━━━╮
│ • ${config.prefix}eval <code>
│ • ${config.prefix}shutdown
╰━━━━━━━━━━━━━━━━━━━╯

Powered by Baileys
        `.trim();
        
        await msg.reply(menuText);
    }
};

module.exports = command;
```

---

## 🚀 **CARA MENGGUNAKAN**

### 1. Setup Project

```bash
# Buat folder project
mkdir whatsapp-bot
cd whatsapp-bot

# Initialize npm
npm init -y

# Install dependencies
npm install @whiskeysockets/baileys dotenv pino qrcode-terminal axios moment-timezone

# Install dev dependencies
npm install --save-dev nodemon
```

### 2. Buat Struktur Folder

```bash
mkdir -p config src plugins/{commands/{owner,general,group},events} lib database/models
```

### 3. Copy Semua File

Copy semua file dari dokumentasi ini ke folder yang sesuai.

### 4. Buat `.env`

```bash
cp .env.example .env
# Edit .env dengan nomor owner Anda
```

### 5. Jalankan Bot

```bash
npm start
```

---

## ✅ **KEUNTUNGAN STRUKTUR INI**

1. ✅ **Terorganisir** - Setiap file punya tugas yang jelas
2. ✅ **Scalable** - Mudah menambah command baru
3. ✅ **Secure** - Secrets di `.env`, tidak di-commit
4. ✅ **Maintainable** - Mudah debug dan update
5. ✅ **Professional** - Mengikuti best practices
6. ✅ **Modular** - Command terpisah per file
7. ✅ **Auto-load** - Command otomatis dimuat
8. ✅ **Cooldown** - Prevent spam
9. ✅ **Error Handling** - Robust error handling
10. ✅ **Documentation** - Jelas dan lengkap

---

**Dokumentasi lengkap untuk WhatsApp Bot profesional!** 🤖✨
