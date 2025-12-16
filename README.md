# 🔐 BSV Quantum Vault

**The First Quantum-Resistant Bitcoin Vault with Front-Run Immunity — Proven on Mainnet**

> Protect your BSV from quantum computers using WOTS-16 hash-based signatures with ECDSA covenant binding. No ECDSA exposure during spend. Mathematically secure against both quantum attacks and front-running.

![BSV](https://img.shields.io/badge/BSV-Mainnet-orange)
![Security](https://img.shields.io/badge/Security-Quantum%20Resistant-green)
![Version](https://img.shields.io/badge/Version-4.6-blue)
![Status](https://img.shields.io/badge/Status-Mainnet%20Proven-brightgreen)
![License](https://img.shields.io/badge/License-MIT-blue)

## 🎉 Mainnet Proven

**December 16, 2025** — First successful WOTS-16 covenant transaction on BSV mainnet:

```
TX: 1cd4c9f57691237ec263d8b2515a67e4d8797a99b027135f479a0a191e775a4c
```

[View on WhatsOnChain →](https://whatsonchain.com/tx/1cd4c9f57691237ec263d8b2515a67e4d8797a99b027135f479a0a191e775a4c)

- **8,451 byte transaction** executed successfully
- **5,786 byte locking script** verified on-chain
- **68-chunk WOTS-16 signature** validated
- **Covenant binding** prevented any front-running

---

## ✨ Features

- **🛡️ Quantum-Resistant Storage** — Hash-based keys, no ECDSA exposure
- **⚡ Quantum-Resistant Spend** — WOTS-16 signatures during withdrawal
- **🔒 Front-Run Immunity** — ECDSA covenant binds signature to outputs
- **📱 Mobile-Friendly** — Responsive design, QR code funding
- **🌐 BSV Native** — Bare scripts, Genesis-compliant, mainnet ready
- **🔓 Open Source** — MIT licensed, fully auditable

---

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Security Levels](#-security-levels)
- [How It Works](#-how-it-works)
- [Installation](#-installation)
- [API Reference](#-api-reference)
- [Technical Specifications](#-technical-specifications)
- [Security Model](#-security-model)
- [FAQ](#-faq)

---

## 🚀 Quick Start

### 1. Create a Vault

1. Select your security level (Ultimate recommended)
2. Click **"Generate Vault"**
3. **CRITICAL**: Save the Master Secret securely offline
4. Note your Vault ID

### 2. Fund Your Vault

1. Click **"Continue to Fund Vault"**
2. Scan QR code with any BSV wallet
3. Send BSV (minimum 2,000 sats for fees)
4. Click **"Deposit to Quantum Vault"**

### 3. Withdraw (Sweep)

1. Go to **"Access Vault"**
2. Paste your Master Secret
3. Enter destination address (starts with `1`)
4. Click **"Sweep Funds"**

---

## 🛡️ Security Levels

| Level | Script Size | Use Case | Quantum Safe | Front-Run Safe |
|-------|-------------|----------|--------------|----------------|
| **Standard** | ~35 bytes | Low value, testing | ✅ Storage | ⚠️ Theoretical risk |
| **Enhanced** | ~45 bytes | Time-locked funds | ✅ Storage | ⚠️ Theoretical risk |
| **Maximum** | ~80 bytes | High value | ✅ Storage | ✅ ECDSA covenant |
| **Ultimate** | ~5.7 KB | Maximum security | ✅ Full | ✅ WOTS-16 + Covenant |

### Ultimate Security (Recommended)

The **Ultimate** level provides complete quantum resistance:

```
┌─────────────────────────────────────────────────────────────┐
│                    WOTS-16 + COVENANT                        │
├─────────────────────────────────────────────────────────────┤
│  • 68 signature chunks (64 message + 4 checksum)            │
│  • 4-bit nibbles (0-15 hash iterations per chunk)           │
│  • ECDSA covenant binds signature to hashOutputs            │
│  • No ECDSA private key revealed during spend               │
│  • Mathematically impossible to front-run                    │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔬 How It Works

### WOTS-16 Signature Scheme

**Winternitz One-Time Signatures** rely on the one-way property of hash functions rather than elliptic curve math.

#### Key Generation

```
1. Generate 68 random 32-byte scalars (private key)
2. For each scalar, hash iteratively 16 times (WOTS-16)
3. Final hashes become public key commitments
4. Embed all commitments in locking script
```

#### Signing

```
Message: 256-bit hash of transaction outputs
Split into: 64 nibbles (4 bits each) + 4 checksum nibbles

For each nibble value N (0-15):
  signature_chunk = SHA256^N(private_scalar)
```

#### Verification (On-Chain)

```
For each signature chunk:
  remaining_hashes = 15 - nibble_value
  expected = SHA256^remaining(signature_chunk)
  Verify: expected == public_commitment
```

### Covenant Protection

The ECDSA covenant ensures the WOTS-16 signature is bound to specific outputs:

```
┌─────────────────────────────────────────────────────────────┐
│  1. WOTS-16 signs: SHA256(transaction_outputs)              │
│  2. ECDSA covenant verifies the binding on-chain            │
│  3. Attacker with preimage CANNOT redirect funds            │
│  4. Output destinations are cryptographically locked         │
└─────────────────────────────────────────────────────────────┘
```

---

## 💻 Installation

### Prerequisites

- Node.js 18+
- npm or yarn

### Setup

```bash
# Clone repository
git clone https://github.com/your-repo/bsv-quantum-vault.git
cd bsv-quantum-vault

# Install dependencies
npm install

# Start server
node server.js

# Open browser
open http://localhost:3000
```

### Dependencies

```json
{
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "bsv": "^1.5.6"
  }
}
```

---

## 📡 API Reference

### Create Vault

```
GET /api/create?security={level}
```

**Parameters:**
- `security`: `standard` | `enhanced` | `maximum` | `ultimate`

**Response:**
```json
{
  "success": true,
  "vaultId": "qv1Z2oMt92S92CteWKwMgLg1XNLFXKre",
  "scriptHash": "abc123...",
  "lockingScript": "a820...",
  "masterSecret": "QVSECRET:...",
  "security": "ultimate"
}
```

### Check Balance

```
POST /api/balance
Content-Type: application/json

{
  "secret": "QVSECRET:..."
}
```

### Sweep Vault

```
POST /api/sweep
Content-Type: application/json

{
  "secret": "QVSECRET:...",
  "destinationAddress": "1ABC..."
}
```

### Generate Funding Address

```
POST /api/generate-funding-address
Content-Type: application/json

{
  "vaultSecret": "QVSECRET:..."
}
```

### Deposit to Vault

```
POST /api/deposit-to-vault
Content-Type: application/json

{
  "fundingWIF": "L5...",
  "vaultSecret": "QVSECRET:..."
}
```

---

## 📊 Technical Specifications

### Transaction Metrics (Ultimate Security)

| Metric | Value |
|--------|-------|
| Locking Script | ~5,786 bytes |
| Unlocking Script | ~2,700 bytes |
| Total TX Size | ~8,500 bytes |
| Signature Chunks | 68 |
| Bits per Chunk | 4 (WOTS-16) |
| Key Entropy | 2,176 bytes |
| Hash Algorithm | SHA-256 |
| Typical Fee | ~8,500 sats |

### Script Structure

**Locking Script (Ultimate):**
```
[68x WOTS-16 verification blocks]
<covenant_pubkey> OP_CHECKSIGVERIFY OP_DROP OP_TRUE
```

**Each WOTS-16 Block:**
```
OP_SWAP OP_DUP
OP_2 OP_MOD OP_IF OP_SWAP OP_SHA256 OP_SWAP OP_ENDIF
OP_DUP OP_2 OP_DIV OP_2 OP_MOD OP_IF OP_SWAP OP_SHA256 OP_SHA256 OP_SWAP OP_ENDIF
OP_DUP OP_4 OP_DIV OP_2 OP_MOD OP_IF OP_SWAP [4x OP_SHA256] OP_SWAP OP_ENDIF
OP_DUP OP_8 OP_DIV OP_2 OP_MOD OP_IF OP_SWAP [8x OP_SHA256] OP_SWAP OP_ENDIF
OP_DROP <expected_hash> OP_EQUALVERIFY
```

### File Structure

```
bsv-quantum-vault/
├── server.js           # Express API server
├── winternitz.js       # WOTS-16 cryptography
├── index.html          # Web interface
├── app.js              # Frontend logic
├── styles.css          # Responsive styles
├── package.json        # Dependencies
└── README.md           # Documentation
```

---

## 🔒 Security Model

### Threat Analysis

| Threat | Protection |
|--------|------------|
| Quantum computer breaks ECDSA | ✅ No ECDSA during spend |
| Mempool front-running | ✅ Covenant binds outputs |
| Preimage theft | ✅ Outputs predetermined |
| Replay attack | ✅ One-time signatures |
| Hash collision | ✅ SHA-256 (2^128 quantum) |

### What's Protected

```
┌─────────────────────────────────────────────────────────────┐
│  WHILE FUNDS ARE IN VAULT:                                   │
│    • No public key exposed                                   │
│    • Only hash commitments on-chain                          │
│    • Quantum computers cannot derive keys                    │
├─────────────────────────────────────────────────────────────┤
│  DURING WITHDRAWAL:                                          │
│    • WOTS-16 preimages revealed (not ECDSA keys)            │
│    • Covenant locks destination addresses                    │
│    • Attackers cannot redirect funds                         │
└─────────────────────────────────────────────────────────────┘
```

### Important Warnings

⚠️ **One-Time Use**: WOTS signatures can only be used ONCE. Never reuse a vault after sweeping.

⚠️ **Master Secret**: If lost, funds are PERMANENTLY inaccessible. No recovery possible.

⚠️ **Large Transactions**: Ultimate security requires ~8.5KB transactions with corresponding fees.

---

## ❓ FAQ

### Is this actually quantum-resistant?

**Yes.** WOTS-16 security relies on SHA-256's one-way property. Grover's algorithm provides only quadratic speedup (2^256 → 2^128), which remains computationally infeasible.

### When will quantum computers be a threat?

Current estimates: 10-20 years for cryptographically relevant quantum computers. But funds stored TODAY can be attacked in the FUTURE. Protect long-term holdings now.

### Why not use a quantum-resistant blockchain?

No production quantum-resistant blockchain exists at scale. BSV Quantum Vault protects your funds TODAY on an established, liquid network.

### Can miners front-run my withdrawal?

**Not with Ultimate security.** The ECDSA covenant binds the WOTS-16 signature to specific outputs. Even with the preimage, attackers cannot redirect funds.

### Why bare scripts instead of P2SH?

BSV deprecated P2SH in the Genesis upgrade (February 2020). Bare scripts are BSV-native and support unlimited script sizes.

### What does it cost?

| Action | Size | Fee (~1 sat/byte) |
|--------|------|-------------------|
| Deposit | ~200 bytes | ~200 sats |
| Sweep (Ultimate) | ~8,500 bytes | ~8,500 sats |

Total: Less than $0.10 USD typically.

### Is this production-ready?

**Yes.** Successfully tested on BSV mainnet (December 16, 2025). Always test with small amounts first.

---

## 🗺️ Roadmap

- [x] WOTS-16 on-chain verification
- [x] ECDSA covenant binding
- [x] Mainnet deployment
- [x] Mobile-responsive UI
- [ ] Multi-signature quantum vaults
- [ ] Hardware wallet integration
- [ ] Batch operations
- [ ] Mobile native app

---

## 📜 License

MIT License — Free to use, modify, and distribute.

---

## ⚠️ Disclaimer

This software is provided "as is" without warranty. While cryptographic primitives are well-established, this is experimental software. Always:

- Test with small amounts first
- Keep secure backups of Master Secret
- Understand the technology before storing significant value

---

## 🙏 Acknowledgments

- **Ralph Merkle** — Hash-based signature foundations
- **Robert Winternitz** — WOTS scheme development
- **BSV Community** — Maintaining unbounded Bitcoin
- **Dean 利迪恩** — Guidance and insights
- **Satoshi Nakamoto** — For Bitcoin

---

<div align="center">

**Made with ❤️ for a quantum-safe future**

```
 ____  _______    __   ____  __  _____    _   ____________  ____  ___
/ __ )/ ___/ |  / /  / __ \/ / / /   |  / | / /_  __/ / / / /  |/  /
/ __  |\__ \| | / /  / / / / / / / /| | /  |/ / / / / / / / / /|_/ / 
/ /_/ /___/ /| |/ /  / /_/ / /_/ / ___ |/ /|  / / / / /_/ / /  /  /  
/_____//____/ |___/   \___\_\____/_/  |_/_/ |_/ /_/  \____/_/_/  /_/   

          QUANTUM VAULT — Securing the Future
```

</div>
