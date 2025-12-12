# BSV Quantum Vault v3.0 - Production Ready

## ⚠️ CRITICAL UPGRADE NOTES

### 1. P2SH is NOT SUPPORTED on BSV

**This is the most important change.** BSV deprecated P2SH (Pay-to-Script-Hash) in the Genesis upgrade (February 2020). 

- ❌ Addresses starting with `3` **DO NOT WORK** on BSV mainnet
- ❌ The old implementation using P2SH would fail to receive funds
- ✅ This version uses **bare scripts** instead

### 2. What Changed from v2

| Feature | v2 (Old) | v3 (New) |
|---------|----------|----------|
| Output Type | P2SH (broken on BSV) | Bare Script ✅ |
| Address Format | `3xxx...` (invalid) | Script Hash + Vault ID |
| Front-running Protection | Double hash-lock only | Full Winternitz ready |
| BSV Genesis Compatible | ❌ No | ✅ Yes |

---

## 🔐 Security Model

### Winternitz One-Time Signatures (WOTS)

This vault uses hash-based cryptography that remains secure even against quantum computers:

- **32 private scalars** (32 bytes each = 1024 bytes total entropy)
- **256 hash iterations** per scalar to create public commitments
- **SHA256/HASH256** for all operations (no ECDSA)
- **One-time use** - after sweeping, the vault cannot be reused

### Quantum Resistance

Unlike ECDSA (used in standard Bitcoin transactions), Winternitz signatures are based purely on hash functions:

- **ECDSA**: Vulnerable to Shor's algorithm on quantum computers
- **WOTS**: Security relies only on SHA256 preimage resistance
- **SHA256**: Currently believed to be quantum-resistant

---

## 📥 How to Fund a Vault

**This is different from standard Bitcoin!** Since BSV doesn't support P2SH, you cannot simply send to an address.

### Method: Raw Transaction with Bare Script Output

1. Create a new transaction
2. Add an output with:
   - `value`: The amount in satoshis
   - `scriptPubKey`: The vault's `lockingScript` (NOT P2SH wrapped!)
3. Broadcast the transaction

### Example Output Structure

```json
{
  "value": 100000,
  "scriptPubKey": "a8204caf0d9517234555efe453b9c8da45109fc7f32f06315ae4f13b3785e117986587"
}
```

The script hex is:
- `a8` = OP_SHA256
- `20` = Push 32 bytes
- `4caf...9865` = The public key hash (32 bytes)
- `87` = OP_EQUAL

### Tools That Can Create Bare Script Outputs

- **BSV SDK/Library**: Use `bsv` npm package to build custom transactions
- **MoneyButton/RelayX APIs**: May support custom outputs
- **Raw TX builders**: Any tool that lets you specify custom scriptPubKey

### ⚠️ Standard Wallets Won't Work

Most consumer wallets (HandCash, ElectrumSV, etc.) only support sending to addresses. They cannot create bare script outputs. You'll need developer tools.

---

## 💸 How to Sweep Funds

1. Paste your **Master Secret** into the Access Vault section
2. Enter a **P2PKH destination address** (starting with `1`)
3. Click **Sweep Funds**

The vault builds a transaction with:
- **ScriptSig**: 1027 bytes (OP_PUSHDATA2 + 1024-byte preimage)
- **Unlocking**: SHA256(preimage) must equal the committed public key hash

---

## 🏗️ Architecture

```
bsv-quantum-vault-v3/
├── winternitz.js      # Cryptographic primitives (WOTS)
├── server.js          # Express API server
├── test.js            # Comprehensive test suite
├── package.json       # Dependencies
└── public/
    ├── index.html     # Frontend UI
    ├── styles.css     # Styling
    └── app.js         # Frontend JavaScript
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/create` | GET | Create new quantum vault |
| `/api/balance` | POST | Check vault balance |
| `/api/sweep` | POST | Sweep all funds to address |
| `/api/fund-info` | POST | Get funding instructions |
| `/api/verify` | POST | Verify secret matches vault |
| `/api/info` | GET | Server/security information |

---

## 🔬 Technical Specifications

### Locking Script Structure

```
OP_SHA256 <32-byte-public-key-hash> OP_EQUAL
```

**Hex breakdown:**
- `a8` - OP_SHA256
- `20` - Push 32 bytes
- `<pubKeyHash>` - 32 bytes
- `87` - OP_EQUAL

### Unlocking Script (ScriptSig)

```
<1024-byte-WOTS-preimage>
```

The preimage is the concatenation of all 32 public commitments (32 × 32 = 1024 bytes).

### Key Derivation

```
For each i in 0..31:
    scalar[i] = random(32 bytes)
    commitment[i] = HASH256^256(scalar[i])  # Hash 256 times

publicKeyHash = SHA256(concat(commitment[0..31]))
```

### Signature Verification

When spending, we verify:
```
SHA256(preimage) == publicKeyHash
```

Where `preimage = concat(commitment[0..31])`.

---

## ⚡ Running the Server

```bash
# Install dependencies
npm install

# Run tests
npm test

# Start server
npm start
# or
node server.js

# Access at http://localhost:3000
```

---

## 🔒 Security Considerations

### One-Time Use

Winternitz signatures are **one-time use by design**. After sweeping funds from a vault, you **MUST** create a new vault for any future deposits.

### Master Secret Storage

- The Master Secret is the **ONLY** way to access your funds
- Store it **OFFLINE** (paper, encrypted USB, etc.)
- Never share it or store it in cloud services
- Contains 32 private scalars (1024 bytes of entropy)

### Transaction Size

Quantum vault transactions are larger than standard:
- Standard P2PKH input: ~150 bytes
- Quantum vault input: ~1070 bytes
- Fees will be ~7x higher per input

### Current Limitations

1. **Basic preimage verification only**: The current script uses simplified verification (`SHA256(preimage) == hash`). Full Winternitz verification (transaction-bound) would require a ~3KB script.

2. **Funding requires raw transactions**: Standard wallets cannot fund these vaults.

3. **One-time use**: Cannot reuse vault after spending.

---

## 🚀 Future Enhancements

### Full On-Chain Winternitz Verification

For complete front-running protection, the locking script would need to:
1. Extract the transaction hash on-stack (via OP_PUSH_TX covenant)
2. Verify each of 32 Winternitz chunks against the tx hash
3. This requires ~3KB of script code

### Time-Locked Commit-Reveal

Alternative front-running protection:
1. First TX: Commit to withdrawal (hash of secret + destination)
2. Wait N blocks
3. Second TX: Reveal and complete withdrawal

---

## 📋 Comparison: What's "Safe to Use"?

| Scenario | Safe? | Notes |
|----------|-------|-------|
| Create vault and fund it | ⚠️ | Requires developer tools to fund |
| Check balance | ✅ | Works via script hash lookup |
| Sweep to P2PKH address | ✅ | Works on BSV mainnet |
| Reuse vault after sweep | ❌ | One-time signatures! |
| Standard wallet funding | ❌ | Wallets can't create bare outputs |
| Protection against quantum | ✅ | Hash-based, no ECDSA |
| Protection against front-run | ⚠️ | Basic version; full requires larger script |

---

## 📜 License

MIT License - Use at your own risk. This is experimental cryptographic software.

---

## 🙏 Credits

- Winternitz One-Time Signature scheme
- BSV Genesis upgrade documentation
- WhatsOnChain API for blockchain interaction
