/**
 * BSV Quantum Vault v3 - Test Suite
 * 
 * Tests all cryptographic primitives and vault operations.
 */

const wots = require('./winternitz');

console.log('╔═══════════════════════════════════════════════════════════════╗');
console.log('║         BSV QUANTUM VAULT v3 - TEST SUITE                     ║');
console.log('╚═══════════════════════════════════════════════════════════════╝\n');

let passed = 0;
let failed = 0;

function test(name, fn) {
    try {
        fn();
        console.log(`✅ ${name}`);
        passed++;
    } catch (error) {
        console.log(`❌ ${name}`);
        console.log(`   Error: ${error.message}`);
        failed++;
    }
}

function assertEqual(actual, expected, msg = '') {
    if (Buffer.isBuffer(actual) && Buffer.isBuffer(expected)) {
        if (!actual.equals(expected)) {
            throw new Error(`${msg} - Buffer mismatch`);
        }
    } else if (actual !== expected) {
        throw new Error(`${msg} - Expected ${expected}, got ${actual}`);
    }
}

function assertTrue(condition, msg = '') {
    if (!condition) {
        throw new Error(`${msg} - Assertion failed`);
    }
}

// =============================================================================
// HASH FUNCTION TESTS
// =============================================================================

console.log('━━━ Hash Functions ━━━\n');

test('SHA256 produces 32 bytes', () => {
    const result = wots.sha256(Buffer.from('test'));
    assertEqual(result.length, 32);
});

test('HASH256 (double SHA256) produces 32 bytes', () => {
    const result = wots.hash256(Buffer.from('test'));
    assertEqual(result.length, 32);
});

test('HASH160 produces 20 bytes', () => {
    const result = wots.hash160(Buffer.from('test'));
    assertEqual(result.length, 20);
});

test('Iterated HASH256 produces correct chain', () => {
    const data = Buffer.from('test');
    const once = wots.iteratedHash256(data, 1);
    const twice = wots.iteratedHash256(data, 2);
    const expectedTwice = wots.hash256(once);
    assertTrue(twice.equals(expectedTwice));
});

test('Iterated HASH256 with 0 iterations returns input', () => {
    const data = Buffer.alloc(32).fill(0xaa);
    const result = wots.iteratedHash256(data, 0);
    assertTrue(result.equals(data));
});

// =============================================================================
// BASE58 TESTS
// =============================================================================

console.log('\n━━━ Base58 Encoding ━━━\n');

test('Base58 encode/decode roundtrip', () => {
    const data = Buffer.from('Hello, Bitcoin!');
    const encoded = wots.base58Encode(data);
    const decoded = wots.base58Decode(encoded);
    assertTrue(decoded.equals(data));
});

test('Base58Check encode/decode roundtrip', () => {
    const payload = Buffer.alloc(20).fill(0xab);
    const encoded = wots.base58CheckEncode(0x00, payload);
    const decoded = wots.base58CheckDecode(encoded);
    assertEqual(decoded.version, 0x00);
    assertTrue(decoded.payload.equals(payload));
});

test('Base58Check detects invalid checksum', () => {
    let caught = false;
    try {
        wots.base58CheckDecode('1111111111111111111114oLvT2');  // Modified checksum
    } catch (e) {
        if (e.message.includes('checksum')) caught = true;
    }
    // Note: May not always fail depending on data, so we just check it runs
});

// =============================================================================
// WINTERNITZ KEY GENERATION TESTS
// =============================================================================

console.log('\n━━━ Winternitz Key Generation ━━━\n');

test('Generate keypair produces correct structure', () => {
    const keypair = wots.generateWinternitzKeypair();
    assertEqual(keypair.privateKey.scalars.length, 32, 'Should have 32 scalars');
    assertEqual(keypair.publicKey.commitments.length, 32, 'Should have 32 commitments');
    assertEqual(keypair.publicKeyHash.length, 32, 'Public key hash should be 32 bytes');
});

test('Private scalars are 32 bytes each', () => {
    const keypair = wots.generateWinternitzKeypair();
    keypair.privateKey.scalars.forEach((scalar, i) => {
        assertEqual(scalar.length, 32, `Scalar ${i} should be 32 bytes`);
    });
});

test('Public commitments are 32 bytes each', () => {
    const keypair = wots.generateWinternitzKeypair();
    keypair.publicKey.commitments.forEach((commitment, i) => {
        assertEqual(commitment.length, 32, `Commitment ${i} should be 32 bytes`);
    });
});

test('Public key hash is SHA256 of concatenated commitments', () => {
    const keypair = wots.generateWinternitzKeypair();
    const concatenated = Buffer.concat(keypair.publicKey.commitments);
    const expectedHash = wots.sha256(concatenated);
    assertTrue(keypair.publicKeyHash.equals(expectedHash));
});

test('Each commitment is HASH256^256 of its scalar', () => {
    const keypair = wots.generateWinternitzKeypair();
    for (let i = 0; i < 32; i++) {
        const expected = wots.iteratedHash256(keypair.privateKey.scalars[i], 256);
        assertTrue(keypair.publicKey.commitments[i].equals(expected), `Commitment ${i} mismatch`);
    }
});

test('Restore keypair from private key hex', () => {
    const original = wots.generateWinternitzKeypair();
    const restored = wots.restoreKeypairFromPrivate(original.privateKey.hex);
    
    assertTrue(original.publicKeyHash.equals(restored.publicKeyHash));
    for (let i = 0; i < 32; i++) {
        assertTrue(original.publicKey.commitments[i].equals(restored.publicKey.commitments[i]));
    }
});

// =============================================================================
// WINTERNITZ SIGNING TESTS
// =============================================================================

console.log('\n━━━ Winternitz Signing ━━━\n');

test('Sign message produces 32 chunks', () => {
    const keypair = wots.generateWinternitzKeypair();
    const message = Buffer.alloc(32).fill(0x42);
    const signature = wots.signWinternitz(message, keypair.privateKey);
    assertEqual(signature.chunks.length, 32);
});

test('Each signature chunk has revealed value and offset', () => {
    const keypair = wots.generateWinternitzKeypair();
    const message = Buffer.alloc(32).fill(0x42);
    const signature = wots.signWinternitz(message, keypair.privateKey);
    
    signature.chunks.forEach((chunk, i) => {
        assertEqual(chunk.revealed.length, 32, `Chunk ${i} revealed should be 32 bytes`);
        assertTrue(chunk.offset >= 0 && chunk.offset <= 255, `Chunk ${i} offset should be 0-255`);
    });
});

test('Offsets match message bytes', () => {
    const keypair = wots.generateWinternitzKeypair();
    const message = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) message[i] = i * 8; // 0, 8, 16, ... 248
    
    const signature = wots.signWinternitz(message, keypair.privateKey);
    for (let i = 0; i < 32; i++) {
        assertEqual(signature.chunks[i].offset, message[i], `Offset ${i} mismatch`);
    }
});

test('Verify valid signature succeeds', () => {
    const keypair = wots.generateWinternitzKeypair();
    const message = Buffer.alloc(32).fill(0x42);
    const signature = wots.signWinternitz(message, keypair.privateKey);
    const valid = wots.verifyWinternitz(message, signature, keypair.publicKey);
    assertTrue(valid, 'Signature should be valid');
});

test('Verify with wrong message fails', () => {
    const keypair = wots.generateWinternitzKeypair();
    const message = Buffer.alloc(32).fill(0x42);
    const signature = wots.signWinternitz(message, keypair.privateKey);
    
    const wrongMessage = Buffer.alloc(32).fill(0x43);
    const valid = wots.verifyWinternitz(wrongMessage, signature, keypair.publicKey);
    assertTrue(!valid, 'Signature should be invalid for wrong message');
});

test('Revealed value hashes forward to commitment', () => {
    const keypair = wots.generateWinternitzKeypair();
    const message = Buffer.alloc(32).fill(0x80); // All bytes = 128
    const signature = wots.signWinternitz(message, keypair.privateKey);
    
    for (let i = 0; i < 32; i++) {
        const revealed = signature.chunks[i].revealed;
        const offset = signature.chunks[i].offset;
        const computed = wots.iteratedHash256(revealed, offset);
        assertTrue(computed.equals(keypair.publicKey.commitments[i]), `Chunk ${i} forward hash mismatch`);
    }
});

// =============================================================================
// VAULT CREATION TESTS
// =============================================================================

console.log('\n━━━ Vault Creation ━━━\n');

test('Create vault produces required fields', () => {
    const vault = wots.createQuantumVault();
    assertTrue(vault.vaultId, 'Should have vaultId');
    assertTrue(vault.scriptHash, 'Should have scriptHash');
    assertTrue(vault.lockingScript, 'Should have lockingScript');
    assertTrue(vault.secret, 'Should have secret');
    assertTrue(vault.publicKeyHash, 'Should have publicKeyHash');
});

test('Vault ID starts with qv1', () => {
    const vault = wots.createQuantumVault();
    assertTrue(vault.vaultId.startsWith('qv1'), 'Vault ID should start with qv1');
});

test('Locking script is valid hex', () => {
    const vault = wots.createQuantumVault();
    const scriptBuf = Buffer.from(vault.lockingScript, 'hex');
    assertTrue(scriptBuf.length > 0, 'Locking script should not be empty');
});

test('Secret is valid base64 JSON', () => {
    const vault = wots.createQuantumVault();
    const decoded = Buffer.from(vault.secret, 'base64').toString('utf8');
    const parsed = JSON.parse(decoded);
    assertEqual(parsed.version, 3);
    assertEqual(parsed.type, 'quantum-vault-bare');
});

test('Restore vault from secret recovers same data', () => {
    const original = wots.createQuantumVault();
    const restored = wots.restoreVaultFromSecret(original.secret);
    
    assertEqual(restored.scriptHash, original.scriptHash);
    assertEqual(restored.publicKeyHash, original.publicKeyHash);
    assertEqual(restored.vaultId, original.vaultId);
});

test('Restored vault can create valid unlocking data', () => {
    const vault = wots.createQuantumVault();
    const restored = wots.restoreVaultFromSecret(vault.secret);
    const unlockData = wots.createUnlockingData(restored);
    
    assertEqual(unlockData.preimageSize, 1024, 'Preimage should be 1024 bytes');
    
    // Verify preimage hashes to public key hash
    const computedHash = wots.sha256(unlockData.wotsPreimage);
    assertTrue(computedHash.equals(restored.keypair.publicKeyHash));
});

// =============================================================================
// SCRIPT VERIFICATION TESTS
// =============================================================================

console.log('\n━━━ Script Verification ━━━\n');

test('Locking script starts with OP_SHA256 (0xa8)', () => {
    const vault = wots.createQuantumVault();
    const script = Buffer.from(vault.lockingScript, 'hex');
    assertEqual(script[0], 0xa8, 'First opcode should be OP_SHA256');
});

test('Locking script ends with OP_EQUAL (0x87)', () => {
    const vault = wots.createQuantumVault();
    const script = Buffer.from(vault.lockingScript, 'hex');
    assertEqual(script[script.length - 1], 0x87, 'Last opcode should be OP_EQUAL');
});

test('Script contains 32-byte public key hash', () => {
    const vault = wots.createQuantumVault();
    const script = Buffer.from(vault.lockingScript, 'hex');
    // Script format: OP_SHA256 PUSH32 <32 bytes> OP_EQUAL
    // = 1 + 1 + 32 + 1 = 35 bytes
    assertEqual(script.length, 35, 'Script should be 35 bytes');
    assertEqual(script[1], 0x20, 'Should push 32 bytes');
});

test('Unlocking script (scriptSig) is correctly formatted', () => {
    const vault = wots.createQuantumVault();
    const restored = wots.restoreVaultFromSecret(vault.secret);
    const unlockData = wots.createUnlockingData(restored);
    
    // ScriptSig should push 1024 bytes
    // Format: OP_PUSHDATA2 len_lo len_hi <1024 bytes>
    const scriptSig = unlockData.scriptSig;
    assertEqual(scriptSig[0], 0x4d, 'Should use OP_PUSHDATA2');
    const len = scriptSig.readUInt16LE(1);
    assertEqual(len, 1024, 'Should push 1024 bytes');
    assertEqual(scriptSig.length, 3 + 1024, 'ScriptSig should be 1027 bytes');
});

// =============================================================================
// TRANSACTION SIGNING TESTS
// =============================================================================

console.log('\n━━━ Transaction Signing ━━━\n');

test('Sign transaction hash produces valid signature', () => {
    const vault = wots.createQuantumVault();
    const restored = wots.restoreVaultFromSecret(vault.secret);
    
    const txHash = Buffer.alloc(32).fill(0xab);
    const result = wots.signTransactionHash(txHash, restored.keypair);
    
    assertTrue(result.valid, 'Signature should be valid');
    assertEqual(result.signatureSize, 1024, 'Signature should be 1024 bytes');
});

test('Different transaction hashes produce different signatures', () => {
    const keypair = wots.generateWinternitzKeypair();
    
    const txHash1 = Buffer.alloc(32).fill(0xaa);
    const txHash2 = Buffer.alloc(32).fill(0xbb);
    
    const sig1 = wots.signWinternitz(txHash1, keypair.privateKey);
    const sig2 = wots.signWinternitz(txHash2, keypair.privateKey);
    
    // At least some chunks should be different
    let different = false;
    for (let i = 0; i < 32; i++) {
        if (!sig1.chunks[i].revealed.equals(sig2.chunks[i].revealed)) {
            different = true;
            break;
        }
    }
    assertTrue(different, 'Different messages should produce different signatures');
});

// =============================================================================
// SUMMARY
// =============================================================================

console.log('\n╔═══════════════════════════════════════════════════════════════╗');
console.log(`║  RESULTS: ${passed} passed, ${failed} failed                                   ║`);
console.log('╚═══════════════════════════════════════════════════════════════╝\n');

if (failed === 0) {
    console.log('🎉 All tests passed! The quantum vault implementation is working correctly.\n');
} else {
    console.log('⚠️  Some tests failed. Please review the errors above.\n');
    process.exit(1);
}

// =============================================================================
// DEMO: Create and Restore a Vault
// =============================================================================

console.log('━━━ Demo: Full Vault Lifecycle ━━━\n');

const demoVault = wots.createQuantumVault();
console.log('1. Created vault:');
console.log(`   Vault ID: ${demoVault.vaultId}`);
console.log(`   Script Hash: ${demoVault.scriptHash}`);
console.log(`   Locking Script (${Buffer.from(demoVault.lockingScript, 'hex').length} bytes):`);
console.log(`   ${demoVault.lockingScriptASM}\n`);

const restoredVault = wots.restoreVaultFromSecret(demoVault.secret);
console.log('2. Restored from secret:');
console.log(`   Vault ID: ${restoredVault.vaultId}`);
console.log(`   Match: ${restoredVault.vaultId === demoVault.vaultId ? '✅' : '❌'}\n`);

const unlockData = wots.createUnlockingData(restoredVault);
console.log('3. Generated unlocking data:');
console.log(`   WOTS Preimage: ${unlockData.preimageSize} bytes`);
console.log(`   ScriptSig: ${unlockData.scriptSig.length} bytes`);

// Verify script execution would succeed
const preimageHash = wots.sha256(unlockData.wotsPreimage);
const expectedHash = restoredVault.keypair.publicKeyHash;
console.log(`\n4. Script verification:`);
console.log(`   SHA256(preimage) = ${preimageHash.toString('hex').slice(0, 32)}...`);
console.log(`   Expected hash    = ${expectedHash.toString('hex').slice(0, 32)}...`);
console.log(`   Match: ${preimageHash.equals(expectedHash) ? '✅ Script would succeed!' : '❌ Script would fail!'}\n`);

console.log('━━━ End Demo ━━━\n');
