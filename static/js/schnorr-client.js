/**
 * schnorr-client.js
 * Client-side Schnorr Zero-Knowledge Proof cryptographic operations
 * using native JavaScript BigInt and Web Crypto API.
 */

class SchnorrClient {
    constructor() {
        this.p = null;
        this.q = null;
        this.g = null;
        this.fingerprint = null;
    }

    /**
     * Get or create a persistent device identifier.
     */
    static getDeviceId() {
        let deviceId = localStorage.getItem("mobilebank_device_id");
        if (!deviceId) {
            if (window.crypto && window.crypto.randomUUID) {
                deviceId = "dev_" + window.crypto.randomUUID();
            } else {
                deviceId = "dev_" + Math.random().toString(36).substring(2, 15) + Date.now().toString(36);
            }
            localStorage.setItem("mobilebank_device_id", deviceId);
        }
        return deviceId;
    }

    /**
     * Fetch group parameters from the bank server.
     */
    async loadParameters() {
        if (this.p && this.q && this.g) {
            return { p: this.p, q: this.q, g: this.g, fingerprint: this.fingerprint };
        }
        const res = await fetch("/auth/params");
        const data = await res.json();
        this.p = BigInt(data.p);
        this.q = BigInt(data.q);
        this.g = BigInt(data.g);
        this.fingerprint = data.fingerprint;
        localStorage.setItem("mobilebank_param_fp", this.fingerprint);
        return data;
    }

    /**
     * Fast modular exponentiation (base^exp mod mod).
     */
    static modPow(base, exp, mod) {
        if (mod === 1n) return 0n;
        let res = 1n;
        base = base % mod;
        while (exp > 0n) {
            if (exp % 2n === 1n) {
                res = (res * base) % mod;
            }
            exp = exp / 2n;
            base = (base * base) % mod;
        }
        return res;
    }

    /**
     * Generate random BigInt in [1, max - 1].
     */
    static randomBigInt(max) {
        const byteLen = 32; // 256 bits for subgroup Q
        const array = new Uint8Array(byteLen);
        while (true) {
            window.crypto.getRandomValues(array);
            let hex = "0x" + Array.from(array).map(b => b.toString(16).padStart(2, "0")).join("");
            let val = BigInt(hex);
            if (val >= 1n && val < max) {
                return val;
            }
        }
    }

    /**
     * Generate Schnorr Keypair on client device.
     * x ∈ [1, q-1]
     * y = g^x mod p
     */
    generateKeyPair() {
        if (!this.p || !this.q || !this.g) {
            throw new Error("Parameters not loaded. Call loadParameters() first.");
        }
        const x = SchnorrClient.randomBigInt(this.q);
        const y = SchnorrClient.modPow(this.g, x, this.p);
        return {
            privateKey: x.toString(),
            publicKey: y.toString()
        };
    }

    /**
     * Prover Move 1: Create commitment.
     * r ∈ [1, q-1]
     * R = g^r mod p
     */
    createCommitment() {
        if (!this.p || !this.q || !this.g) {
            throw new Error("Parameters not loaded. Call loadParameters() first.");
        }
        const r = SchnorrClient.randomBigInt(this.q);
        const R = SchnorrClient.modPow(this.g, r, this.p);
        return {
            nonce_r: r.toString(),
            commitment_R: R.toString()
        };
    }

    /**
     * Prover Move 3: Compute response.
     * s = (r + c * x) mod q
     */
    createResponse(nonce_r_str, challenge_c_str, privateKey_x_str) {
        const r = BigInt(nonce_r_str);
        const c = BigInt(challenge_c_str);
        const x = BigInt(privateKey_x_str);
        const q = this.q;
        const s = (r + (c * x) % q) % q;
        return s.toString();
    }
}

window.schnorrClient = new SchnorrClient();
