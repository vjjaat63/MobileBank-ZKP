function checkStoredKey() {
    const accInput = document.getElementById("account_number");
    const keyStatus = document.getElementById("key-status");
    const manualContainer = document.getElementById("manual-key-container");
    if (!accInput || !keyStatus) return;

    const acc = accInput.value.trim();
    if (!acc) {
        keyStatus.innerHTML = "";
        if (manualContainer) manualContainer.style.display = "none";
        return;
    }

    const storedKey = localStorage.getItem(`mobilebank_sk_${acc}`);
    if (storedKey) {
        keyStatus.innerHTML = "<span style='color: #2e7d32;'>✓ Private key detected on this device</span>";
        if (manualContainer) manualContainer.style.display = "none";
    } else {
        keyStatus.innerHTML = "<span style='color: #e65100;'>⚠️ Private key not found on this device</span>";
        if (manualContainer) manualContainer.style.display = "block";
    }
}

async function login() {
    const accInput = document.getElementById("account_number");
    const manualKeyInput = document.getElementById("private_key");
    const msgContainer = document.getElementById("msg");
    const handshakeStatus = document.getElementById("handshake-status");
    const loginBtn = document.getElementById("login-btn");

    const s1 = document.getElementById("step-1");
    const s2 = document.getElementById("step-2");
    const s3 = document.getElementById("step-3");
    const s4 = document.getElementById("step-4");

    const acc = accInput.value.trim();
    if (!acc) {
        msgContainer.innerHTML = "<p style='color: red;'>Please enter your account number.</p>";
        msgContainer.style.display = "block";
        return;
    }

    let privKey = localStorage.getItem(`mobilebank_sk_${acc}`);
    if (!privKey && manualKeyInput) {
        privKey = manualKeyInput.value.trim();
    }

    if (!privKey) {
        msgContainer.innerHTML = "<p style='color: red;'>Missing private key! Provide your key or register a new account on this device.</p>";
        msgContainer.style.display = "block";
        return;
    }

    try {
        if (loginBtn) loginBtn.disabled = true;
        msgContainer.style.display = "none";
        if (handshakeStatus) handshakeStatus.style.display = "block";

        if (s1) { s1.innerText = "⏳ Move 1: Generating commitment R = g^r mod p..."; s1.style.color = "#2196F3"; }
        if (s2) { s2.innerText = "⚪ Move 2: Requesting 256-bit server challenge c..."; s2.style.color = "#999"; }
        if (s3) { s3.innerText = "⚪ Move 3: Computing response s = (r + c·x) mod q..."; s3.style.color = "#999"; }
        if (s4) { s4.innerText = "⚪ Verifying proof at bank..."; s4.style.color = "#999"; }

        // Load parameters
        await window.schnorrClient.loadParameters();

        // Prover Move 1: Create commitment (r, R)
        const commitment = window.schnorrClient.createCommitment();
        const deviceId = SchnorrClient.getDeviceId();

        if (s1) { s1.innerText = "✓ Move 1: Commitment R computed"; s1.style.color = "#4CAF50"; }
        if (s2) { s2.innerText = "⏳ Move 2: Sending commitment to server..."; s2.style.color = "#2196F3"; }

        // Send Move 1 to server -> Receive Move 2 (challenge c, session_id)
        const commitRes = await fetch("/auth/commit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                account_number: acc,
                device_id: deviceId,
                commitment: commitment.commitment_R
            })
        });
        const commitData = await commitRes.json();

        if (!commitData.success) {
            throw new Error(commitData.message || "Failed to initiate handshake");
        }

        const { session_id, challenge } = commitData;
        if (s2) { s2.innerText = "✓ Move 2: Received 256-bit challenge c"; s2.style.color = "#4CAF50"; }
        if (s3) { s3.innerText = "⏳ Move 3: Computing response s = (r + c·x) mod q..."; s3.style.color = "#2196F3"; }

        // Prover Move 3: Compute response s = (r + c*x) mod q
        const response_s = window.schnorrClient.createResponse(commitment.nonce_r, challenge, privKey);

        if (s3) { s3.innerText = "✓ Move 3: Computed response s"; s3.style.color = "#4CAF50"; }
        if (s4) { s4.innerText = "⏳ Verifying proof on server..."; s4.style.color = "#2196F3"; }

        // Send Move 3 to server -> Verify
        const verifyRes = await fetch("/auth/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: session_id,
                response: response_s
            })
        });
        const verifyData = await verifyRes.json();

        if (verifyData.success) {
            if (s4) { s4.innerText = "✓ Zero-Knowledge Proof Verified! Success!"; s4.style.color = "#4CAF50"; }
            localStorage.setItem("mobilebank_last_account", acc);
            window.location.href = "/dashboard";
        } else {
            if (s4) { s4.innerText = "✗ Verification failed"; s4.style.color = "#f44336"; }
            throw new Error(verifyData.message || "Zero-Knowledge authentication failed");
        }

    } catch (err) {
        msgContainer.innerHTML = `<p style="color: red;">❌ ${err.message}</p>`;
        msgContainer.style.display = "block";
    } finally {
        if (loginBtn) loginBtn.disabled = false;
    }
}

async function register() {
    const nameInput = document.getElementById("name");
    const balanceInput = document.getElementById("balance");
    const messageContainer = document.getElementById("msg");
    const statusContainer = document.getElementById("crypto-status");
    const registerBtn = document.getElementById("register-btn");

    const name = nameInput.value.trim();
    const balance = balanceInput.value.trim();

    if (!name || balance === "") {
        messageContainer.innerHTML = "<p style='color: red;'>Please enter your full name and initial deposit.</p>";
        messageContainer.style.display = "block";
        return;
    }

    try {
        if (registerBtn) registerBtn.disabled = true;
        if (statusContainer) {
            statusContainer.innerText = "⏳ Loading cryptographic group parameters...";
            statusContainer.style.display = "block";
        }

        // 1. Load parameters from bank
        await window.schnorrClient.loadParameters();

        if (statusContainer) {
            statusContainer.innerText = "🔐 Generating 3072-bit private key locally on device...";
        }

        // Allow UI to update before computation
        await new Promise(r => setTimeout(r, 50));

        // 2. Generate local keypair
        const keypair = window.schnorrClient.generateKeyPair();
        const deviceId = SchnorrClient.getDeviceId();

        if (statusContainer) {
            statusContainer.innerText = "📡 Transmitting public key to bank (private key stays on device)...";
        }

        // 3. Send registration payload (public key as decimal string, no password)
        const response = await fetch("/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                name: name,
                balance: balance,
                public_key: keypair.publicKey,
                device_id: deviceId
            })
        });

        const result = await response.json();

        if (result.success) {
            // Save private key bound to this account on this device
            localStorage.setItem(`mobilebank_sk_${result.account_number}`, keypair.privateKey);
            localStorage.setItem(`mobilebank_pk_${result.account_number}`, keypair.publicKey);
            localStorage.setItem("mobilebank_last_account", result.account_number);

            messageContainer.innerHTML = `
                <div style="background: #e8f5e9; border: 1px solid #4CAF50; padding: 14px; border-radius: 6px; color: #2e7d32; text-align: left;">
                    <strong>🎉 ${result.message}</strong>
                    <p style="margin-top: 8px; font-size: 12px; color: #333;">
                        🔑 Your Schnorr private key has been generated and saved locally on this device.
                    </p>
                    <div style="background: #fff3e0; border-left: 3px solid #ff9800; padding: 8px; margin: 10px 0; font-size: 11px; color: #b78103;">
                        ⚠️ <strong>Warning:</strong> The bank never holds your private key. If you clear your browser data or switch devices, you must have this backup to restore access!
                    </div>
                    <button type="button" onclick="downloadBackup(${result.account_number})" style="background-color: #2e7d32; color: white; width: 100%; padding: 8px; font-size: 13px; cursor: pointer; border: none; border-radius: 4px; font-weight: bold;">
                        📥 Download Key Backup (.json)
                    </button>
                    <div style="margin-top: 10px; text-align: center;">
                        <a href="/login" style="font-size: 13px; font-weight: bold; color: #1b5e20;">Continue to Sign In →</a>
                    </div>
                </div>
            `;
            if (statusContainer) statusContainer.style.display = "none";
        } else {
            messageContainer.innerHTML = `<p style="color: red;">❌ ${result.message}</p>`;
            if (statusContainer) statusContainer.style.display = "none";
        }
    } catch (err) {
        messageContainer.innerHTML = `<p style="color: red;">❌ Registration error: ${err.message}</p>`;
        if (statusContainer) statusContainer.style.display = "none";
    } finally {
        if (registerBtn) registerBtn.disabled = false;
        messageContainer.style.display = "block";
    }
}

/**
 * Download Account and Private Key Backup file (.json)
 */
function downloadBackup(accountNumber) {
    const privKey = localStorage.getItem(`mobilebank_sk_${accountNumber}`);
    const pubKey = localStorage.getItem(`mobilebank_pk_${accountNumber}`);
    const deviceId = localStorage.getItem("mobilebank_device_id");
    const fingerprint = localStorage.getItem("mobilebank_param_fp");

    if (!privKey) {
        alert("No private key found on this device for account #" + accountNumber);
        return;
    }

    const backupData = {
        system: "MobileBank-ZKP",
        version: "1.0",
        algorithm: "schnorr-dl-3072",
        account_number: accountNumber,
        device_id: deviceId,
        public_key: pubKey,
        private_key: privKey,
        param_fingerprint: fingerprint,
        created_at: new Date().toISOString()
    };

    const blob = new Blob([JSON.stringify(backupData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `mobilebank_backup_acc_${accountNumber}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Restore Account & Keys from an uploaded Backup File (.json)
 */
function handleBackupFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const data = JSON.parse(e.target.result);
            if (!data.account_number || !data.private_key) {
                throw new Error("Invalid backup format: missing account_number or private_key");
            }

            // Restore keys and device binding into browser localStorage
            localStorage.setItem(`mobilebank_sk_${data.account_number}`, data.private_key);
            if (data.public_key) {
                localStorage.setItem(`mobilebank_pk_${data.account_number}`, data.public_key);
            }
            if (data.device_id) {
                localStorage.setItem("mobilebank_device_id", data.device_id);
            }
            localStorage.setItem("mobilebank_last_account", data.account_number);

            // Update UI
            const accInput = document.getElementById("account_number");
            if (accInput) {
                accInput.value = data.account_number;
            }
            checkStoredKey();

            const msgContainer = document.getElementById("msg");
            if (msgContainer) {
                msgContainer.innerHTML = `
                    <div style="background: #e8f5e9; border: 1px solid #4CAF50; padding: 10px; border-radius: 4px; color: #2e7d32; font-size: 12px; text-align: left;">
                        ✓ Account <strong>#${data.account_number}</strong> & Private Key successfully restored from backup!<br>
                        Click <strong>Authenticate (ZKP)</strong> to sign in.
                    </div>
                `;
                msgContainer.style.display = "block";
            }
        } catch (err) {
            alert("Failed to restore backup file: " + err.message);
        }
    };
    reader.readAsText(file);
}

async function deposite() {
    const amount = document.getElementById("dipo-amount").value;
    const response = await fetch("/deposite", {
        method: "POST", 
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            amount: amount
        })
    });
    const result = await response.json();
    if (result.redirect) {
        window.location.href = result.redirect;
        return;
    }
    const messageContainer = document.getElementById("dipo-msg");
    messageContainer.innerHTML = `<p>${result.message}</p>`;
}

async function withdraw() {
    const amount = document.getElementById("with-amount").value;
    const response = await fetch("/withdraw", {
        method: "POST", 
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            amount: amount
        })
    });
    const result = await response.json();
    if (result.redirect) {
        window.location.href = result.redirect;
        return;
    }
    const messageContainer = document.getElementById("with-msg");
    messageContainer.innerHTML = `<p>${result.message}</p>`;
}

async function transfer() {
    const recipient = document.getElementById("recipient").value;
    const amount = document.getElementById("amount").value;
    const response = await fetch("/transfer", {
        method: "POST", 
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            recipient: recipient,
            amount: amount
        })
    });
    const result = await response.json();
    if (result.redirect) {
        window.location.href = result.redirect;
        return;
    }
    const messageContainer = document.getElementById("tran-msg");
    messageContainer.innerHTML = `<p>${result.message}</p>`;
}

async function view_balance(){
    const response = await fetch("/view_balance", {
        method: "POST", 
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({})
    });
    const result = await response.json();
    if (result.redirect) {
        window.location.href = result.redirect;
        return;
    }
    hideall();
    const balance_message = document.getElementById("bal-msg");
    document.getElementById("bal").style.display = "flex";
    balance_message.innerHTML = `<p>${result.message}</p>`;
    balance_message.style.display = "block";
}

async function logout(){
    const response = await fetch("/logout", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({

        })
    });
    const result = await response.json()
    if (result.success){
        window.location.href = result.redirect;
    }
}

async function transaction_history(){
    const response = await fetch("/transaction_history",{
        method: "POST",
        headers:{
            "Content-Type": "application/json"
        },
        body: JSON.stringify({})
    });
    const result = await response.json()
    if (result.success){
        const historyContainer = document.getElementById("history-data");
        historyContainer.innerHTML = "";
        if (result.data.length == 0){
            historyContainer.innerHTML = "<P> No Transactions Found </p>"
        }
        let tableHTML = `
            <table border="1" cellpadding="5" cellspacing="0" style="width: 100%; text-align: center;">
                    <tr>
                        <th>ID</th>
                        <th>Date</th>
                        <th>Type</th>
                        <th>From Account</th>
                        <th>To Account</th>
                        <th>Amount</th>
                    </tr>
        `;
        result.data.forEach(transaction => {
            tableHTML += `
                <tr>
                    <td>${transaction.Transaction_id}</td>
                    <td>${transaction.Date}</td>
                    <td>${transaction.Type}</td>
                    <td>${transaction.Sender}</td>
                    <td>${transaction.Receipent}</td>
                    <td>${transaction.Amount}</td>
                </tr>
            `;
        });
        tableHTML += "</table>";
        historyContainer.innerHTML = tableHTML;
        document.getElementById("hist").style.display = "block";
        document.getElementById("dipo").style.display = "none";
        document.getElementById("with").style.display = "none";
        document.getElementById("tran").style.display = "none";
    }
    else{
        historyContainer.innerHTML = `<p>${result.message}</p>`
    }
    
}

function dashboard(){
    window.location.href = "/dashboard"
}

function getDeposite(){
    hideall();
    document.getElementById("dipo").style.display = "flex";
}

function getWithdraw(){
    hideall();
    document.getElementById("with").style.display = "flex";
    
}

function getTransfer(){
    hideall();
    document.getElementById("tran").style.display = "flex";
    
}

function goToLogin(){
    window.location.href = "/login";
}
function goToRegister(){
    window.location.href = "/register"
}
function hideall(){
    document.getElementById("dipo").style.display = "none";
    document.getElementById("bal").style.display = "none";
    document.getElementById("tran").style.display = "none";
    document.getElementById("dipo").style.display = "none";
    document.getElementById("with").style.display = "none";
    document.getElementById("hist").style.display = "none";
}