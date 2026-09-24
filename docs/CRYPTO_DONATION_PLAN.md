# CipherVault Cryptocurrency Donation Integration Plan

**Document ID:** `PLAN-LANDING-CRYPTO-DONATIONS`  
**Target File(s):** [`apps/landing/index.html`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/landing/index.html), [`apps/landing/script.js`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/landing/script.js), [`apps/landing/styles.css`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/landing/styles.css)  
**Status:** Pending Review & Approval  

---

## 1. Objective & Design Philosophy

To sustain project growth, infrastructure hosting (GCP operator nodes, Caddy gateway, CI runners), and continuous protocol development, CipherVault will accept community donations in cryptocurrency.

### Guiding Principles:
1. **Tasteful & Minor (Non-Intrusive)**: CipherVault is a developer-first cryptographic security engine, not a crowdfunding site. Donation entry points must be clean, elegant, and non-distracting.
2. **Multi-Chain EVM Compatibility**: Ethereum Mainnet and Arbitrum One L2 share the same 20-byte EVM address format (`0x...`). A single address receives:
   - **Ethereum (L1)**: Native `ETH` and `USDT` (ERC-20).
   - **Arbitrum One (L2)**: Native `ETH`, `ARB`, and `USDT` (Arbitrum Bridge).
3. **Zero Third-Party Tracking**: No external payment gateways, iframes, or tracking cookies. Pure vanilla HTML/CSS/JS with SVG QR rendering and instant copy-to-clipboard.
4. **Theme Harmonization**: Matches the 4 terminal palettes (`Cyber`, `Dark`, `Light`, `Mono`).

---

## 2. Supported Assets & Network Routing

Because Arbitrum One is CipherVault's native anchoring layer (settling state in [`CipherVaultRegistry.sol`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/contracts/CipherVaultRegistry.sol)), we will highlight Arbitrum One as the recommended low-fee network while supporting Ethereum Mainnet:

| Asset | Supported Networks | Contract / Token Type | Recommended Tag |
| :--- | :--- | :--- | :--- |
| **Arbitrum (ETH / ARB)** | Arbitrum One L2 | Native ETH + ARB (ERC-20: `0x912ce59144191c1204e64559fe8253a0e49e6548`) | **⚡ Low Gas (< $0.05)** |
| **USDT (Tether)** | Arbitrum One & Ethereum | Arbitrum: `0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9`<br>Ethereum: `0xdAC17F958D2ee523a2206206994597C13D831ec7` | Multi-Chain |
| **Ethereum (ETH)** | Ethereum Mainnet & Arbitrum | Native L1 / L2 Gas Asset | Standard |

> [!NOTE]
> **Single EVM Wallet Address**: You only need **one** Ethereum-compatible address (e.g. from a Ledger, Trezor, MetaMask, or Gnosis Safe multisig). Any tokens sent on Ethereum Mainnet or Arbitrum One L2 to that address will arrive safely in the same wallet.

---

## 3. Visual Placement Strategy

### Point A: Top Navigation Bar Action Button
In the top-right toolbar (alongside `Explorer ↗` and `★ GitHub`), add a sleek action button:
* Label: `❤ Support` or `❤ Donate`
* Clicking it opens the clean **Crypto Donation Modal**.

### Point B: Pre-Footer Community Support Banner
Placed right below Pane 6 (Installation & Quickstart) and before the collapsible REPL bar:
* Title: **"Support Sovereign Secrets & Decentralized Infrastructure"**
* Subtext: *"CipherVault is open-source and community-operated. Donations help fund the independent 3-node storage quorum, Arbitrum L2 gas fees, and automated SLSA/Trivy build runners."*
* Direct address box with one-click `[COPY ADDRESS]` button and `[VIEW QR CODE]` toggle.

---

## 4. Technical Implementation Details

### 4.1. DOM Elements ([`apps/landing/index.html`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/landing/index.html))
1. **Topbar Action Button**: `<button class="tui-donate-btn" id="btn-open-donate" title="Support CipherVault infrastructure with crypto">[❤ Support]</button>`
2. **Pre-Footer Support Card**: Lightweight responsive section styled with `.tui-box`.
3. **Donation Modal Dialog**: Accessible modal (`role="dialog"`, `aria-modal="true"`) with backdrop blur, QR code container, network badges (`Arbitrum One`, `Ethereum`), asset tags (`ETH`, `USDT`, `ARB`), address display, and copy button.

### 4.2. Logic & Interactions ([`apps/landing/script.js`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/landing/script.js))
1. **Configured Recipient EVM Address**:
   ```javascript
   const CRYPTO_DONATION_CONFIG = Object.freeze({
     evmAddress: '0x5f424b4ec88073fd461eb194833681a31adfa311',
     networks: Object.freeze({
       arbitrum: Object.freeze({
         name: 'Arbitrum One L2 (Recommended)',
         label: 'ARBITRUM ONE (L2) EVM ADDRESS:',
         fee: 'LOW GAS < $0.05',
         explorerUrl: 'https://arbiscan.io/address/0x5f424b4ec88073fd461eb194833681a31adfa311',
         notice: 'Send ETH, USDT, or ARB on Arbitrum One L2 to this address.'
       }),
       ethereum: Object.freeze({
         name: 'Ethereum Mainnet (L1)',
         label: 'ETHEREUM MAINNET (L1) EVM ADDRESS:',
         fee: 'STANDARD GAS',
         explorerUrl: 'https://etherscan.io/address/0x5f424b4ec88073fd461eb194833681a31adfa311',
         notice: 'Send ETH or USDT (ERC-20) on Ethereum Mainnet to this address.'
       }),
       sepolia: Object.freeze({
         name: 'Sepolia Testnet (Dev/Test)',
         label: 'SEPOLIA TESTNET EVM ADDRESS:',
         fee: 'TESTNET FAUCET',
         explorerUrl: 'https://sepolia.etherscan.io/address/0x5f424b4ec88073fd461eb194833681a31adfa311',
         notice: 'Send Sepolia ETH or Sepolia Testnet Assets to this address.'
       })
     })
   });
   ```
2. **Modal Handlers**: Open on topbar/card click, close on `Esc` key or backdrop click.
3. **Copy-to-Clipboard**: Uses `navigator.clipboard.writeText` with visual feedback (`✓ ADDRESS COPIED TO CLIPBOARD`).
4. **Clean Pure-SVG QR Code**: Inline SVG vector QR code rendering for crisp display at all zoom levels without loading external image services.
5. **Direct Explorer Verification**: Direct links to Arbiscan, Etherscan, and Sepolia Etherscan so donors can verify the address on-chain before sending.
6. **REPL Integration**: Interactive `donate` and `support` terminal command.

---

## 5. Security & Protection Guidelines

> [!CAUTION]
> **Critical Treasury Security Rules:**
> 1. **Public Address is Read-Only**: `0x5f424b4ec88073fd461eb194833681a31adfa311` is your **public key identifier**. It can ONLY be used to deposit funds. It can NEVER be used to withdraw funds or sign transactions on its own.
> 2. **Never Commit Private Keys**: The corresponding private key or 12/24-word seed phrase must **NEVER** be committed to Git, placed in `.env` files on public servers, or stored on online cloud notes.
> 3. **Hardware Wallet / Multi-Sig**: To protect incoming donations from device compromise, consider holding this address on a hardware device (Ledger, Trezor) or migrating the treasury to a **Safe{Wallet} (Gnosis Safe)** multi-sig on Arbitrum One as treasury balances grow.
> 4. **Runtime Immutability**: The address in `script.js` is wrapped in `Object.freeze()` to prevent rogue browser extensions or runtime tampering from changing the destination address in client memory.
> 5. **Public Explorer Verification**: Donors can inspect the address on [Arbiscan](https://arbiscan.io/address/0x5f424b4ec88073fd461eb194833681a31adfa311) and [Etherscan](https://etherscan.io/address/0x5f424b4ec88073fd461eb194833681a31adfa311) directly from the modal.

---

## 6. Verification Status

* **Static DOM Verification**: Passed (`node scripts/verify_landing.cjs` - 67 IDs verified).
* **Network Coverage**: Arbitrum One L2, Ethereum Mainnet (L1), Sepolia Testnet.
* **Accepted Assets**: ETH, USDT, ARB, Sepolia ETH.

