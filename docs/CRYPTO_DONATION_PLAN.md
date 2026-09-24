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
1. **Configurable Address Constant**:
   ```javascript
   const CRYPTO_DONATION_CONFIG = {
     evmAddress: '0x0000000000000000000000000000000000000000', // Configurable wallet address
     supportedAssets: ['Arbitrum (ETH / ARB)', 'Ethereum (ETH)', 'Tether USD (USDT)'],
     networks: ['Arbitrum One L2 (Recommended)', 'Ethereum Mainnet (L1)']
   };
   ```
2. **Modal Handlers**: Open on topbar/card click, close on `Esc` key or backdrop click.
3. **Copy-to-Clipboard**: Uses `navigator.clipboard.writeText` with visual feedback (`✓ Copied to clipboard!`).
4. **Clean Pure-SVG QR Code**: Inline SVG vector QR code rendering for crisp display at all zoom levels without loading external image services.
5. **REPL Integration**: Add `donate` or `support` command to REPL responses so developers can type `ciphervault donate` in the terminal to view addresses.

### 4.3. Styling & Micro-Interactions ([`apps/landing/styles.css`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/landing/styles.css))
* Non-intrusive gold/cyan accents matching the active theme.
* Smooth modal fade/scale CSS transitions (`0.2s cubic-bezier(0.16, 1, 0.3, 1)`).
* Responsive stack layout for mobile viewports.

---

## 5. Wallet Address Recommendation & Verification

> [!IMPORTANT]
> **What wallet address should be used?**
> You can provide any standard Ethereum / EVM address that you control. Recommended options:
> 1. **Hardware Wallet Address** (Ledger, Trezor, Keystone): The safest option for personal/team management.
> 2. **Gnosis Safe Multi-Sig**: Ideal if multiple project contributors co-manage funds.
> 3. **Dedicated Hot Wallet Address** (MetaMask, Rabby, Coinbase Wallet): Easiest to set up immediately.
> 
> *Because Arbitrum One and Ethereum share the exact same private key / address derivation, one address receives ETH, USDT, and ARB on both networks seamlessly.*

---

## 6. Execution Steps Upon Approval

1. **Step 1**: Add the CSS styling rules for `.tui-donate-btn`, `.donation-modal`, `.network-pills`, and `.address-copy-deck` into [`apps/landing/styles.css`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/landing/styles.css).
2. **Step 2**: Add the Topbar Support button, Pre-Footer Support Card, and accessible Modal structure into [`apps/landing/index.html`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/landing/index.html).
3. **Step 3**: Implement modal open/close, single-click copy, QR display, and REPL `donate` command in [`apps/landing/script.js`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/apps/landing/script.js).
4. **Step 4**: Verify DOM IDs and asset integrity with `node scripts/verify_landing.cjs`.
5. **Step 5**: Test responsiveness across desktop and mobile.
