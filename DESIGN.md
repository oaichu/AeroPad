# DESIGN SPECIFICATION — AETHERPAD & 2FA VAULT

## 1. Visual Contract & Design Tokens
All UI and rendering must strictly consume tokens defined in `design/tokens-v1.json`.

* **Base Surface (Dark Mode - Default)**:
  - Canvas: `#07090E` (Deep Space Obsidian)
  - Surface Glass: `rgba(16, 22, 34, 0.75)` with `backdrop-filter: blur(28px) saturate(180%)`
  - Elevated Cards: `rgba(22, 30, 46, 0.90)`
* **Light Mode Surface**:
  - Canvas: `#F4F6FB` (Frost Titanium)
  - Surface Glass: `rgba(255, 255, 255, 0.82)`
* **Borders & Outlines**:
  - Hairline: `1px solid rgba(255, 255, 255, 0.08)` (Dark) / `rgba(0, 0, 0, 0.08)` (Light)
  - Active Glow: `rgba(0, 242, 254, 0.4)`
* **Accents & Semantics**:
  - `Electric Cyan`: `#00F2FE` (Primary branding, TOTP live digit highlight)
  - `Web3 Indigo`: `#6366F1` (Secondary badges, aura glow)
  - `Security Mint`: `#10B981` (Safe encryption state, passed checks)
  - `Expiry Amber`: `#F59E0B` (TOTP countdown < 5 seconds warning)
  - `Destructive Coral`: `#F43F5E` (Delete / Reset actions)

## 2. Typography
* **Prose, Navigation & Controls**: `-apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Inter', sans-serif`
* **Digits, Secret Keys & Monospace Codes**: `'SF Mono', 'JetBrains Mono', 'Fira Code', monospace` with `font-variant-numeric: tabular-nums` to ensure stable rendering during countdowns.

## 3. Architecture & Interaction Model
* **Zero-Knowledge Principle**: Pure client-side execution; all cryptographic operations (TOTP RFC 6238 HMAC calculation, AES-256 GCM storage encryption, QR generation & decoding) take place strictly within the browser using Web Crypto API.
* **Storage Hierarchy**: IndexedDB / LocalStorage key-value pairs with isolated keys (`aether_notes`, `aether_totp`, `aether_theme`).
