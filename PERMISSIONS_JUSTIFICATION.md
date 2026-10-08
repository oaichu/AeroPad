# Chrome Web Store Permissions Justification for AeroPad

This document provides explicit technical justification for each permission declared in `manifest.json` for review by the Google Chrome Web Store Review Team.

## 1. `storage`
- **Justification:** Required to save the user's encrypted 2FA vault, domain-associated secret tokens, user preferences (auto-lock duration, language selection), and encrypted notes locally using `chrome.storage.local`.
- **Data Treatment:** All data stored is encrypted with AES-256-GCM.

## 2. `activeTab` & `scripting`
- **Justification:** Required to detect 2FA/OTP input fields on the active webpage when the user triggers 2FA autofill via the extension popup or keyboard shortcut (`Ctrl+Shift+F`), and to inject the calculated TOTP code into the focused field.

## 3. `commands`
- **Justification:** Required to register the global browser keyboard shortcut `fill-current` (`Ctrl+Shift+F`), enabling users to autofill the active 2FA code without opening the popup UI.

## 4. `host_permissions: ["<all_urls>"]`
- **Justification:** Two-factor authentication is implemented across thousands of disparate domains, enterprise portals, and internal intranet sites. In order to offer autofill matching for the domain currently being logged into, the extension needs to match authentication pages across arbitrary domains.
- **Security Safeguards:** Content scripts only read domain origins (`window.location.origin`) to query the local matching vault entry, and never transmit or exfiltrate any page content.
