/**
 * AETHERPAD & 2FA VAULT — FULL CLIENT-SIDE APP LOGIC
 * RFC 6238 TOTP Engine + Client-Side Notes & QR Studio
 */

// ==========================================
// 1. BASE32 & TOTP CRYPTO ENGINE (Web Crypto)
// ==========================================
const Base32 = {
  alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
  
  decode(input) {
    const cleanInput = input.toUpperCase().replace(/[\s=-]/g, '');
    const length = cleanInput.length;
    let bits = 0;
    let value = 0;
    let index = 0;
    const output = new Uint8Array(Math.floor((length * 5) / 8));

    for (let i = 0; i < length; i++) {
      const char = cleanInput[i];
      const val = this.alphabet.indexOf(char);
      if (val === -1) continue;

      value = (value << 5) | val;
      bits += 5;

      if (bits >= 8) {
        output[index++] = (value >>> (bits - 8)) & 255;
        bits -= 8;
      }
    }
    return output.buffer;
  },

  encode(buffer) {
    const bytes = new Uint8Array(buffer);
    let bits = 0;
    let value = 0;
    let output = '';

    for (let i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;

      while (bits >= 5) {
        output += this.alphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }

    if (bits > 0) {
      output += this.alphabet[(value << (5 - bits)) & 31];
    }
    return output;
  },

  randomSecret(length = 16) {
    let result = '';
    const bytes = new Uint8Array(length);
    window.crypto.getRandomValues(bytes);
    for (let i = 0; i < length; i++) {
      result += this.alphabet[bytes[i] % this.alphabet.length];
    }
    return result;
  }
};

// TOTP Generator (RFC 6238)
async function generateTOTP(secretBase32, period = 30, digits = 6, algo = 'SHA-1') {
  try {
    const keyBytes = Base32.decode(secretBase32);
    if (keyBytes.byteLength === 0) return '------';

    const epoch = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epoch / period);

    const counterBuffer = new ArrayBuffer(8);
    const counterView = new DataView(counterBuffer);
    counterView.setBigUint64(0, BigInt(counter), false);

    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: { name: algo } },
      false,
      ['sign']
    );

    const signature = await window.crypto.subtle.sign('HMAC', cryptoKey, counterBuffer);
    const hmacBytes = new Uint8Array(signature);

    const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
    const binary =
      ((hmacBytes[offset] & 0x7f) << 24) |
      ((hmacBytes[offset + 1] & 0xff) << 16) |
      ((hmacBytes[offset + 2] & 0xff) << 8) |
      (hmacBytes[offset + 3] & 0xff);

    const otp = binary % Math.pow(10, digits);
    return otp.toString().padStart(digits, '0');
  } catch (err) {
    console.error('TOTP Calc Error:', err);
    return '000000';
  }
}

// ==========================================
// 2. STATE & DEFAULT DATA
// ==========================================
const DEFAULT_NOTES = [
  {
    id: 'note-1',
    title: '🔐 Web3 & Cold Storage Checklist',
    content: `# Security Blueprint for High-Value Assets\n\n- [x] Khởi tạo ví lạnh Hardware Wallet\n- [x] Sao lưu Seed Phrase vào Titanium Plate\n- [ ] Kích hoạt xác thực 2FA TOTP cho Binance & Kraken\n- [ ] Đặt Master Key cho AetherPad Vault\n\n> "Bảo mật không phải là một sản phẩm, đó là một quy trình."`,
    updatedAt: Date.now() - 1000 * 60 * 15
  },
  {
    id: 'note-2',
    title: '🌐 Cloudflare Pages + DNS Free Setup',
    content: `# Triển Khai Không Tốn Kém\n\n1. Tạo repository trên GitHub: \`aether-vault\`\n2. Đẩy code tĩnh (HTML/CSS/JS) lên branch \`main\`\n3. Vào Cloudflare Dashboard -> Workers & Pages -> Create Application\n4. Chọn repo và click **Deploy Site**\n5. URL mặc định: \`https://aether-vault.pages.dev\` (SSL trọn đời, 0đ/tháng)`,
    updatedAt: Date.now() - 1000 * 60 * 120
  }
];

const DEFAULT_VAULT_ACCOUNTS = [
  {
    id: 'totp-1',
    issuer: 'Binance Exchange',
    account: 'trader@web3.io',
    secret: 'JBSWY3DPEHPK3PXP',
    digits: 6,
    period: 30
  },
  {
    id: 'totp-2',
    issuer: 'GitHub DevSecOps',
    account: 'oaichu-security',
    secret: 'NBSWY3DPEHPK3PXQ',
    digits: 6,
    period: 30
  },
  {
    id: 'totp-3',
    issuer: 'Google Cloud Platform',
    account: 'admin@aethervault.io',
    secret: 'MZXW6YTBOI======',
    digits: 6,
    period: 30
  },
  {
    id: 'totp-4',
    issuer: 'Solana Validator',
    account: 'sol_val_key_01',
    secret: 'KRUGS4ZANFZSAYJA',
    digits: 6,
    period: 30
  }
];

// App State
let appState = {
  notes: JSON.parse(localStorage.getItem('aether_notes')) || DEFAULT_NOTES,
  activeNoteId: null,
  totpAccounts: JSON.parse(localStorage.getItem('aether_totp')) || DEFAULT_VAULT_ACCOUNTS,
  theme: localStorage.getItem('aether_theme') || 'dark',
  currentTab: 'notepad',
  current2FASubtab: 'vault',
  editorMode: 'edit'
};

// ==========================================
// 3. INITIALIZATION & ROUTING
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initNavigation();
  initNotepad();
  initTOTPStudio();
  initDecoder();
  startGlobalTOTPTimer();
  updateStorageStat();
});

// Toast Notifications
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = 'toast-item glass-panel';
  
  let iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00F2FE" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
  if (type === 'error') {
    iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#F43F5E" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`;
  }

  toast.innerHTML = `${iconSvg} <span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 2600);
}

// ==========================================
// 4. THEME & NAVIGATION
// ==========================================
function initTheme() {
  const root = document.documentElement;
  if (appState.theme === 'light') {
    root.classList.remove('dark');
    root.classList.add('light');
  } else {
    root.classList.remove('light');
    root.classList.add('dark');
  }

  document.getElementById('themeToggle').addEventListener('click', () => {
    if (root.classList.contains('dark')) {
      root.classList.remove('dark');
      root.classList.add('light');
      appState.theme = 'light';
    } else {
      root.classList.remove('light');
      root.classList.add('dark');
      appState.theme = 'dark';
    }
    localStorage.setItem('aether_theme', appState.theme);
    renderQRCode();
  });
}

function initNavigation() {
  // Main Segmented Tabs
  document.querySelectorAll('.nav-pill').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.nav-pill').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      
      btn.classList.add('active');
      const tabId = btn.dataset.tab;
      document.getElementById(`tab-${tabId}`).classList.add('active');
      appState.currentTab = tabId;
    });
  });

  // 2FA Subnav Tabs
  document.querySelectorAll('.totp-subpill').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.totp-subpill').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.totp-subpane').forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const subtab = btn.dataset.subtab;
      document.getElementById(`subtab-${subtab}`).classList.add('active');
      appState.current2FASubtab = subtab;

      if (subtab === 'generator') {
        renderQRCode();
      }
    });
  });

  // Master Lock Button
  const vaultBtn = document.getElementById('vaultLockBtn');
  vaultBtn.addEventListener('click', () => {
    showToast('Vault bảo mật đang ở trạng thái Hoạt Động (Unlocked)');
  });
}

// ==========================================
// 5. SMART NOTEPAD LOGIC
// ==========================================
function initNotepad() {
  if (appState.notes.length > 0) {
    appState.activeNoteId = appState.notes[0].id;
  }
  renderNotesList();
  loadActiveNote();

  // Inputs
  const titleInput = document.getElementById('noteTitle');
  const contentInput = document.getElementById('noteContent');

  titleInput.addEventListener('input', autoSaveNote);
  contentInput.addEventListener('input', () => {
    autoSaveNote();
    updateWordCounts();
    if (appState.editorMode !== 'edit') {
      renderMarkdownPreview();
    }
  });

  // New Note
  document.getElementById('newNoteBtn').addEventListener('click', () => {
    const newNote = {
      id: 'note-' + Date.now(),
      title: 'Ghi chú không tiêu đề',
      content: '',
      updatedAt: Date.now()
    };
    appState.notes.unshift(newNote);
    appState.activeNoteId = newNote.id;
    saveNotesToStorage();
    renderNotesList();
    loadActiveNote();
    titleInput.focus();
    showToast('Đã tạo ghi chú mới');
  });

  // Delete Note
  document.getElementById('deleteNoteBtn').addEventListener('click', () => {
    if (appState.notes.length <= 1) {
      showToast('Cần giữ lại ít nhất 1 ghi chú', 'error');
      return;
    }
    appState.notes = appState.notes.filter(n => n.id !== appState.activeNoteId);
    appState.activeNoteId = appState.notes[0].id;
    saveNotesToStorage();
    renderNotesList();
    loadActiveNote();
    showToast('Đã xóa ghi chú');
  });

  // Search Notes
  document.getElementById('noteSearch').addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase();
    renderNotesList(q);
  });

  // Editor Modes (Edit / Split / Preview)
  document.querySelectorAll('.editor-mode-toggle button').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.editor-mode-toggle button').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const mode = btn.dataset.mode;
      appState.editorMode = mode;

      const raw = document.getElementById('noteContent');
      const prev = document.getElementById('notePreview');

      if (mode === 'edit') {
        raw.classList.remove('hidden');
        prev.classList.add('hidden');
      } else if (mode === 'preview') {
        raw.classList.add('hidden');
        prev.classList.remove('hidden');
        renderMarkdownPreview();
      } else if (mode === 'split') {
        raw.classList.remove('hidden');
        prev.classList.remove('hidden');
        renderMarkdownPreview();
      }
    });
  });

  // Format Toolbar Actions
  document.querySelectorAll('.editor-toolbar button[data-format]').forEach(btn => {
    btn.addEventListener('click', () => {
      const format = btn.dataset.format;
      insertFormatting(format);
    });
  });

  // Copy Note Content
  document.getElementById('copyNoteContent').addEventListener('click', () => {
    const note = appState.notes.find(n => n.id === appState.activeNoteId);
    if (note) {
      navigator.clipboard.writeText(`${note.title}\n\n${note.content}`);
      showToast('Đã sao chép nội dung ghi chú');
    }
  });

  // Export Dropdown
  const exportBtn = document.getElementById('exportBtn');
  const exportMenu = document.getElementById('exportMenu');
  exportBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    exportMenu.classList.toggle('show');
  });
  document.addEventListener('click', () => exportMenu.classList.remove('show'));

  exportMenu.querySelectorAll('button').forEach(btn => {
    btn.addEventListener('click', () => {
      const format = btn.dataset.export;
      exportNoteFile(format);
    });
  });
}

function renderNotesList(filterQuery = '') {
  const list = document.getElementById('notesList');
  list.innerHTML = '';

  const filtered = appState.notes.filter(n => 
    n.title.toLowerCase().includes(filterQuery) || 
    n.content.toLowerCase().includes(filterQuery)
  );

  filtered.forEach(note => {
    const item = document.createElement('div');
    item.className = `note-item ${note.id === appState.activeNoteId ? 'active' : ''}`;
    
    const timeAgo = formatTimeAgo(note.updatedAt);
    const snippet = note.content.slice(0, 45).replace(/[#*`\n]/g, ' ') || 'Chưa có nội dung...';

    item.innerHTML = `
      <div class="note-item-title">${escapeHTML(note.title || 'Không tiêu đề')}</div>
      <div class="note-item-snippet">${escapeHTML(snippet)}</div>
      <div class="note-item-time">${timeAgo}</div>
    `;

    item.addEventListener('click', () => {
      appState.activeNoteId = note.id;
      renderNotesList(filterQuery);
      loadActiveNote();
    });

    list.appendChild(item);
  });
}

function loadActiveNote() {
  const note = appState.notes.find(n => n.id === appState.activeNoteId);
  if (!note) return;

  document.getElementById('noteTitle').value = note.title;
  document.getElementById('noteContent').value = note.content;
  updateWordCounts();
  renderMarkdownPreview();
}

function autoSaveNote() {
  const note = appState.notes.find(n => n.id === appState.activeNoteId);
  if (!note) return;

  note.title = document.getElementById('noteTitle').value;
  note.content = document.getElementById('noteContent').value;
  note.updatedAt = Date.now();

  saveNotesToStorage();
  renderNotesList();

  const indicator = document.getElementById('saveIndicator');
  indicator.style.opacity = '1';
}

function saveNotesToStorage() {
  localStorage.setItem('aether_notes', JSON.stringify(appState.notes));
  updateStorageStat();
}

function updateWordCounts() {
  const text = document.getElementById('noteContent').value;
  const words = text.trim() ? text.trim().split(/\s+/).length : 0;
  const chars = text.length;
  const readMinutes = Math.max(1, Math.ceil(words / 200));

  document.getElementById('wordCount').textContent = `${words} từ`;
  document.getElementById('charCount').textContent = `${chars} ký tự`;
  document.getElementById('readTime').textContent = `${readMinutes} phút đọc`;
}

function renderMarkdownPreview() {
  const text = document.getElementById('noteContent').value;
  const preview = document.getElementById('notePreview');
  
  // Lightweight markdown parser for instant client-side preview
  let html = escapeHTML(text)
    .replace(/^# (.*$)/gim, '<h1>$1</h1>')
    .replace(/^## (.*$)/gim, '<h2>$1</h2>')
    .replace(/^### (.*$)/gim, '<h3>$1</h3>')
    .replace(/\*\*(.*?)\*\*/gim, '<b>$1</b>')
    .replace(/\*(.*?)\*/gim, '<i>$1</i>')
    .replace(/`([^`]+)`/gim, '<code>$1</code>')
    .replace(/^- \[(x|X)\] (.*$)/gim, '<div class="check-item checked"><input type="checkbox" checked disabled> $2</div>')
    .replace(/^- \[ \] (.*$)/gim, '<div class="check-item"><input type="checkbox" disabled> $2</div>')
    .replace(/^- (.*$)/gim, '<li>$1</li>')
    .replace(/^\> (.*$)/gim, '<blockquote>$1</blockquote>')
    .replace(/\n\n/gim, '<br><br>');

  preview.innerHTML = html || '<p style="color:var(--text-muted)">Bản xem trước trống...</p>';
}

function insertFormatting(type) {
  const textarea = document.getElementById('noteContent');
  const start = textarea.selectionStart;
  const end = textarea.selectionEnd;
  const selText = textarea.value.substring(start, end);

  let insert = '';
  switch (type) {
    case 'bold': insert = `**${selText || 'văn bản in đậm'}**`; break;
    case 'italic': insert = `*${selText || 'văn bản in nghiêng'}*`; break;
    case 'heading': insert = `\n## ${selText || 'Tiêu đề'}\n`; break;
    case 'code': insert = `\`${selText || 'code'}\``; break;
    case 'quote': insert = `\n> ${selText || 'Trích dẫn'}\n`; break;
    case 'list': insert = `\n- ${selText || 'Mục danh sách'}`; break;
    case 'check': insert = `\n- [ ] ${selText || 'Công việc cần làm'}`; break;
  }

  textarea.setRangeText(insert, start, end, 'end');
  autoSaveNote();
  updateWordCounts();
  if (appState.editorMode !== 'edit') renderMarkdownPreview();
}

function exportNoteFile(type) {
  const note = appState.notes.find(n => n.id === appState.activeNoteId);
  if (!note) return;

  let content = '';
  let filename = `${(note.title || 'note').replace(/\s+/g, '_')}`;
  let mimeType = 'text/plain';

  if (type === 'md') {
    content = `# ${note.title}\n\n${note.content}`;
    filename += '.md';
  } else if (type === 'txt') {
    content = `${note.title}\n\n${note.content}`;
    filename += '.txt';
  } else if (type === 'json') {
    content = JSON.stringify(note, null, 2);
    filename += '-backup.json';
    mimeType = 'application/json';
  }

  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`Đã xuất file: ${filename}`);
}

function updateStorageStat() {
  const jsonStr = JSON.stringify(appState);
  const bytes = new Blob([jsonStr]).size;
  const kb = (bytes / 1024).toFixed(1);
  const el = document.getElementById('storageUsage');
  if (el) el.textContent = `${kb} KB`;
}

// ==========================================
// 6. 2FA STUDIO & LIVE TOTP VAULT
// ==========================================
function initTOTPStudio() {
  renderTOTPCards();

  // Generator random secret button
  document.getElementById('randomSecretBtn').addEventListener('click', () => {
    const newSecret = Base32.randomSecret(16);
    document.getElementById('genSecret').value = newSecret;
    renderQRCode();
    showToast('Đã sinh khóa Secret Key mới');
  });

  // Generator inputs change
  ['genIssuer', 'genAccount', 'genSecret', 'genPeriod', 'genDigits'].forEach(id => {
    document.getElementById(id).addEventListener('input', renderQRCode);
  });

  // Copy Gen Secret
  document.getElementById('copyGenSecret').addEventListener('click', () => {
    const sec = document.getElementById('genSecret').value;
    navigator.clipboard.writeText(sec);
    showToast('Đã sao chép khóa bí mật');
  });

  // Copy OTP URL
  document.getElementById('copyOtpUrlBtn').addEventListener('click', () => {
    const uri = getOtpAuthURI();
    navigator.clipboard.writeText(uri);
    showToast('Đã sao chép đường dẫn OTP Auth');
  });

  // Download QR PNG
  document.getElementById('downloadQRBtn').addEventListener('click', downloadQRPNG);

  // Save Gen to Vault
  document.getElementById('saveToVaultBtn').addEventListener('click', () => {
    const issuer = document.getElementById('genIssuer').value.trim() || 'Custom Issuer';
    const account = document.getElementById('genAccount').value.trim() || 'user';
    const secret = document.getElementById('genSecret').value.trim().toUpperCase();

    if (!secret) {
      showToast('Vui lòng nhập hoặc sinh Secret Key', 'error');
      return;
    }

    const newItem = {
      id: 'totp-' + Date.now(),
      issuer,
      account,
      secret,
      digits: parseInt(document.getElementById('genDigits').value) || 6,
      period: parseInt(document.getElementById('genPeriod').value) || 30
    };

    appState.totpAccounts.push(newItem);
    localStorage.setItem('aether_totp', JSON.stringify(appState.totpAccounts));
    renderTOTPCards();
    showToast('Đã lưu mã 2FA vào Vault');

    // Switch to Vault
    document.querySelector('.totp-subpill[data-subtab="vault"]').click();
  });

  // Quick Add 2FA Modal
  const modalBackdrop = document.getElementById('modalBackdrop');
  document.getElementById('quickAdd2FABtn').addEventListener('click', () => {
    modalBackdrop.classList.remove('hidden');
    document.getElementById('modalSecret').value = Base32.randomSecret(16);
  });

  document.getElementById('closeModalBtn').addEventListener('click', () => modalBackdrop.classList.add('hidden'));
  document.getElementById('cancelModalBtn').addEventListener('click', () => modalBackdrop.classList.add('hidden'));

  document.getElementById('confirmAdd2FABtn').addEventListener('click', () => {
    const issuer = document.getElementById('modalIssuer').value.trim() || 'Mã Xác Thực';
    const account = document.getElementById('modalAccount').value.trim() || 'user';
    const secret = document.getElementById('modalSecret').value.trim().toUpperCase();

    if (!secret) {
      showToast('Khóa Secret không được để trống', 'error');
      return;
    }

    appState.totpAccounts.push({
      id: 'totp-' + Date.now(),
      issuer,
      account,
      secret,
      digits: 6,
      period: 30
    });

    localStorage.setItem('aether_totp', JSON.stringify(appState.totpAccounts));
    renderTOTPCards();
    modalBackdrop.classList.add('hidden');
    showToast('Đã thêm tài khoản 2FA');
  });
}

function getOtpAuthURI() {
  const issuer = encodeURIComponent(document.getElementById('genIssuer').value.trim() || 'AetherPad');
  const account = encodeURIComponent(document.getElementById('genAccount').value.trim() || 'user');
  const secret = document.getElementById('genSecret').value.trim().toUpperCase();
  const digits = document.getElementById('genDigits').value;
  const period = document.getElementById('genPeriod').value;

  return `otpauth://totp/${issuer}:${account}?secret=${secret}&issuer=${issuer}&digits=${digits}&period=${period}`;
}

function renderQRCode() {
  const uri = getOtpAuthURI();
  const container = document.getElementById('qrContainer');
  if (!container) return;
  container.innerHTML = '';

  const prevIss = document.getElementById('previewIssuer');
  const prevAcc = document.getElementById('previewAccount');
  if (prevIss) prevIss.textContent = document.getElementById('genIssuer').value || 'AetherPad';
  if (prevAcc) prevAcc.textContent = document.getElementById('genAccount').value || 'admin@aethervault.io';

  try {
    if (typeof qrcode !== 'undefined') {
      const qr = qrcode(0, 'M');
      qr.addData(uri);
      qr.make();
      container.innerHTML = qr.createImgTag(5, 8);
    }
  } catch (err) {
    console.error('QR Render Error:', err);
  }
}

function downloadQRPNG() {
  const img = document.querySelector('#qrContainer img');
  if (!img) return;

  const canvas = document.createElement('canvas');
  canvas.width = 300;
  canvas.height = 300;
  const ctx = canvas.getContext('2d');

  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, 300, 300);
  ctx.drawImage(img, 20, 20, 260, 260);

  const a = document.createElement('a');
  a.download = `2FA-${document.getElementById('genIssuer').value || 'QR'}.png`;
  a.href = canvas.toDataURL('image/png');
  a.click();
  showToast('Đã tải xuống ảnh mã QR');
}

async function renderTOTPCards() {
  const grid = document.getElementById('totpCardsGrid');
  if (!grid) return;
  grid.innerHTML = '';

  for (const acc of appState.totpAccounts) {
    const card = document.createElement('div');
    card.className = 'totp-card glass-panel';
    
    const initial = (acc.issuer || '2F').charAt(0).toUpperCase();
    const currentCode = await generateTOTP(acc.secret, acc.period, acc.digits);
    const formattedCode = currentCode.slice(0, 3) + ' ' + currentCode.slice(3);

    card.innerHTML = `
      <div class="totp-card-top">
        <div class="totp-issuer-group">
          <div class="totp-avatar">${initial}</div>
          <div>
            <div class="totp-issuer-title">${escapeHTML(acc.issuer)}</div>
            <div class="totp-account-label">${escapeHTML(acc.account)}</div>
          </div>
        </div>
        <button class="btn-danger-ghost delete-totp-btn" title="Xóa tài khoản này">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
        </button>
      </div>

      <div class="totp-code-box">
        <div class="totp-code-text" id="code-${acc.id}">${formattedCode}</div>
        <button class="btn-copy-code" title="Sao chép 6 số">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
        </button>
      </div>

      <div class="totp-card-footer">
        <span>Tự động cập nhật mỗi 30s</span>
        <span class="font-mono text-cyan">RFC 6238</span>
      </div>
      <div class="totp-card-progress">
        <div class="totp-card-progress-bar" id="prog-${acc.id}"></div>
      </div>
    `;

    // Copy action
    card.querySelector('.btn-copy-code').addEventListener('click', (e) => {
      e.stopPropagation();
      navigator.clipboard.writeText(currentCode);
      showToast(`Đã sao chép mã: ${currentCode}`);
    });

    // Card click also copies
    card.addEventListener('click', (e) => {
      if (e.target.closest('.delete-totp-btn')) return;
      navigator.clipboard.writeText(currentCode);
      showToast(`Đã sao chép mã: ${currentCode}`);
    });

    // Delete
    card.querySelector('.delete-totp-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      appState.totpAccounts = appState.totpAccounts.filter(a => a.id !== acc.id);
      localStorage.setItem('aether_totp', JSON.stringify(appState.totpAccounts));
      renderTOTPCards();
      showToast('Đã xóa tài khoản khỏi Vault');
    });

    grid.appendChild(card);
  }
}

// Global 30s Countdown Engine Loop
function startGlobalTOTPTimer() {
  setInterval(async () => {
    const now = Math.floor(Date.now() / 1000);
    const remain = 30 - (now % 30);
    const percent = (remain / 30) * 100;

    // Global Top Badge
    const secEl = document.getElementById('globalCountdownSec');
    const circleEl = document.getElementById('globalCountdownCircle');
    if (secEl) secEl.textContent = `${remain}s`;
    if (circleEl) {
      circleEl.setAttribute('stroke-dasharray', `${percent}, 100`);
      if (remain <= 5) {
        circleEl.classList.add('expiring');
      } else {
        circleEl.classList.remove('expiring');
      }
    }

    // Decoder preview timer bar
    const decProg = document.getElementById('decProgressFill');
    if (decProg) decProg.style.width = `${percent}%`;

    // If new cycle starts (remain === 30), update all TOTP cards
    if (remain === 30 || remain === 29) {
      updateAllTOTPValues();
    }

    // Update individual card progress bars
    appState.totpAccounts.forEach(acc => {
      const p = document.getElementById(`prog-${acc.id}`);
      if (p) p.style.width = `${percent}%`;
    });
  }, 1000);
}

async function updateAllTOTPValues() {
  for (const acc of appState.totpAccounts) {
    const code = await generateTOTP(acc.secret, acc.period, acc.digits);
    const el = document.getElementById(`code-${acc.id}`);
    if (el) {
      el.textContent = code.slice(0, 3) + ' ' + code.slice(3);
    }
  }

  // Update decoded live test if visible
  if (currentDecodedSecret) {
    const testCode = await generateTOTP(currentDecodedSecret);
    const display = document.getElementById('decLiveCode');
    if (display) display.innerHTML = `<span>${testCode.slice(0, 3)}</span> <span>${testCode.slice(3)}</span>`;
  }
}

// ==========================================
// 7. 2FA DECODER & QR SCANNER
// ==========================================
let currentDecodedSecret = null;
let currentDecodedItem = null;

function initDecoder() {
  const dropZone = document.getElementById('qrDropZone');
  const fileInput = document.getElementById('qrFileInput');
  const decodeBtn = document.getElementById('decodeBtn');
  const rawInput = document.getElementById('rawOtpInput');

  if (!dropZone) return;

  // Drag & drop
  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      handleQRFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleQRFile(e.target.files[0]);
    }
  });

  // Paste image from clipboard
  window.addEventListener('paste', (e) => {
    if (appState.currentTab === 'totp' && appState.current2FASubtab === 'decoder') {
      const items = (e.clipboardData || e.originalEvent.clipboardData).items;
      for (const item of items) {
        if (item.type.indexOf('image') !== -1) {
          const blob = item.getAsFile();
          handleQRFile(blob);
          break;
        }
      }
    }
  });

  // Decode text button
  decodeBtn.addEventListener('click', () => {
    const text = rawInput.value.trim();
    if (!text) {
      showToast('Vui lòng dán chuỗi otpauth:// hoặc Secret Key', 'error');
      return;
    }
    parseAndDisplayOTPString(text);
  });

  // Copy Decoded Secret
  document.getElementById('copyDecSecret').addEventListener('click', () => {
    if (currentDecodedSecret) {
      navigator.clipboard.writeText(currentDecodedSecret);
      showToast('Đã sao chép khóa bí mật giải mã');
    }
  });

  // Add Decoded to Vault
  document.getElementById('addDecodedToVaultBtn').addEventListener('click', () => {
    if (!currentDecodedItem) return;
    appState.totpAccounts.push({
      id: 'totp-' + Date.now(),
      issuer: currentDecodedItem.issuer,
      account: currentDecodedItem.account,
      secret: currentDecodedItem.secret,
      digits: 6,
      period: 30
    });
    localStorage.setItem('aether_totp', JSON.stringify(appState.totpAccounts));
    renderTOTPCards();
    showToast('Đã thêm vào Vault thành công!');
    document.querySelector('.totp-subpill[data-subtab="vault"]').click();
  });
}

function handleQRFile(file) {
  const reader = new FileReader();
  reader.onload = (e) => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      
      // Use jsQR to decode
      if (typeof jsQR !== 'undefined') {
        const code = jsQR(imageData.data, imageData.width, imageData.height);
        if (code) {
          showToast('Đã phát hiện và giải mã mã QR!');
          parseAndDisplayOTPString(code.data);
        } else {
          showToast('Không thể đọc mã QR từ ảnh. Thử tải ảnh rõ nét hơn.', 'error');
        }
      } else {
        showToast('jsQR library chưa được tải', 'error');
      }
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

async function parseAndDisplayOTPString(input) {
  let issuer = 'Bảo Mật Tùy Chỉnh';
  let account = 'user@vault';
  let secret = '';

  if (input.startsWith('otpauth://')) {
    try {
      const url = new URL(input);
      const label = decodeURIComponent(url.pathname.replace(/^\/\/totp\//, ''));
      if (label.includes(':')) {
        const parts = label.split(':');
        issuer = parts[0];
        account = parts[1];
      } else {
        account = label;
      }
      secret = url.searchParams.get('secret') || '';
      if (url.searchParams.get('issuer')) {
        issuer = url.searchParams.get('issuer');
      }
    } catch (err) {
      console.warn('URL Parse warning:', err);
    }
  } else {
    // Pure Base32 key
    secret = input.replace(/[\s-]/g, '').toUpperCase();
    issuer = 'Direct Secret Key';
    account = 'Account';
  }

  if (!secret) {
    showToast('Không tìm thấy Secret Key hợp lệ trong chuỗi', 'error');
    return;
  }

  currentDecodedSecret = secret;
  currentDecodedItem = { issuer, account, secret };

  document.getElementById('decIssuer').textContent = issuer;
  document.getElementById('decAccount').textContent = account;
  document.getElementById('decSecret').textContent = secret;

  // Generate live code
  const liveCode = await generateTOTP(secret);
  document.getElementById('decLiveCode').innerHTML = `<span>${liveCode.slice(0, 3)}</span> <span>${liveCode.slice(3)}</span>`;

  document.getElementById('decoderResultCard').scrollIntoView({ behavior: 'smooth' });
}

// ==========================================
// 8. HELPERS
// ==========================================
function escapeHTML(str) {
  return (str || '').replace(/[&<>'"]/g, tag => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;'
  }[tag] || tag));
}

function formatTimeAgo(timestamp) {
  const diff = Date.now() - timestamp;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Vừa xong';
  if (mins < 60) return `${mins} phút trước`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} giờ trước`;
  return `${Math.floor(hours / 24)} ngày trước`;
}
