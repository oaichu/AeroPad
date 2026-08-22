# 🛡️ AeroPad — 2FA Vault & Private Notepad

> **Apple Minimalist + Web3 Obsidian Luxury Aesthetic**  
> 100% Client-Side Notepad & RFC 6238 TOTP Studio — mọi tính toán diễn ra ngay trên máy bạn, không backend, không database.

> 🔐 **Mã hóa at-rest (tùy chọn nhưng khuyên dùng)**: Vào nút **Vault** (góc phải) → đặt Master Password → toàn bộ ghi chú + secret TOTP + mật khẩu tài khoản được mã hóa **AES-256-GCM** (PBKDF2-SHA256 310.000 vòng) trước khi ghi vào LocalStorage. Mỗi lần mở lại app phải nhập mật khẩu để giải mã — key chỉ tồn tại trong RAM, **không có khôi phục nếu quên mật khẩu**. Nếu chưa đặt mật khẩu, dữ liệu lưu văn bản thuần — đừng dùng chế độ đó trên máy dùng chung.

---

## 🌟 Tính Năng Lõi (Core Features)

- 📝 **Smart Notepad**: Soạn thảo văn bản & Markdown mượt mà, bộ đếm số từ, ký tự và thời gian đọc, tự động lưu cục bộ (LocalStorage), xuất file `.md`, `.txt`, `.json`.
- 🔑 **Live 2FA Vault**: Mã TOTP 6/8 chữ số thời gian thực chuẩn RFC 6238 (HMAC-SHA1/SHA-256/SHA-512) chạy trực tiếp trên Web Crypto API. Copy mã luôn lấy mã **đang hiển thị** (không bao giờ copy mã đã hết hạn).
- ⚡ **2FA Generator & QR Studio**: Sinh khóa Base32 ngẫu nhiên (Web Crypto), mã QR động có nhúng đủ `algorithm`/`digits`/`period`, tải PNG, copy link `otpauth://`.
- 🔍 **2FA Decoder & Scanner**: Kéo thả / dán ảnh QR (Ctrl+V), dán link `otpauth://` hoặc secret thô. Giữ nguyên `digits`/`period`/`algorithm` của tài khoản khi lưu vào Vault.
- 🛡️ **Privacy + Encryption**: Không backend — toàn bộ xử lý nằm 100% tại máy. Đặt Master Password để mã hóa vault bằng AES-256-GCM (Web Crypto, key không rời RAM). CDN scripts được pin version + SRI, CSP strict qua `_headers`/`vercel.json`.

---

## 🚀 Hướng Dẫn Triển Khai Miễn Phí 0đ (100% Free Hosting & Domain)

### Triển khai trên Cloudflare (Khuyên Dùng)
> **Hỗ trợ cả GitHub Repo PRIVATE và PUBLIC hoàn toàn miễn phí 0đ vĩnh viễn!**

**Cách 1 — Cloudflare Pages (static):**
1. Truy cập [Cloudflare Pages Dashboard](https://pages.cloudflare.com/) > **Create application** > **Connect to Git**.
2. Chọn repo `aeropad`.
3. Cấu hình build:
   - **Framework preset**: *None*
   - **Build command**: `npm run build`
   - **Build output directory**: `dist`
4. Bấm **Save and Deploy** → `https://aeropad.pages.dev`. File `_headers` (CSP/HSTS) được copy vào `dist` tự động.

**Cách 2 — Cloudflare Workers Static Assets (wrangler):**
```bash
npm run build && npx wrangler deploy
```

### Triển khai trên Vercel
Repo đã có `vercel.json` (CSP/HSTS headers). Vercel tự serve thư mục `public/` — sau khi sửa code gốc, chạy:
```bash
npm run sync:public
```

### Build artifacts
- `npm run build:standalone` — sinh lại `aeropad-standalone.html` từ `index.html` + `styles.css` + `app.js` (inlines CSS/JS; in cả CSP hash của inline script). **Không sửa tay file standalone** — sửa 3 file gốc rồi chạy lệnh này.
- `npm run build` — sinh `dist/` (kèm `_headers`) cho Cloudflare.
- `npm run sync:public` — đồng bộ `public/` cho Vercel.

---

## 🧪 Chạy Kiểm Thử (Unit Tests)

```bash
npm test
# hoặc
node --test tests/*.test.js
```

Tests đối chiếu engine TOTP với các vector chính thức RFC 6238 (SHA-1 & SHA-256), kiểm tra parser `otpauth://` giữ đủ tham số, và Base32 strict (từ chối ký tự lạ thay vì sinh khóa sai âm thầm).
