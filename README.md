# 🛡️ AeroPad — 2FA Vault & Private Notepad

> **Apple Minimalist + Web3 Obsidian Luxury Aesthetic**  
> 100% Client-Side Zero-Knowledge Encrypted Notepad & RFC 6238 TOTP Studio.

---

## 🌟 Tính Năng Lõi (Core Features)

- 📝 **Smart Notepad**: Soạn thảo văn bản & Markdown mượt mà, bộ đếm số từ, ký tự và thời gian đọc, tự động lưu cục bộ (LocalStorage), xuất file `.md`, `.txt`, `.json`.
- 🔑 **Live 2FA Vault**: Bộ tính toán mã TOTP 6/8 chữ số thời gian thực chuẩn RFC 6238 HMAC-SHA1 chạy trực tiếp trên Web Crypto API của trình duyệt.
- ⚡ **2FA Generator & QR Studio**: Tự động sinh khóa bí mật Base32 ngẫu nhiên, kết xuất ảnh mã QR động để quét trên điện thoại hoặc tải về máy dạng PNG, sao chép link `otpauth://`.
- 🔍 **2FA Decoder & Scanner**: Kéo thả ảnh mã QR, dán ảnh trực tiếp từ Clipboard (Ctrl+V) hoặc dán link `otpauth://` để giải mã thông tin và sinh ngay mã 6 số test trực tiếp.
- 🛡️ **Zero-Knowledge Privacy**: Không cần backend database, toàn bộ hoạt động lưu trữ và xử lý mã hóa nằm 100% tại máy của người dùng.

---

## 🚀 Hướng Dẫn Triển Khai Miễn Phí 0đ (100% Free Hosting & Domain)

### Triển khai trên Cloudflare Pages (Khuyên Dùng)
> **Hỗ trợ cả GitHub Repo PRIVATE và PUBLIC hoàn toàn miễn phí 0đ vĩnh viễn!**

1. Truy cập [Cloudflare Pages Dashboard](https://pages.cloudflare.com/).
2. Chọn **Create application** > **Connect to Git**.
3. Chọn repo `aeropad` (kể cả khi repo để ở chế độ **Private**).
4. Cấu hình build:
   - **Framework preset**: *None*
   - **Build output directory**: `/` (hoặc thư mục gốc chứa `index.html`)
5. Bấm **Save and Deploy**. Website của bạn sẽ nhận được tên miền miễn phí trọn đời dạng: `https://aeropad.pages.dev`.

---

## 🧪 Chạy Kiểm Thử (Unit Tests)

```bash
npm test
# hoặc
node --test tests/*.test.js
```
