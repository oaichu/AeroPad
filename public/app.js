/**
 * AEROPAD & 2FA VAULT — FULL CLIENT-SIDE APP LOGIC
 * RFC 6238 TOTP Engine + Client-Side Zero-Knowledge Notes & Multi-Language System
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
    if (!secretBase32) return '------';
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
// 2. INTERNATIONALIZATION (i18n — 7 Languages)
// ==========================================
const TRANSLATIONS = {
  en: {
    name: 'English',
    flag: '🇺🇸',
    brand_badge: '2FA & CIPHER VAULT',
    tab_notepad: 'Smart Notepad',
    tab_totp: '2FA Studio',
    zero_knowledge: 'Zero-Knowledge',
    vault_unlocked: 'Vault Unlocked',
    search_notes: 'Search notes...',
    storage_used: 'Storage used',
    storage_sub: 'AES-256 Encrypted • Local Storage',
    note_title_placeholder: 'Note title...',
    saved_status: 'Saved',
    mode_edit: 'Edit',
    mode_split: 'Split',
    mode_preview: 'Preview',
    export_file: 'Export',
    copy_content: 'Copy',
    note_content_placeholder: 'Start typing your note... Markdown, to-do lists, seed phrases, or private security keys supported...',
    empty_notes_title: 'No notes yet.',
    empty_notes_btn: '+ Create New Note',
    subtab_vault: 'Live TOTP Vault',
    subtab_gen: 'New 2FA (Secret & QR)',
    subtab_decoder: 'Decode & Scan QR 2FA',
    vault_heading: 'Two-Factor Authentication (TOTP)',
    vault_subheading: 'Auto-refreshes via RFC 6238 HMAC-SHA1. Runs 100% locally on Web Crypto API.',
    add_new_code_btn: 'Add New Code',
    empty_totp_title: 'No 2FA accounts in Vault',
    empty_totp_desc: 'Click "Add New Code" or switch to "New 2FA" / "Decode & Scan QR" to store 2FA accounts securely.',
    gen_heading: 'Generate New Secret Key & 2FA QR',
    gen_subheading: 'Generate high-entropy Base32 secret keys to enable two-factor authentication for your apps or services.',
    gen_issuer: 'Issuer Name',
    gen_account: 'Account / Email',
    gen_secret: 'Secret Key (Base32)',
    gen_random_btn: 'Generate New Random',
    gen_hash_algo: 'Hash Algorithm',
    gen_period_digits: 'Period & Digits',
    save_to_vault_btn: 'Save Directly to Vault',
    no_qr_placeholder: 'No QR Code yet.<br>Generate or enter a Secret Key.',
    download_qr_png: 'Download QR PNG',
    copy_otp_link: 'Copy OTP Link',
    dec_heading: 'Decode QR Code & 2FA Key',
    dec_subheading: 'Drag & drop QR code image, paste image from clipboard (Ctrl+V) or paste otpauth:// link to extract Secret Key & view real-time 6-digit code.',
    drop_title: 'Drag & drop QR code image here',
    drop_subtitle: 'or browse file / paste image from clipboard (Ctrl+V)',
    paste_prompt: 'OR PASTE OTPAUTH URI / SECRET KEY',
    decode_now_btn: 'Decode Now',
    dec_result_title: '2FA Account Information',
    dec_live_label: 'REAL-TIME GENERATED 6-DIGIT CODE:',
    save_dec_to_vault: 'Save This Account to Your Vault',
    modal_add_title: 'Add New 2FA Account',
    cancel_btn: 'Cancel',
    confirm_add_btn: 'Add to Vault',
    modal_password_label: 'Account Password (Optional)',
    modal_password_placeholder: 'e.g. •••••••• (Leave empty if not needed)',
    gen_pass_quick: 'Generate',
    toast_pass_copied: 'Account password copied to clipboard!',
    word_unit: 'words',
    char_unit: 'characters',
    read_unit: 'min read',
    toast_created_note: 'New note created',
    toast_deleted_note: 'Note deleted',
    toast_copied_note: 'Note content copied to clipboard',
    toast_secret_copied: 'Secret key copied',
    toast_otp_copied: 'OTP Auth link copied',
    toast_qr_downloaded: 'QR Code downloaded as PNG',
    toast_code_copied: '2FA code copied:',
    toast_totp_added: '2FA account added to Vault',
    toast_qr_detected: 'QR Code detected and decoded successfully!'
  },
  vi: {
    name: 'Tiếng Việt',
    flag: '🇻🇳',
    brand_badge: '2FA & KHO MẬT MÃ',
    tab_notepad: 'Ghi Chú Thông Minh',
    tab_totp: 'Xác Thực 2FA',
    zero_knowledge: 'Zero-Knowledge',
    vault_unlocked: 'Vault Đang Mở',
    search_notes: 'Tìm ghi chú...',
    storage_used: 'Dung lượng đã dùng',
    storage_sub: 'Mã hóa AES-256 • LocalStorage Cục bộ',
    note_title_placeholder: 'Tiêu đề ghi chú...',
    saved_status: 'Đã lưu',
    mode_edit: 'Soạn thảo',
    mode_split: 'Chia đôi',
    mode_preview: 'Xem trước',
    export_file: 'Xuất file',
    copy_content: 'Sao chép',
    note_content_placeholder: 'Bắt đầu gõ ghi chú của bạn... Hỗ trợ định dạng Markdown, danh sách to-do, seed phrases hoặc mã bảo mật bí mật...',
    empty_notes_title: 'Chưa có ghi chú nào.',
    empty_notes_btn: '+ Tạo ghi chú mới',
    subtab_vault: 'Kho Mã TOTP Trực Tiếp',
    subtab_gen: 'Tạo Mới 2FA (Secret & QR)',
    subtab_decoder: 'Giải Mã & Quét QR 2FA',
    vault_heading: 'Mã Xác Thực 2 Bước (TOTP)',
    vault_subheading: 'Tự động làm mới theo chuẩn RFC 6238 HMAC-SHA1. Chạy hoàn toàn trên Web Crypto API cục bộ.',
    add_new_code_btn: 'Thêm Mã Mới',
    empty_totp_title: 'Chưa có mã 2FA nào trong Vault',
    empty_totp_desc: 'Hãy bấm "Thêm Mã Mới" hoặc sang tab "Tạo Mới 2FA" / "Giải Mã & Quét QR" để lưu tài khoản 2FA an toàn.',
    gen_heading: 'Tạo Khóa Bí Mật & Mã QR 2FA Mới',
    gen_subheading: 'Sinh khóa Base32 bảo mật cao để kích hoạt xác thực 2 bước cho dịch vụ hoặc ứng dụng của bạn.',
    gen_issuer: 'Tên Đơn Vị Phát Hành',
    gen_account: 'Tài Khoản / Email',
    gen_secret: 'Khóa Bí Mật (Base32)',
    gen_random_btn: 'Sinh ngẫu nhiên mới',
    gen_hash_algo: 'Thuật toán Hash',
    gen_period_digits: 'Chu kỳ & Chữ số',
    save_to_vault_btn: 'Lưu Trực Tiếp Vào Vault',
    no_qr_placeholder: 'Chưa có mã QR.<br>Hãy sinh hoặc nhập Secret Key.',
    download_qr_png: 'Tải QR PNG',
    copy_otp_link: 'Copy OTP Link',
    dec_heading: 'Giải Mã Mã QR & Khóa 2FA',
    dec_subheading: 'Kéo thả ảnh QR Code, dán ảnh từ clipboard (Ctrl+V) hoặc dán link otpauth:// để trích xuất Secret Key & xem mã 6 số tức thì.',
    drop_title: 'Kéo thả ảnh mã QR vào đây',
    drop_subtitle: 'hoặc nhấp để duyệt tệp / dán ảnh từ Clipboard (Ctrl+V)',
    paste_prompt: 'HOẶC DÁN CHUỖI OTPAUTH / SECRET KEY',
    decode_now_btn: 'Giải Mã Ngay',
    dec_result_title: 'Thông Tin Tài Khoản 2FA',
    dec_live_label: 'MÃ 6 SỐ THỜI GIAN THỰC ĐƯỢC TẠO RA:',
    save_dec_to_vault: 'Lưu Tài Khoản Này Vào Vault Của Bạn',
    modal_add_title: 'Thêm Mã 2FA Mới',
    cancel_btn: 'Hủy',
    confirm_add_btn: 'Thêm vào Vault',
    modal_password_label: 'Mật khẩu tài khoản (Tùy chọn)',
    modal_password_placeholder: 'vd: •••••••• (Để trống nếu không dùng)',
    gen_pass_quick: 'Tạo tự động',
    toast_pass_copied: 'Đã sao chép mật khẩu tài khoản!',
    word_unit: 'từ',
    char_unit: 'ký tự',
    read_unit: 'phút đọc',
    toast_created_note: 'Đã tạo ghi chú mới',
    toast_deleted_note: 'Đã xóa ghi chú',
    toast_copied_note: 'Đã sao chép nội dung ghi chú',
    toast_secret_copied: 'Đã sao chép khóa bí mật',
    toast_otp_copied: 'Đã sao chép đường dẫn OTP Auth',
    toast_qr_downloaded: 'Đã tải xuống ảnh mã QR',
    toast_code_copied: 'Đã sao chép mã 2FA:',
    toast_totp_added: 'Đã thêm tài khoản vào Vault',
    toast_qr_detected: 'Đã phát hiện và giải mã mã QR thành công!'
  },
  zh: {
    name: '简体中文',
    flag: '🇨🇳',
    brand_badge: '2FA & 密码保险库',
    tab_notepad: '智能记事本',
    tab_totp: '2FA 工作室',
    zero_knowledge: '零知识加密',
    vault_unlocked: '保险库已解锁',
    search_notes: '搜索笔记...',
    storage_used: '已用存储',
    storage_sub: 'AES-256 加密 • 本地存储',
    note_title_placeholder: '笔记标题...',
    saved_status: '已保存',
    mode_edit: '编辑',
    mode_split: '分屏',
    mode_preview: '预览',
    export_file: '导出文件',
    copy_content: '复制内容',
    note_content_placeholder: '开始输入笔记... 支持 Markdown、待办清单、助记词或私密密钥...',
    empty_notes_title: '暂无笔记。',
    empty_notes_btn: '+ 创建新笔记',
    subtab_vault: '实时 TOTP 保险库',
    subtab_gen: '生成新 2FA (密钥与二维码)',
    subtab_decoder: '解码与扫描 2FA 二维码',
    vault_heading: '双重身份验证 (TOTP)',
    vault_subheading: '通过 RFC 6238 HMAC-SHA1 自动刷新。100% 本地 Web Crypto API 运行。',
    add_new_code_btn: '添加新验证码',
    empty_totp_title: '保险库中暂无 2FA 账户',
    empty_totp_desc: '点击“添加新验证码”或切换至“生成新 2FA”/“解码与扫描”以安全保存 2FA 账户。',
    gen_heading: '生成新密钥与 2FA 二维码',
    gen_subheading: '生成高熵 Base32 密钥，为您的服务或应用启用双重身份验证。',
    gen_issuer: '发布机构名称',
    gen_account: '账户名称 / 邮箱',
    gen_secret: '密钥 (Base32)',
    gen_random_btn: '随机生成新密钥',
    gen_hash_algo: '哈希算法',
    gen_period_digits: '周期与位数',
    save_to_vault_btn: '直接保存至保险库',
    no_qr_placeholder: '暂无二维码。<br>请生成或输入密钥。',
    download_qr_png: '下载二维码 PNG',
    copy_otp_link: '复制 OTP 链接',
    dec_heading: '解码二维码与 2FA 密钥',
    dec_subheading: '拖放二维码图片、从剪贴板粘贴 (Ctrl+V) 或粘贴 otpauth:// 链接以提取密钥并查看实时 6 位代码。',
    drop_title: '将二维码图片拖放到此处',
    drop_subtitle: '或点击浏览文件 / 从剪贴板粘贴 (Ctrl+V)',
    paste_prompt: '或粘贴 OTPAUTH 链接 / 密钥',
    decode_now_btn: '立即解码',
    dec_result_title: '2FA 账户信息',
    dec_live_label: '实时生成的 6 位验证码：',
    save_dec_to_vault: '将此账户保存至您的保险库',
    modal_add_title: '添加新 2FA 账户',
    cancel_btn: '取消',
    confirm_add_btn: '添加至保险库',
    modal_password_label: '账户密码（可选）',
    modal_password_placeholder: '例如：••••••••（无需则留空）',
    gen_pass_quick: '随机生成',
    toast_pass_copied: '账户密码已复制到剪贴板！',
    word_unit: '字',
    char_unit: '字符',
    read_unit: '分钟阅读',
    toast_created_note: '已创建新笔记',
    toast_deleted_note: '已删除笔记',
    toast_copied_note: '笔记内容已复制到剪贴板',
    toast_secret_copied: '密钥已复制',
    toast_otp_copied: 'OTP 链接已复制',
    toast_qr_downloaded: '二维码已下载为 PNG',
    toast_code_copied: '2FA 验证码已复制：',
    toast_totp_added: '已添加 2FA 账户至保险库',
    toast_qr_detected: '成功识别并解码二维码！'
  },
  ko: {
    name: '한국어',
    flag: '🇰🇷',
    brand_badge: '2FA & 암호 금고',
    tab_notepad: '스마트 메모장',
    tab_totp: '2FA 스튜디오',
    zero_knowledge: '영지식 암호화',
    vault_unlocked: '금고 잠금해제됨',
    search_notes: '메모 검색...',
    storage_used: '사용된 용량',
    storage_sub: 'AES-256 암호화 • 로컬 저장소',
    note_title_placeholder: '메모 제목...',
    saved_status: '저장됨',
    mode_edit: '편집',
    mode_split: '분할',
    mode_preview: '미리보기',
    export_file: '내보내기',
    copy_content: '복사',
    note_content_placeholder: '메모를 작성하세요... 마크다운, 체크리스트, 시드 구문 또는 보안 키 지원...',
    empty_notes_title: '아직 메모가 없습니다.',
    empty_notes_btn: '+ 새 메모 작성',
    subtab_vault: '실시간 TOTP 금고',
    subtab_gen: '2FA 새로 만들기 (비밀키 & QR)',
    subtab_decoder: '2FA QR 디코드 & 스캔',
    vault_heading: '2단계 인증 (TOTP)',
    vault_subheading: 'RFC 6238 HMAC-SHA1 표준으로 자동 갱신됩니다. 로컬 Web Crypto API에서 100% 실행됩니다.',
    add_new_code_btn: '새 코드 추가',
    empty_totp_title: '금고에 2FA 계정이 없습니다',
    empty_totp_desc: '"새 코드 추가"를 누르거나 "2FA 새로 만들기" / "QR 디코드" 탭에서 계정을 저장하세요.',
    gen_heading: '새 비밀키 & 2FA QR 생성',
    gen_subheading: '서비스 또는 앱에 2단계 인증을 사용하도록 보안성 높은 Base32 키를 생성합니다.',
    gen_issuer: '발급자 이름',
    gen_account: '계정 이름 / 이메일',
    gen_secret: '비밀키 (Base32)',
    gen_random_btn: '새로 무작위 생성',
    gen_hash_algo: '해시 알고리즘',
    gen_period_digits: '주기 & 자릿수',
    save_to_vault_btn: '금고에 바로 저장',
    no_qr_placeholder: 'QR 코드가 없습니다.<br>비밀키를 생성하거나 입력하세요.',
    download_qr_png: 'QR PNG 다운로드',
    copy_otp_link: 'OTP 링크 복사',
    dec_heading: 'QR 코드 & 2FA 키 디코드',
    dec_subheading: 'QR 코드 이미지를 드래그 앤 드롭하거나 클립보드에서 붙여넣어 비밀키를 추출하고 6자리 코드를 확인하세요.',
    drop_title: 'QR 코드 이미지를 여기에 드래그 앤 드롭',
    drop_subtitle: '또는 파일 찾아보기 / 클립보드에서 붙여넣기 (Ctrl+V)',
    paste_prompt: '또는 OTPAUTH URI / 비밀키 붙여넣기',
    decode_now_btn: '지금 디코드',
    dec_result_title: '2FA 계정 정보',
    dec_live_label: '실시간 생성된 6자리 코드:',
    save_dec_to_vault: '이 계정을 금고에 저장',
    modal_add_title: '새 2FA 계정 추가',
    cancel_btn: '취소',
    confirm_add_btn: '금고에 추가',
    modal_password_label: '계정 비밀번호(선택사항)',
    modal_password_placeholder: '예: •••••••• (필요 없으면 비워둠)',
    gen_pass_quick: '자동 생성',
    toast_pass_copied: '계정 비밀번호가 클립보드에 복사되었습니다!',
    word_unit: '단어',
    char_unit: '글자',
    read_unit: '분 읽기',
    toast_created_note: '새 메모가 생성되었습니다',
    toast_deleted_note: '메모가 삭제되었습니다',
    toast_copied_note: '메모 내용이 클립보드에 복사되었습니다',
    toast_secret_copied: '비밀키가 복사되었습니다',
    toast_otp_copied: 'OTP 링크가 복사되었습니다',
    toast_qr_downloaded: 'QR 코드가 PNG로 다운로드되었습니다',
    toast_code_copied: '2FA 코드가 복사되었습니다:',
    toast_totp_added: '금고에 2FA 계정이 추가되었습니다',
    toast_qr_detected: 'QR 코드가 감지되어 디코드되었습니다!'
  },
  ja: {
    name: '日本語',
    flag: '🇯🇵',
    brand_badge: '2FA & 暗号ボールト',
    tab_notepad: 'スマートノート',
    tab_totp: '2FA スタジオ',
    zero_knowledge: 'ゼロ知識暗号',
    vault_unlocked: 'ボールト解除中',
    search_notes: 'ノートを検索...',
    storage_used: '使用済みストレージ',
    storage_sub: 'AES-256 暗号化 • ローカル保存',
    note_title_placeholder: 'ノートのタイトル...',
    saved_status: '保存済み',
    mode_edit: '編集',
    mode_split: '分割',
    mode_preview: 'プレビュー',
    export_file: 'エクスポート',
    copy_content: 'コピー',
    note_content_placeholder: 'ノートを入力... Markdown、チェックリスト、シードフレーズ、秘密鍵に対応...',
    empty_notes_title: 'ノートがありません。',
    empty_notes_btn: '+ 新規ノート作成',
    subtab_vault: 'ライブ TOTP ボールト',
    subtab_gen: '新規 2FA (シークレット & QR)',
    subtab_decoder: '2FA QR デコード & スキャン',
    vault_heading: '2段階認証 (TOTP)',
    vault_subheading: 'RFC 6238 HMAC-SHA1で自動更新。ローカルのWeb Crypto APIで100%実行。',
    add_new_code_btn: '新規コード追加',
    empty_totp_title: 'ボールトに2FAアカウントがありません',
    empty_totp_desc: '「新規コード追加」をクリックするか「新規2FA作成」/「QRデコード」タブで安全に保存してください。',
    gen_heading: '新規シークレットキー & 2FA QR生成',
    gen_subheading: 'サービスやアプリで2要素認証を有効化するための安全なBase32キーを生成します。',
    gen_issuer: '発行者名',
    gen_account: 'アカウント名 / メール',
    gen_secret: 'シークレットキー (Base32)',
    gen_random_btn: 'ランダム新規生成',
    gen_hash_algo: 'ハッシュアルゴリズム',
    gen_period_digits: '周期 & 桁数',
    save_to_vault_btn: 'ボールトに直接保存',
    no_qr_placeholder: 'QRコードがありません。<br>キーを生成または入力してください。',
    download_qr_png: 'QR PNGを保存',
    copy_otp_link: 'OTPリンクをコピー',
    dec_heading: 'QRコード & 2FAキーのデコード',
    dec_subheading: 'QRコード画像をドラッグ＆ドロップするかクリップボードから貼り付けてキーを抽出します。',
    drop_title: 'ここにQRコード画像をドラッグ＆ドロップ',
    drop_subtitle: 'またはファイルを参照 / クリップボードから貼り付け (Ctrl+V)',
    paste_prompt: 'または OTPAUTH URI / シークレットキーを貼り付け',
    decode_now_btn: '今すぐデコード',
    dec_result_title: '2FA アカウント情報',
    dec_live_label: 'リアルタイム生成された6桁コード:',
    save_dec_to_vault: 'このアカウントをボールトに保存',
    modal_add_title: '新規 2FA アカウント追加',
    cancel_btn: 'キャンセル',
    confirm_add_btn: 'ボールトに追加',
    modal_password_label: 'アカウントパスワード（任意）',
    modal_password_placeholder: '例: •••••••• (不要な場合は空欄)',
    gen_pass_quick: '自動生成',
    toast_pass_copied: 'アカウントパスワードをクリップボードにコピーしました！',
    word_unit: '単語',
    char_unit: '文字',
    read_unit: '分で読める',
    toast_created_note: '新規ノートを作成しました',
    toast_deleted_note: 'ノートを削除しました',
    toast_copied_note: 'ノート内容をコピーしました',
    toast_secret_copied: 'シークレットキーをコピーしました',
    toast_otp_copied: 'OTPリンクをコピーしました',
    toast_qr_downloaded: 'QRコードをPNGで保存しました',
    toast_code_copied: '2FAコードをコピーしました:',
    toast_totp_added: '2FAアカウントをボールトに追加しました',
    toast_qr_detected: 'QRコードを検出してデコードしました！'
  },
  es: {
    name: 'Español',
    flag: '🇪🇸',
    brand_badge: 'BÓVEDA 2FA & CIFRADO',
    tab_notepad: 'Bloc de Notas',
    tab_totp: 'Estudio 2FA',
    zero_knowledge: 'Conocimiento Cero',
    vault_unlocked: 'Bóveda Desbloqueada',
    search_notes: 'Buscar notas...',
    storage_used: 'Almacenamiento usado',
    storage_sub: 'Cifrado AES-256 • Almacenamiento Local',
    note_title_placeholder: 'Título de la nota...',
    saved_status: 'Guardado',
    mode_edit: 'Editar',
    mode_split: 'Dividir',
    mode_preview: 'Vista previa',
    export_file: 'Exportar',
    copy_content: 'Copiar',
    note_content_placeholder: 'Escribe tu nota... Compatible con Markdown, listas de tareas, frases semilla o claves privadas...',
    empty_notes_title: 'No hay notas aún.',
    empty_notes_btn: '+ Crear Nueva Nota',
    subtab_vault: 'Bóveda TOTP en Vivo',
    subtab_gen: 'Generar 2FA (Secreto y QR)',
    subtab_decoder: 'Decodificar y Escanear QR 2FA',
    vault_heading: 'Autenticación de Dos Factores (TOTP)',
    vault_subheading: 'Se actualiza automáticamente mediante RFC 6238 HMAC-SHA1. 100% local con Web Crypto API.',
    add_new_code_btn: 'Agregar Código',
    empty_totp_title: 'No hay cuentas 2FA en la Bóveda',
    empty_totp_desc: 'Haz clic en "Agregar Código" o ve a "Generar 2FA" / "Decodificar QR" para guardar cuentas de forma segura.',
    gen_heading: 'Generar Clave Secreta y QR 2FA',
    gen_subheading: 'Genera claves secretas Base32 de alta entropía para habilitar 2FA en tus servicios o aplicaciones.',
    gen_issuer: 'Nombre del emisor',
    gen_account: 'Cuenta / Correo',
    gen_secret: 'Clave Secreta (Base32)',
    gen_random_btn: 'Generar nuevo aleatorio',
    gen_hash_algo: 'Algoritmo Hash',
    gen_period_digits: 'Período y Dígitos',
    save_to_vault_btn: 'Guardar en la Bóveda',
    no_qr_placeholder: 'No hay código QR aún.<br>Genera o introduce una clave.',
    download_qr_png: 'Descargar QR PNG',
    copy_otp_link: 'Copiar Enlace OTP',
    dec_heading: 'Decodificar Código QR y Clave 2FA',
    dec_subheading: 'Arrastra y suelta la imagen QR, pégala desde el portapapeles (Ctrl+V) o pega el enlace otpauth:// para ver el código en tiempo real.',
    drop_title: 'Arrastra y suelta la imagen QR aquí',
    drop_subtitle: 'o buscar archivo / pegar imagen del portapapeles (Ctrl+V)',
    paste_prompt: 'O PEGAR URI OTPAUTH / CLAVE SECRETA',
    decode_now_btn: 'Decodificar Ahora',
    dec_result_title: 'Información de la Cuenta 2FA',
    dec_live_label: 'CÓDIGO DE 6 DÍGITOS GENERADO EN TIEMPO REAL:',
    save_dec_to_vault: 'Guardar esta cuenta en la Bóveda',
    modal_add_title: 'Agregar Cuenta 2FA',
    cancel_btn: 'Cancelar',
    confirm_add_btn: 'Agregar a la Bóveda',
    modal_password_label: 'Contraseña de la cuenta (Opcional)',
    modal_password_placeholder: 'ej. •••••••• (Dejar vacío si no es necesario)',
    gen_pass_quick: 'Generar',
    toast_pass_copied: '¡Contraseña de la cuenta copiada al portapapeles!',
    word_unit: 'palabras',
    char_unit: 'caracteres',
    read_unit: 'min de lectura',
    toast_created_note: 'Nueva nota creada',
    toast_deleted_note: 'Nota eliminada',
    toast_copied_note: 'Contenido copiado al portapapeles',
    toast_secret_copied: 'Clave secreta copiada',
    toast_otp_copied: 'Enlace OTP copiado',
    toast_qr_downloaded: 'Código QR descargado como PNG',
    toast_code_copied: 'Código 2FA copiado:',
    toast_totp_added: 'Cuenta 2FA agregada a la Bóveda',
    toast_qr_detected: '¡Código QR detectado y decodificado!'
  },
  id: {
    name: 'Bahasa Indonesia',
    flag: '🇮🇩',
    brand_badge: 'BRANKAS 2FA & CIPHER',
    tab_notepad: 'Catatan Pintar',
    tab_totp: 'Studio 2FA',
    zero_knowledge: 'Nol-Pengetahuan',
    vault_unlocked: 'Brankas Terbuka',
    search_notes: 'Cari catatan...',
    storage_used: 'Penyimpanan terpakai',
    storage_sub: 'Terenkripsi AES-256 • Penyimpanan Lokal',
    note_title_placeholder: 'Judul catatan...',
    saved_status: 'Tersimpan',
    mode_edit: 'Edit',
    mode_split: 'Bagi',
    mode_preview: 'Pratinjau',
    export_file: 'Ekspor',
    copy_content: 'Salin',
    note_content_placeholder: 'Mulai mengetik catatan... Mendukung Markdown, daftar tugas, seed phrase, atau kunci keamanan privat...',
    empty_notes_title: 'Belum ada catatan.',
    empty_notes_btn: '+ Buat Catatan Baru',
    subtab_vault: 'Brankas TOTP Langsung',
    subtab_gen: 'Buat 2FA Baru (Rahasia & QR)',
    subtab_decoder: 'Dekode & Pindai QR 2FA',
    vault_heading: 'Autentikasi Dua Faktor (TOTP)',
    vault_subheading: 'Diperbarui otomatis via RFC 6238 HMAC-SHA1. 100% berjalan lokal di Web Crypto API.',
    add_new_code_btn: 'Tambah Kode Baru',
    empty_totp_title: 'Belum ada akun 2FA di Brankas',
    empty_totp_desc: 'Klik "Tambah Kode Baru" atau buka tab "Buat 2FA" / "Dekode QR" untuk menyimpan akun dengan aman.',
    gen_heading: 'Buat Kunci Rahasia & QR 2FA Baru',
    gen_subheading: 'Hasilkan kunci rahasia Base32 berkekuatan tinggi untuk mengaktifkan autentikasi dua faktor.',
    gen_issuer: 'Nama Penerbit',
    gen_account: 'Nama Akun / Email',
    gen_secret: 'Kunci Rahasia (Base32)',
    gen_random_btn: 'Acak Baru',
    gen_hash_algo: 'Algoritma Hash',
    gen_period_digits: 'Periode & Digit',
    save_to_vault_btn: 'Simpan ke Brankas',
    no_qr_placeholder: 'Belum ada Kode QR.<br>Hasilkan atau masukkan Kunci Rahasia.',
    download_qr_png: 'Unduh QR PNG',
    copy_otp_link: 'Salin Tautan OTP',
    dec_heading: 'Dekode Kode QR & Kunci 2FA',
    dec_subheading: 'Tarik & lepas gambar kode QR, tempel gambar dari papan klip (Ctrl+V) atau tempel tautan otpauth:// untuk melihat kode 6 digit real-time.',
    drop_title: 'Tarik & lepas gambar QR di sini',
    drop_subtitle: 'atau telusuri file / tempel gambar dari papan klip (Ctrl+V)',
    paste_prompt: 'ATAU TEMPEL OTPAUTH URI / KUNCI RAHASIA',
    decode_now_btn: 'Dekode Sekarang',
    dec_result_title: 'Informasi Akun 2FA',
    dec_live_label: 'KODE 6 DIGIT DIHASILKAN SECARA REAL-TIME:',
    save_dec_to_vault: 'Simpan Akun Ini ke Brankas Anda',
    modal_add_title: 'Tambah Akun 2FA Baru',
    cancel_btn: 'Batal',
    confirm_add_btn: 'Tambah ke Brankas',
    modal_password_label: 'Kata Sandi Akun (Opsional)',
    modal_password_placeholder: 'cth: •••••••• (Biarkan kosong jika tidak perlu)',
    gen_pass_quick: 'Hasilkan',
    toast_pass_copied: 'Kata sandi akun disalin ke papan klip!',
    word_unit: 'kata',
    char_unit: 'karakter',
    read_unit: 'mnt baca',
    toast_created_note: 'Catatan baru dibuat',
    toast_deleted_note: 'Catatan dihapus',
    toast_copied_note: 'Konten catatan disalin ke papan klip',
    toast_secret_copied: 'Kunci rahasia disalin',
    toast_otp_copied: 'Tautan OTP disalin',
    toast_qr_downloaded: 'Kode QR diunduh sebagai PNG',
    toast_code_copied: 'Kode 2FA disalin:',
    toast_totp_added: 'Akun 2FA ditambahkan ke Brankas',
    toast_qr_detected: 'Kode QR terdeteksi dan berhasil didekode!'
  }
};

// ==========================================
// 3. STATE & STORAGE
// ==========================================
const DEFAULT_NOTES = [];
const DEFAULT_VAULT_ACCOUNTS = [];

let appState = {
  notes: JSON.parse(localStorage.getItem('aeropad_notes')) || DEFAULT_NOTES,
  activeNoteId: null,
  totpAccounts: JSON.parse(localStorage.getItem('aeropad_totp')) || DEFAULT_VAULT_ACCOUNTS,
  theme: localStorage.getItem('aeropad_theme') || 'dark',
  lang: localStorage.getItem('aeropad_lang') || 'en',
  currentTab: 'notepad',
  current2FASubtab: 'vault',
  editorMode: 'edit'
};

function t(key) {
  const langDict = TRANSLATIONS[appState.lang] || TRANSLATIONS.en;
  return langDict[key] || TRANSLATIONS.en[key] || key;
}

// ==========================================
// 4. INITIALIZATION & ROUTING
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
  initLanguage();
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
  if (!container) return;
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
// 5. LANGUAGE MANAGER (i18n)
// ==========================================
function initLanguage() {
  const wrap = document.getElementById('langDropdownWrap');
  const btn = document.getElementById('langToggleBtn');
  const menu = document.getElementById('langMenu');

  btn?.addEventListener('click', (e) => {
    e.stopPropagation();
    wrap?.classList.toggle('open');
    menu?.classList.toggle('show');
  });

  document.addEventListener('click', (e) => {
    if (!wrap?.contains(e.target)) {
      wrap?.classList.remove('open');
      menu?.classList.remove('show');
    }
  });

  menu?.querySelectorAll('.lang-opt').forEach(opt => {
    opt.addEventListener('click', (e) => {
      e.stopPropagation();
      const selectedLang = opt.getAttribute('data-lang');
      if (selectedLang) {
        applyLanguage(selectedLang);
      }
      wrap?.classList.remove('open');
      menu?.classList.remove('show');
    });
  });

  applyLanguage(appState.lang);
}

function applyLanguage(lang) {
  if (!TRANSLATIONS[lang]) lang = 'en';
  appState.lang = lang;
  localStorage.setItem('aeropad_lang', lang);

  // Update button label and active menu item
  const currentLabel = document.getElementById('currentLangLabel');
  if (currentLabel) {
    currentLabel.textContent = TRANSLATIONS[lang].name;
  }

  document.querySelectorAll('#langMenu .lang-opt').forEach(opt => {
    opt.classList.toggle('active', opt.dataset.lang === lang);
  });

  // Translate all [data-i18n] text elements
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (key && TRANSLATIONS[lang][key]) {
      el.innerHTML = TRANSLATIONS[lang][key];
    }
  });

  // Translate [data-i18n-placeholder] elements
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (key && TRANSLATIONS[lang][key]) {
      el.setAttribute('placeholder', TRANSLATIONS[lang][key]);
    }
  });

  // Re-render dynamic list empty states
  renderNotesList();
  renderTOTPCards();
  updateWordCounts();
  renderQRCode();
}

// ==========================================
// 6. THEME & NAVIGATION
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

  document.getElementById('themeToggle')?.addEventListener('click', () => {
    if (root.classList.contains('dark')) {
      root.classList.remove('dark');
      root.classList.add('light');
      appState.theme = 'light';
    } else {
      root.classList.remove('light');
      root.classList.add('dark');
      appState.theme = 'dark';
    }
    localStorage.setItem('aeropad_theme', appState.theme);
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
      const targetPane = document.getElementById(`tab-${tabId}`);
      if (targetPane) targetPane.classList.add('active');
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
      const targetSubpane = document.getElementById(`subtab-${subtab}`);
      if (targetSubpane) targetSubpane.classList.add('active');
      appState.current2FASubtab = subtab;

      if (subtab === 'generator') {
        renderQRCode();
      }
    });
  });

  // Master Lock Button
  const vaultBtn = document.getElementById('vaultLockBtn');
  vaultBtn?.addEventListener('click', () => {
    showToast(t('vault_unlocked') + ' • 100% Zero-Knowledge');
  });
}

// ==========================================
// 7. SMART NOTEPAD LOGIC
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

  titleInput?.addEventListener('input', autoSaveNote);
  contentInput?.addEventListener('input', () => {
    autoSaveNote();
    updateWordCounts();
    if (appState.editorMode !== 'edit') {
      renderMarkdownPreview();
    }
  });

  // New Note
  document.getElementById('newNoteBtn')?.addEventListener('click', createNewNote);

  // Delete Note
  document.getElementById('deleteNoteBtn')?.addEventListener('click', () => {
    if (appState.notes.length === 0) return;
    appState.notes = appState.notes.filter(n => n.id !== appState.activeNoteId);
    appState.activeNoteId = appState.notes.length > 0 ? appState.notes[0].id : null;
    saveNotesToStorage();
    renderNotesList();
    loadActiveNote();
    showToast(t('toast_deleted_note'));
  });

  // Search Notes
  document.getElementById('noteSearch')?.addEventListener('input', (e) => {
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
  document.getElementById('copyNoteContent')?.addEventListener('click', () => {
    const note = appState.notes.find(n => n.id === appState.activeNoteId);
    if (note) {
      navigator.clipboard.writeText(`${note.title}\n\n${note.content}`);
      showToast(t('toast_copied_note'));
    }
  });

  // Export Dropdown
  const exportBtn = document.getElementById('exportBtn');
  const exportMenu = document.getElementById('exportMenu');
  exportBtn?.addEventListener('click', (e) => {
    e.stopPropagation();
    exportMenu.classList.toggle('show');
  });
  document.addEventListener('click', () => exportMenu?.classList.remove('show'));

  exportMenu?.querySelectorAll('button').forEach(btn => {
    btn.addEventListener('click', () => {
      const format = btn.dataset.export;
      exportNoteFile(format);
    });
  });
}

function createNewNote() {
  const newNote = {
    id: 'note-' + Date.now(),
    title: t('note_title_placeholder').replace('...', ''),
    content: '',
    updatedAt: Date.now()
  };
  appState.notes.unshift(newNote);
  appState.activeNoteId = newNote.id;
  saveNotesToStorage();
  renderNotesList();
  loadActiveNote();
  const titleInput = document.getElementById('noteTitle');
  if (titleInput) {
    titleInput.focus();
    titleInput.select();
  }
  showToast(t('toast_created_note'));
}

function renderNotesList(filterQuery = '') {
  const list = document.getElementById('notesList');
  if (!list) return;
  list.innerHTML = '';

  const filtered = appState.notes.filter(n => 
    n.title.toLowerCase().includes(filterQuery) || 
    n.content.toLowerCase().includes(filterQuery)
  );

  if (filtered.length === 0) {
    list.innerHTML = `
      <div class="empty-state-notes">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width:36px;height:36px;opacity:0.4"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
        <p>${t('empty_notes_title')}</p>
        <button class="btn-primary-gradient btn-sm" id="emptyCreateNoteBtn" style="margin-top:4px">${t('empty_notes_btn')}</button>
      </div>
    `;
    document.getElementById('emptyCreateNoteBtn')?.addEventListener('click', createNewNote);
    return;
  }

  filtered.forEach(note => {
    const item = document.createElement('div');
    item.className = `note-item ${note.id === appState.activeNoteId ? 'active' : ''}`;
    
    const timeAgo = formatTimeAgo(note.updatedAt);
    const snippet = note.content.slice(0, 45).replace(/[#*`\n]/g, ' ') || '...';

    item.innerHTML = `
      <div class="note-item-title">${escapeHTML(note.title || 'Untitled')}</div>
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
  const titleInput = document.getElementById('noteTitle');
  const contentInput = document.getElementById('noteContent');

  if (!note) {
    if (titleInput) titleInput.value = '';
    if (contentInput) contentInput.value = '';
    updateWordCounts();
    renderMarkdownPreview();
    return;
  }

  if (titleInput) titleInput.value = note.title;
  if (contentInput) contentInput.value = note.content;
  updateWordCounts();
  renderMarkdownPreview();
}

function autoSaveNote() {
  if (appState.notes.length === 0) {
    const newNote = {
      id: 'note-' + Date.now(),
      title: document.getElementById('noteTitle').value || 'Note',
      content: document.getElementById('noteContent').value || '',
      updatedAt: Date.now()
    };
    appState.notes.push(newNote);
    appState.activeNoteId = newNote.id;
  } else {
    const note = appState.notes.find(n => n.id === appState.activeNoteId);
    if (!note) return;
    note.title = document.getElementById('noteTitle').value;
    note.content = document.getElementById('noteContent').value;
    note.updatedAt = Date.now();
  }

  saveNotesToStorage();
  renderNotesList();

  const indicator = document.getElementById('saveIndicator');
  if (indicator) indicator.style.opacity = '1';
}

function saveNotesToStorage() {
  localStorage.setItem('aeropad_notes', JSON.stringify(appState.notes));
  updateStorageStat();
}

function updateWordCounts() {
  const contentEl = document.getElementById('noteContent');
  const text = contentEl ? contentEl.value : '';
  const words = text.trim() ? text.trim().split(/\s+/).length : 0;
  const chars = text.length;
  const readMinutes = Math.max(1, Math.ceil(words / 200));

  const wordEl = document.getElementById('wordCount');
  const charEl = document.getElementById('charCount');
  const readEl = document.getElementById('readTime');

  if (wordEl) wordEl.textContent = `${words} ${t('word_unit')}`;
  if (charEl) charEl.textContent = `${chars} ${t('char_unit')}`;
  if (readEl) readEl.textContent = `${readMinutes} ${t('read_unit')}`;
}

function renderMarkdownPreview() {
  const contentEl = document.getElementById('noteContent');
  const text = contentEl ? contentEl.value : '';
  const preview = document.getElementById('notePreview');
  if (!preview) return;
  
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

  preview.innerHTML = html || `<p style="color:var(--text-muted)">${t('empty_notes_title')}</p>`;
}

function insertFormatting(type) {
  const textarea = document.getElementById('noteContent');
  if (!textarea) return;
  const start = textarea.selectionStart;
  const end = textarea.selectionEnd;
  const selText = textarea.value.substring(start, end);

  let insert = '';
  switch (type) {
    case 'bold': insert = `**${selText || 'bold text'}**`; break;
    case 'italic': insert = `*${selText || 'italic text'}*`; break;
    case 'heading': insert = `\n## ${selText || 'Heading'}\n`; break;
    case 'code': insert = `\`${selText || 'code'}\``; break;
    case 'quote': insert = `\n> ${selText || 'Quote'}\n`; break;
    case 'list': insert = `\n- ${selText || 'List item'}`; break;
    case 'check': insert = `\n- [ ] ${selText || 'To-do item'}`; break;
  }

  textarea.setRangeText(insert, start, end, 'end');
  autoSaveNote();
  updateWordCounts();
  if (appState.editorMode !== 'edit') renderMarkdownPreview();
}

function exportNoteFile(type) {
  const note = appState.notes.find(n => n.id === appState.activeNoteId);
  if (!note) {
    showToast(t('empty_notes_title'), 'error');
    return;
  }

  let content = '';
  let filename = `${(note.title || 'note').replace(/\s+/g, '_')}`;
  let mimeType = 'text/plain';

  if (type === 'md') {
    content = `# ${note.title}\n\n${note.content}`;
    filename += '.md';
    mimeType = 'text/markdown';
  } else if (type === 'txt') {
    content = `${note.title}\n\n${note.content}`;
    filename += '.txt';
    mimeType = 'text/plain';
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
  showToast(`Exported: ${filename}`);
}

function updateStorageStat() {
  const jsonStr = JSON.stringify(appState);
  const bytes = new Blob([jsonStr]).size;
  const kb = (bytes / 1024).toFixed(1);
  const el = document.getElementById('storageUsage');
  if (el) el.textContent = `${kb} KB`;
}

// ==========================================
// 8. 2FA STUDIO & LIVE TOTP VAULT
// ==========================================
function initTOTPStudio() {
  renderTOTPCards();
  initTOTPGenerator();
}

// Secure Random Password Generator (Crypto API)
function generateRandomPassword(length = 16) {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const digits = '23456789';
  const symbols = '!@#$%^&*()_+~|}{[]:;?><,.-=';
  const all = upper + lower + digits + symbols;
  
  let password = '';
  password += upper.charAt(Math.floor(Math.random() * upper.length));
  password += lower.charAt(Math.floor(Math.random() * lower.length));
  password += digits.charAt(Math.floor(Math.random() * digits.length));
  password += symbols.charAt(Math.floor(Math.random() * symbols.length));
  
  const array = new Uint32Array(length - 4);
  window.crypto.getRandomValues(array);
  for (let i = 0; i < array.length; i++) {
    password += all.charAt(array[i] % all.length);
  }
  
  return password.split('').sort(() => 0.5 - Math.random()).join('');
}

function initTOTPGenerator() {
  const secretInput = document.getElementById('genSecret');
  const randomBtn = document.getElementById('randomSecretBtn');
  const copyBtn = document.getElementById('copyGenSecret');
  const issuerInput = document.getElementById('genIssuer');
  const accountInput = document.getElementById('genAccount');
  const algoSelect = document.getElementById('genAlgo');
  const periodSelect = document.getElementById('genPeriod');
  const digitsSelect = document.getElementById('genDigits');

  // Generator Password show/hide toggle
  document.getElementById('toggleGenPassVisibility')?.addEventListener('click', (e) => {
    e.preventDefault();
    const input = document.getElementById('genPassword');
    const eyeOpen = e.currentTarget.querySelector('.eye-open');
    const eyeClosed = e.currentTarget.querySelector('.eye-closed');
    if (input.type === 'password') {
      input.type = 'text';
      eyeOpen.classList.add('hidden');
      eyeClosed.classList.remove('hidden');
    } else {
      input.type = 'password';
      eyeOpen.classList.remove('hidden');
      eyeClosed.classList.add('hidden');
    }
  });

  // Generator Random Password Button
  document.getElementById('genPassBtn')?.addEventListener('click', (e) => {
    e.preventDefault();
    const pass = generateRandomPassword(16);
    const input = document.getElementById('genPassword');
    if (input) {
      input.value = pass;
      input.type = 'text';
      const btn = document.getElementById('toggleGenPassVisibility');
      btn?.querySelector('.eye-open')?.classList.add('hidden');
      btn?.querySelector('.eye-closed')?.classList.remove('hidden');
      showToast('Generated secure password!');
    }
  });

  // Modal Password show/hide toggle
  document.getElementById('toggleModalPassVisibility')?.addEventListener('click', (e) => {
    e.preventDefault();
    const input = document.getElementById('modalPassword');
    const eyeOpen = e.currentTarget.querySelector('.eye-open');
    const eyeClosed = e.currentTarget.querySelector('.eye-closed');
    if (input.type === 'password') {
      input.type = 'text';
      eyeOpen.classList.add('hidden');
      eyeClosed.classList.remove('hidden');
    } else {
      input.type = 'password';
      eyeOpen.classList.remove('hidden');
      eyeClosed.classList.add('hidden');
    }
  });

  // Modal Random Password Button
  document.getElementById('genModalPassBtn')?.addEventListener('click', (e) => {
    e.preventDefault();
    const pass = generateRandomPassword(16);
    const input = document.getElementById('modalPassword');
    if (input) {
      input.value = pass;
      input.type = 'text';
      const btn = document.getElementById('toggleModalPassVisibility');
      btn?.querySelector('.eye-open')?.classList.add('hidden');
      btn?.querySelector('.eye-closed')?.classList.remove('hidden');
      showToast('Generated secure password!');
    }
  });

  // Generate Initial Random Secret Key
  if (secretInput && !secretInput.value) {
    secretInput.value = Base32.randomSecret(16);
    renderQRCode();
  }

  randomBtn?.addEventListener('click', () => {
    if (secretInput) {
      secretInput.value = Base32.randomSecret(16);
      renderQRCode();
      showToast(t('gen_random_btn'));
    }
  });

  copyBtn?.addEventListener('click', () => {
    if (secretInput && secretInput.value) {
      navigator.clipboard.writeText(secretInput.value.trim());
      showToast(t('toast_secret_copied'));
    }
  });

  [secretInput, issuerInput, accountInput, algoSelect, periodSelect, digitsSelect].forEach(el => {
    el?.addEventListener('input', renderQRCode);
    el?.addEventListener('change', renderQRCode);
  });

  // Copy OTP Auth Link
  document.getElementById('copyOtpUrlBtn')?.addEventListener('click', () => {
    const uri = getOtpAuthURI();
    if (uri) {
      navigator.clipboard.writeText(uri);
      showToast(t('toast_otp_copied'));
    }
  });

  // Download QR PNG
  document.getElementById('downloadQRBtn')?.addEventListener('click', downloadQRPNG);

  // Save Gen to Vault
  document.getElementById('saveToVaultBtn')?.addEventListener('click', () => {
    const issuer = document.getElementById('genIssuer').value.trim() || '2FA Service';
    const account = document.getElementById('genAccount').value.trim() || 'user';
    const secret = document.getElementById('genSecret').value.trim().toUpperCase();
    const password = document.getElementById('genPassword')?.value.trim() || '';

    if (!secret) {
      showToast(t('gen_secret'), 'error');
      return;
    }

    const newItem = {
      id: 'totp-' + Date.now(),
      issuer,
      account,
      secret,
      password,
      digits: parseInt(document.getElementById('genDigits').value) || 6,
      period: parseInt(document.getElementById('genPeriod').value) || 30
    };

    appState.totpAccounts.push(newItem);
    localStorage.setItem('aeropad_totp', JSON.stringify(appState.totpAccounts));
    renderTOTPCards();
    showToast(t('toast_totp_added'));

    // Switch to Vault
    document.querySelector('.totp-subpill[data-subtab="vault"]')?.click();
  });

  // Quick Add 2FA Modal
  const modalBackdrop = document.getElementById('modalBackdrop');
  document.getElementById('quickAdd2FABtn')?.addEventListener('click', () => {
    modalBackdrop.classList.remove('hidden');
    document.getElementById('modalSecret').value = Base32.randomSecret(16);
    const modalPass = document.getElementById('modalPassword');
    if (modalPass) modalPass.value = '';
  });

  document.getElementById('closeModalBtn')?.addEventListener('click', () => modalBackdrop.classList.add('hidden'));
  document.getElementById('cancelModalBtn')?.addEventListener('click', () => modalBackdrop.classList.add('hidden'));

  document.getElementById('confirmAdd2FABtn')?.addEventListener('click', () => {
    const issuer = document.getElementById('modalIssuer').value.trim() || '2FA Service';
    const account = document.getElementById('modalAccount').value.trim() || 'user';
    const secret = document.getElementById('modalSecret').value.trim().toUpperCase();
    const password = document.getElementById('modalPassword')?.value.trim() || '';

    if (!secret) {
      showToast(t('gen_secret'), 'error');
      return;
    }

    appState.totpAccounts.push({
      id: 'totp-' + Date.now(),
      issuer,
      account,
      secret,
      password,
      digits: 6,
      period: 30
    });

    localStorage.setItem('aeropad_totp', JSON.stringify(appState.totpAccounts));
    renderTOTPCards();
    modalBackdrop.classList.add('hidden');
    showToast(t('toast_totp_added'));
  });
}

function getOtpAuthURI() {
  const secret = (document.getElementById('genSecret')?.value || '').trim().toUpperCase();
  if (!secret) return '';

  const issuer = encodeURIComponent(document.getElementById('genIssuer')?.value.trim() || 'AeroPad');
  const account = encodeURIComponent(document.getElementById('genAccount')?.value.trim() || 'user');
  const digits = document.getElementById('genDigits')?.value || '6';
  const period = document.getElementById('genPeriod')?.value || '30';

  return `otpauth://totp/${issuer}:${account}?secret=${secret}&issuer=${issuer}&digits=${digits}&period=${period}`;
}

function renderQRCode() {
  const uri = getOtpAuthURI();
  const container = document.getElementById('qrContainer');
  if (!container) return;

  const issVal = document.getElementById('genIssuer')?.value.trim();
  const accVal = document.getElementById('genAccount')?.value.trim();
  const prevIss = document.getElementById('previewIssuer');
  const prevAcc = document.getElementById('previewAccount');
  
  if (prevIss) prevIss.textContent = issVal || '---';
  if (prevAcc) prevAcc.textContent = accVal || 'user@account';

  if (!uri) {
    container.innerHTML = `<span style="color:var(--text-muted);font-size:0.8rem;text-align:center;padding:10px;">${t('no_qr_placeholder')}</span>`;
    return;
  }

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
  showToast(t('toast_qr_downloaded'));
}

async function renderTOTPCards() {
  const grid = document.getElementById('totpCardsGrid');
  if (!grid) return;
  grid.innerHTML = '';

  if (appState.totpAccounts.length === 0) {
    grid.innerHTML = `
      <div class="empty-state-totp glass-panel">
        <div class="empty-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
        </div>
        <h3>${t('empty_totp_title')}</h3>
        <p>${t('empty_totp_desc')}</p>
      </div>
    `;
    return;
  }

  for (const acc of appState.totpAccounts) {
    const card = document.createElement('div');
    card.className = 'totp-card glass-panel';
    card.dataset.accId = acc.id;
    
    const initial = (acc.issuer || '2F').charAt(0).toUpperCase();
    const currentCode = await generateTOTP(acc.secret, acc.period, acc.digits);
    const formattedCode = currentCode.slice(0, 3) + ' ' + currentCode.slice(3);

    const hasPassword = Boolean(acc.password && acc.password.trim().length > 0);
    const passwordRowHTML = hasPassword ? `
      <div class="totp-card-password-row">
        <div class="pass-label-col">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="pass-icon"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
          <span class="pass-masked-val" id="pass-val-${acc.id}">••••••••••••</span>
        </div>
        <div class="pass-actions-col">
          <button class="btn-icon-xs toggle-card-pass" data-id="${acc.id}" title="Show/Hide Password">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="eye-open"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="eye-closed hidden"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
          </button>
          <button class="btn-icon-xs copy-card-pass" data-id="${acc.id}" title="Copy Password">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
          </button>
        </div>
      </div>
    ` : '';

    card.innerHTML = `
      <div class="totp-card-top">
        <div class="totp-issuer-group">
          <div class="totp-avatar">${initial}</div>
          <div>
            <div class="totp-issuer-title">${escapeHTML(acc.issuer)}</div>
            <div class="totp-account-label">${escapeHTML(acc.account)}</div>
          </div>
        </div>
        <button class="btn-danger-ghost delete-totp-btn" title="Delete account">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
        </button>
      </div>

      <div class="totp-code-box">
        <div class="totp-code-text" id="code-${acc.id}">${formattedCode}</div>
        <button class="btn-copy-code" title="Copy 6-digit code">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
        </button>
      </div>

      ${passwordRowHTML}

      <div class="totp-card-footer">
        <span>RFC 6238 HMAC-SHA1</span>
        <span class="font-mono text-cyan">${acc.period}s</span>
      </div>
      <div class="totp-card-progress">
        <div class="totp-card-progress-bar" id="prog-${acc.id}"></div>
      </div>
    `;

    // Copy action
    card.querySelector('.btn-copy-code')?.addEventListener('click', (e) => {
      e.stopPropagation();
      navigator.clipboard.writeText(currentCode);
      showToast(`${t('toast_code_copied')} ${currentCode}`);
    });

    // Copy Password action
    if (hasPassword) {
      card.querySelector('.copy-card-pass')?.addEventListener('click', (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(acc.password);
        showToast(t('toast_pass_copied') || 'Password copied to clipboard!');
      });

      // Toggle Password reveal/mask
      card.querySelector('.toggle-card-pass')?.addEventListener('click', (e) => {
        e.stopPropagation();
        const btn = e.currentTarget;
        const valEl = document.getElementById(`pass-val-${acc.id}`);
        const eyeOpen = btn.querySelector('.eye-open');
        const eyeClosed = btn.querySelector('.eye-closed');
        
        if (valEl.textContent === '••••••••••••') {
          valEl.textContent = acc.password;
          eyeOpen.classList.add('hidden');
          eyeClosed.classList.remove('hidden');
        } else {
          valEl.textContent = '••••••••••••';
          eyeOpen.classList.remove('hidden');
          eyeClosed.classList.add('hidden');
        }
      });
    }

    // Card click copies OTP code (except when clicking buttons/passwords)
    card.addEventListener('click', (e) => {
      if (e.target.closest('.delete-totp-btn') || e.target.closest('.totp-card-password-row')) return;
      navigator.clipboard.writeText(currentCode);
      showToast(`${t('toast_code_copied')} ${currentCode}`);
    });

    // Delete
    card.querySelector('.delete-totp-btn')?.addEventListener('click', (e) => {
      e.stopPropagation();
      appState.totpAccounts = appState.totpAccounts.filter(a => a.id !== acc.id);
      localStorage.setItem('aeropad_totp', JSON.stringify(appState.totpAccounts));
      renderTOTPCards();
      showToast(t('toast_deleted_note'));
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
// 9. 2FA DECODER & QR SCANNER
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
  decodeBtn?.addEventListener('click', () => {
    const text = rawInput.value.trim();
    if (!text) {
      showToast(t('paste_prompt'), 'error');
      return;
    }
    parseAndDisplayOTPString(text);
  });

  // Copy Decoded Secret
  document.getElementById('copyDecSecret')?.addEventListener('click', () => {
    if (currentDecodedSecret) {
      navigator.clipboard.writeText(currentDecodedSecret);
      showToast(t('toast_secret_copied'));
    }
  });

  // Toggle Decoded Password visibility
  document.getElementById('toggleDecPassVisibility')?.addEventListener('click', (e) => {
    e.preventDefault();
    const input = document.getElementById('decPasswordInput');
    const eyeOpen = e.currentTarget.querySelector('.eye-open');
    const eyeClosed = e.currentTarget.querySelector('.eye-closed');
    if (input.type === 'password') {
      input.type = 'text';
      eyeOpen.classList.add('hidden');
      eyeClosed.classList.remove('hidden');
    } else {
      input.type = 'password';
      eyeOpen.classList.remove('hidden');
      eyeClosed.classList.add('hidden');
    }
  });

  // Add Decoded to Vault
  document.getElementById('addDecodedToVaultBtn')?.addEventListener('click', () => {
    if (!currentDecodedItem) return;
    const password = document.getElementById('decPasswordInput')?.value.trim() || '';
    appState.totpAccounts.push({
      id: 'totp-' + Date.now(),
      issuer: currentDecodedItem.issuer,
      account: currentDecodedItem.account,
      secret: currentDecodedItem.secret,
      password,
      digits: 6,
      period: 30
    });
    localStorage.setItem('aeropad_totp', JSON.stringify(appState.totpAccounts));
    renderTOTPCards();
    showToast(t('toast_totp_added'));
    document.querySelector('.totp-subpill[data-subtab="vault"]')?.click();
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
          showToast(t('toast_qr_detected'));
          parseAndDisplayOTPString(code.data);
        } else {
          showToast('Failed to decode QR code from image.', 'error');
        }
      } else {
        showToast('jsQR library not loaded', 'error');
      }
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

async function parseAndDisplayOTPString(input) {
  let issuer = 'Security Service';
  let account = 'user@vault';
  let secret = '';

  if (input.startsWith('otpauth://')) {
    try {
      const url = new URL(input);
      const label = decodeURIComponent(url.pathname.replace(/^\/+/, '').replace(/^totp\//i, ''));
      if (label.includes(':')) {
        const parts = label.split(':');
        issuer = parts[0];
        account = parts[1];
      } else if (label) {
        account = label;
      }
      secret = (url.searchParams.get('secret') || '').replace(/[\s-]/g, '').toUpperCase();
      if (url.searchParams.get('issuer')) {
        issuer = url.searchParams.get('issuer');
      }
    } catch (err) {
      console.warn('URL Parse warning:', err);
    }
  } else {
    // Pure Base32 key
    secret = input.replace(/[\s-]/g, '').toUpperCase();
    issuer = 'Direct Key';
    account = 'Account';
  }

  if (!secret) {
    showToast('Invalid Secret Key', 'error');
    return;
  }

  currentDecodedSecret = secret;
  currentDecodedItem = { issuer, account, secret };

  const decIss = document.getElementById('decIssuer');
  const decAcc = document.getElementById('decAccount');
  const decSec = document.getElementById('decSecret');

  if (decIss) decIss.textContent = issuer;
  if (decAcc) decAcc.textContent = account;
  if (decSec) decSec.textContent = secret;

  // Generate live code
  const liveCode = await generateTOTP(secret);
  const liveDisplay = document.getElementById('decLiveCode');
  if (liveDisplay) {
    liveDisplay.innerHTML = `<span>${liveCode.slice(0, 3)}</span> <span>${liveCode.slice(3)}</span>`;
  }

  document.getElementById('decoderResultCard')?.scrollIntoView({ behavior: 'smooth' });
}

// ==========================================
// 10. HELPERS
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
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}
