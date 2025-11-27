// setAdmin.js (管理者設定用の使い捨てスクリプト)

const admin = require('firebase-admin');

// ★★★★★★★ 修正する箇所 (1) ★★★★★★★
// ステップ1で調べた「あなたのUID」に書き換えてください
const USER_ID_TO_MAKE_ADMIN = 'MH0SUqgCDXgTK9JqCpln7ArEepi2'; 
// 例: 'aBcDeF12345GhIjK67890'

// ★★★★★★★ 修正する箇所 (2) ★★★★★★★
// ステップ2でダウンロードした「秘密鍵のJSONファイル」へのパスに書き換えてください
// ★ 修正後 (スラッシュ)
const SERVICE_ACCOUNT_KEY_PATH = 'C:/Users/80kat/OneDrive/デスクトップ/maiken-project/image-uploader/maiken-2025-firebase-adminsdk-fbsvc-1a6f9c8d94.json';
// 例: './firebase-adminsdk-xxxx-yyyy.json'

// --- Firebase Adminの初期化 ---
try {
  const serviceAccount = require(SERVICE_ACCOUNT_KEY_PATH);
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
} catch (e) {
  console.error('Error initializing Firebase Admin:', e.message);
  console.error('秘密鍵のパス (SERVICE_ACCOUNT_KEY_PATH) が正しいか確認してください。');
  process.exit(1);
}
// -----------------------------------


// --- メイン処理: カスタムクレームを設定 ---
async function setAdminClaim() {
  if (!USER_ID_TO_MAKE_ADMIN || USER_ID_TO_MAKE_ADMIN === 'YOUR_USER_ID') {
    console.error('エラー: USER_ID_TO_MAKE_ADMIN をあなたのUIDに書き換えてください。');
    return;
  }

  console.log(`UID: ${USER_ID_TO_MAKE_ADMIN} に管理者権限 (admin: true) を設定します...`);

  try {
    // これがカスタムクレームを設定する処理
    await admin.auth().setCustomUserClaims(USER_ID_TO_MAKE_ADMIN, { admin: true });
    
    console.log('----------------------------------------------------');
    console.log('✅ 成功！');
    console.log(`ユーザー (${USER_ID_TO_MAKE_ADMIN}) は管理者になりました。`);
    console.log('Reactアプリで一度ログアウトし、再度ログインして確認してください。');
    console.log('----------------------------------------------------');

  } catch (error) {
    console.error('カスタムクレームの設定に失敗しました:', error.message);
  } finally {
    process.exit(0); // 処理が完了したら終了
  }
}

// スクリプトを実行
setAdminClaim();