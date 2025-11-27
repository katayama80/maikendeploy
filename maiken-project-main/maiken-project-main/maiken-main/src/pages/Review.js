import React, { useState, useEffect } from 'react';
// ★ Firebaseモジュールをインポート (認証関連をすべて追加)
// ★ 修正: getApp, getApps を追加 (重複初期化エラー 'app/duplicate-app' 回避のため)
import { initializeApp, getApp, getApps } from "firebase/app";
import {
  getAuth,
  onAuthStateChanged,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
} from "firebase/auth";

// ★ 削除: ハードコードされたAPI_URLは削除
// const API_URL = 'https://jt1tbf88-3000.asse.devtunnels.ms/';

// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
// ★ 修正: firebaseConfig
// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
const firebaseConfig = {
  apiKey: "AIzaSyChc6zo5ZH5QbGAdj9526jEeakvxaYg8js",
  authDomain: "maiken-2025.firebaseapp.com",
  projectId: "maiken-2025",
  storageBucket: "maiken-2025.firebasestorage.app",
  messagingSenderId: "106897039274",
  appId: "1:106897039274:web:812bd77ce5f3518bc255d3",
  measurementId: "G-58V56R0HSW"
};

// ★ 修正: Firebaseアプリを初期化 (重複エラー 'app/duplicate-app' を回避)
// 既に[DEFAULT]アプリが初期化されていなければ初期化し、されていれば既存のものを取得する
const app = !getApps().length ? initializeApp(firebaseConfig) : getApp();
const auth = getAuth(app);


// ★ 修正: propsで apiUrl を受け取る
const Review = ({ setCurrentPage, apiUrl }) => {
  const [reviewData, setReviewData] = useState({
    comment: ''
  });
  const [isReviewButtonEnabled, setIsReviewButtonEnabled] = useState(false);
  const [isCompleted, setIsCompleted] = useState(false);

  // ★ 認証用のState
  const [currentUser, setCurrentUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);

  // ★ ログイン/新規登録フォーム用のState (追加)
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState(null); // 認証エラーメッセージ用

  // ★ 認証状態の監視
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      setCurrentUser(user);
      setAuthLoading(false); // 認証状態が確定
      setAuthError(null); // ユーザー状態が変わったらエラーをリセット
    });
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    const allFieldsFilled = reviewData.comment.trim() !== '';
    setIsReviewButtonEnabled(allFieldsFilled);
  }, [reviewData]);

  const handleReviewChange = (field, value) => {
    setReviewData({ ...reviewData, [field]: value });
  };

  // ★ 新規登録処理 (追加)
  const handleSignUp = async () => {
    setAuthError(null);
    try {
      await createUserWithEmailAndPassword(auth, email, password);
      // 成功時、onAuthStateChanged が自動的に currentUser をセットする
    } catch (error) {
      console.error("Sign up error:", error);
      setAuthError(getFriendlyAuthErrorMessage(error));
    }
  };

  // ★ ログイン処理 (追加)
  const handleLogin = async () => {
    setAuthError(null);
    try {
      await signInWithEmailAndPassword(auth, email, password);
      // 成功時、onAuthStateChanged が自動的に currentUser をセットする
    } catch (error) {
      console.error("Login error:", error);
      setAuthError(getFriendlyAuthErrorMessage(error));
    }
  };

  // ★ ログアウト処理 (追加)
  const handleLogout = async () => {
    setAuthError(null);
    try {
      await signOut(auth);
      // 成功時、onAuthStateChanged が自動的に currentUser を null にする
    } catch (error) {
      console.error("Logout error:", error);
      setAuthError(getFriendlyAuthErrorMessage(error));
    }
  };

  // ★ Firebaseエラーを日本語に変換するヘルパー (追加)
  const getFriendlyAuthErrorMessage = (error) => {
    switch (error.code) {
      case 'auth/invalid-email':
        return 'メールアドレスの形式が正しくありません。';
      case 'auth/user-not-found':
        return 'このメールアドレスは登録されていません。';
      case 'auth/wrong-password':
        return 'パスワードが間違っています。';
      case 'auth/email-already-in-use':
        return 'このメールアドレスは既に使用されています。';
      case 'auth/weak-password':
        return 'パスワードは6文字以上である必要があります。';
      default:
        return '認証に失敗しました。もう一度お試しください。';
    }
  };


  const handleReviewSubmit = async () => {
    // ★ apiUrl が渡されているか確認
    if (!apiUrl) {
      alert("API URLが設定されていません。App.jsを確認してください。");
      return;
    }
    // ★ ログインチェック (念のため残す)
    if (!currentUser) {
      alert("レビューを投稿するにはログインが必要です。");
      return;
    }

    let response;

    try {
      // ★ IDトークンを取得
      const idToken = await currentUser.getIdToken();

      // ★ 修正: propsの apiUrl を使用 (404エラー修正)
      response = await fetch(`${apiUrl}/reviews`, { // サーバーURL
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${idToken}`
        },
        body: JSON.stringify({
          comment: reviewData.comment,
        }),
      });

      if (!response.ok) {
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
          const errorData = await response.json();
          throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
        } else {
          const errorText = await response.text();
          console.error("Server returned non-JSON error:", errorText);
          throw new Error(`サーバーが予期しない応答を返しました (Status: ${response.status})`);
        }
      }

      console.log('レビューデータが正常にサーバー経由で保存されました。');
      setIsCompleted(true);

    } catch (error) {
      console.error('データの保存中にエラーが発生しました:', error);
      alert(`レビューの登録に失敗しました: ${error.message}`);
    }
  };

  if (isCompleted) {
    return (
      <div className="completion-screen">
        <p>回答終了。<br />結果はカレンダーをご参照ください。</p>
        <div className="action-buttons">
          <button onClick={() => setCurrentPage('main')}>前の画面に戻る</button>
        </div>
      </div>
    );
  }

  // ★ 認証状態を確認中
  if (authLoading) {
    return <div>認証情報を確認中...</div>;
  }

  // ★ 未ログインの場合 (ログインフォームを表示)
  if (!currentUser) {
    return (
      <div className="screen-container">
        <h2>レビュー（ログイン/新規登録）</h2>

        {/* ★ 認証フォームUI (追加) */}
        <div className="auth-form">
          <div className="form-group">
            <label>メールアドレス</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="test@example.com"
            />
          </div>
          <div className="form-group">
            NT            <label>パスワード (6文字以上)</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="******"
            />
          </div>

          {/* エラーメッセージ表示 */}
          {authError && <p className="auth-error" style={{ color: 'red' }}>{authError}</p>}

          <div className="action-buttons auth-buttons">
            <button onClick={handleLogin}>ログイン</button>
            <button onClick={handleSignUp}>新規登録</button>
          </div>
        </div>

        <hr style={{ margin: '20px 0' }} />
        <button onClick={() => setCurrentPage('main')}>メイン画面に戻る</button>
      </div>
    );
  }

  // ★ ログイン済みの場合 (レビュー投稿フォームを表示)
  return (
    <div className="screen-container">
      <h2>レビュー</h2>

      {/* ★ ログイン情報とログアウトボタン (追加) */}
      <div className="user-info">
        <p>{currentUser.email} でログイン中</p>
        SAP     <button onClick={handleLogout} className="logout-button">ログアウト</button>
      </div>

      <div className="review-step">
        <div className="review-item">
          <label>コメント</label>
          <textarea value={reviewData.comment} onChange={(e) => handleReviewChange('comment', e.target.value)} maxLength="1000" />
          <div className="char-limit">
            文字制限 {reviewData.comment.length}/1000文字
          </div>
        </div>
        <div className="action-buttons">
          <button onClick={handleReviewSubmit} disabled={!isReviewButtonEnabled}>回答</button>
          <button onClick={() => setCurrentPage('main')}>キャンセル</button>
        </div>
      </div>
    </div>
  );
};

export default Review;