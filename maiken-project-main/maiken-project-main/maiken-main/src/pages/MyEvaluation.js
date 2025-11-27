// src/pages/MyEvaluation.js

import React, { useState, useEffect } from 'react';
// ★ Firebaseモジュールをインポート (認証のために追加)
import { initializeApp, getApp, getApps } from "firebase/app";
import { getAuth, onAuthStateChanged, getIdToken } from "firebase/auth"; // getIdToken も使用


// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
// ★ Firebase設定 (Review.jsから流用)
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
const app = !getApps().length ? initializeApp(firebaseConfig) : getApp();
const auth = getAuth(app);


// ★ 修正: propsで apiUrl と mainScreenState を受け取る
const MyEvaluation = ({ setCurrentPage, apiUrl, mainScreenState }) => { // ★ apiUrl, mainScreenState を追加
  const [foodAmounts, setFoodAmounts] = useState({
    '筑前煮': 0, // ★ 初期値を数値(0)に
    '温泉卵': 0,
    '温野菜サラダ': 0,
    '味噌汁': 0,
    'ごはん(A定食)': 0
  });
  const [isEvaluationButtonEnabled, setIsEvaluationButtonEnabled] = useState(false);
  const [isCompleted, setIsCompleted] = useState(false);
  
  // ★ 認証用のStateを追加
  const [currentUser, setCurrentUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);

  // ★ 認証状態の監視 (Review.jsから流用)
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      setCurrentUser(user);
      setAuthLoading(false); 
    });
    return () => unsubscribe();
  }, []);


  useEffect(() => {
    // foodAmountsの全ての値が数値または空文字以外であることを確認 (今回は数値0を許容)
    const allFieldsFilled = Object.values(foodAmounts).every(amount => amount !== '' && amount !== null);
    setIsEvaluationButtonEnabled(allFieldsFilled);
  }, [foodAmounts]);

  const handleFoodAmountChange = (dish, value) => {
    // 入力を数値として扱い、0〜200%に制限
    const amount = Math.min(Math.max(0, parseInt(value) || 0), 200);
    setFoodAmounts({ ...foodAmounts, [dish]: amount });
  };

  const handleEvaluationSubmit = async () => {
    // ★ apiUrl が渡されているか確認
    if (!apiUrl) {
      alert("API URLが設定されていません。");
      return;
    }
    // ★ ログインチェック
    if (!currentUser) {
      alert("評価を投稿するにはログインが必要です。");
      return;
    }
    
    // ★ サーバー側のAPIで必須となっている mealId を生成
    // 献立を特定するための仮のIDとして、選択された日付+時間+定食名を使用します。
    const { selectedDate, selectedTime, selectedMeal } = mainScreenState;
    if (!selectedDate || !selectedTime || !selectedMeal) {
      alert("評価を投稿する前に、メイン画面で献立の日付、時間、定食を選択してください。");
      return;
    }
    const mealId = `${selectedDate}_${selectedTime}_${selectedMeal}`; 

    let response;

    try {
      // ★ IDトークンを取得
      const idToken = await currentUser.getIdToken();

      // サーバーの /evaluations エンドポイントにデータを送信
      // ★ 修正: propsの apiUrl を使用し、認証ヘッダーを追加
      response = await fetch(`${apiUrl}/evaluations`, { 
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${idToken}` // ★ 認証ヘッダーを追加
        },
        body: JSON.stringify({
          foodAmounts: foodAmounts,
          mealId: mealId, // ★ サーバーの必須項目を追加
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

      console.log('自分の評価データが正常にサーバー経由で保存されました。');
      setIsCompleted(true);
    } catch (error) {
      console.error('データの保存中にエラーが発生しました:', error);
      alert(`評価の登録に失敗しました: ${error.message}`);
    }
  };

  // ★ 認証状態を確認中
  if (authLoading) {
    return <div>認証情報を確認中...</div>;
  }
  
  // ★ 未ログイン時は評価を許可しない
  if (!currentUser) {
    return (
      <div className="screen-container">
        <h2>自分の評価</h2>
        <p style={{ color: 'red' }}>評価を投稿するには、Firebaseにログインが必要です。先にレビューページでログインしてください。</p>
        <div className="action-buttons">
          <button onClick={() => setCurrentPage('review')}>レビューページへ</button>
          <button onClick={() => setCurrentPage('main')}>前の画面に戻る</button>
        </div>
      </div>
    );
  }


  if (isCompleted) {
    // ... (変更なし)
    return (
      <div className="completion-screen">
        <p>回答終了。<br />結果はカレンダーをご参照ください。</p>
        <div className="action-buttons">
          <button onClick={() => setCurrentPage('main')}>前の画面に戻る</button>
        </div>
      </div>
    );
  }

  return (
    <div className="screen-container">
      <h2>自分の評価</h2>
      <p>料理をそれぞれ何割食べたのか</p>
      {/* ★ 選択献立の確認用UIを追加 */}
      <p style={{ fontWeight: 'bold' }}>
        選択中の献立: {mainScreenState.selectedDate} / {mainScreenState.selectedTime} / {mainScreenState.selectedMeal}
      </p> 
      <table className="food-table">
        <thead>
          <tr>
            <th>料理</th>
            <th>どれくらい食べたか %</th>
          </tr>
        </thead>
        <tbody>
          {Object.keys(foodAmounts).map((dish) => (
            <tr key={dish}>
              <td>{dish}</td>
              <td>
                <input
                  type="number"
                  min="0"
                  max="200"
                  value={foodAmounts[dish]}
                  onChange={(e) => handleFoodAmountChange(dish, e.target.value)}
                />
                %
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="action-buttons">
        <button onClick={handleEvaluationSubmit} disabled={!isEvaluationButtonEnabled}>回答</button>
        <button onClick={() => setCurrentPage('main')}>キャンセル</button>
      </div>
    </div>
  );
};

export default MyEvaluation;