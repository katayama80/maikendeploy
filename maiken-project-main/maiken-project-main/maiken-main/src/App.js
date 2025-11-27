// src/App.js

import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import About from './pages/About';
import Calendar from './pages/Calendar';
import MainScreen from './pages/MainScreen';
import MyEvaluation from './pages/MyEvaluation';
import Review from './pages/Review';
import Comments from './pages/Comments';
import './App.css';

// ★ サーバーのURLを定数として定義
// ★ 修正: 末尾のスラッシュを削除
const API_URL = 'https://jt1tbf88-3000.asse.devtunnels.ms';

function App() {
  const [currentPage, setCurrentPage] = useState('about');
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);

  // ★ サーバーの接続状態を管理するためのstateを追加
  const [serverStatus, setServerStatus] = useState('connecting'); // 'connecting', 'online', 'offline'

  // MainScreenの項目をApp.jsで管理
  const [mainScreenState, setMainScreenState] = useState({
    selectedDate: '',
    selectedTime: '',
    selectedMeal: ''
  });

  // ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
  // ★ サーバーの生存確認を行う処理 ★
  // ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
  useEffect(() => {
    // 生存確認を行う関数
    const checkServerHealth = () => {
      // ★ 修正: API_URL を使用してヘルスチェックパスを構築
      fetch(`${API_URL}/health`)
        .then(response => {
          // サーバーからの応答があれば 'online' に設定
          if (response.ok) {
            setServerStatus('online');
          } else {
            setServerStatus('offline');
          }
        })
        .catch((error) => { // ★ エラーオブジェクトを受け取る
          // fetch自体が失敗した場合 (サーバーがダウンしているなど) は 'offline' に設定
          console.error("Health check failed:", error); // ★ エラーをコンソールに出力
          setServerStatus('offline');
        });
    };

    // 最初に一度、すぐに確認
    checkServerHealth();

    // その後、5秒ごとに定期的に確認
    const intervalId = setInterval(checkServerHealth, 5000);

    // コンポーネントがアンマウントされるときに、定期実行をクリーンアップ
    return () => clearInterval(intervalId);
  }, []); // []が空なので、このuseEffectは最初のマウント時に1回だけ実行される


  const toggleSidebar = () => {
    setIsSidebarOpen(!isSidebarOpen);
  };

  const renderPage = () => {
    // ★ サーバーがオフラインの場合は、どのページでもエラーメッセージを表示
    if (serverStatus === 'offline') {
      return (
        <div>
          <h1 style={{ color: 'red' }}>サーバーに接続できません</h1>
          <p>バックエンドサーバー({API_URL})が起動しているか、</p>
          <p>またはVSCodeのポートフォワーディング設定を確認してください。</p>
        </div>
      );
    }
    // ★ 接続中の表示を追加
    if (serverStatus === 'connecting') {
      return <div>サーバーに接続中...</div>;
    }

    switch (currentPage) {
      case 'about':
        return <About />;
      case 'calendar':
        return <Calendar />;
      case 'main':
        return (
          <MainScreen
            mainScreenState={mainScreenState}
            setMainScreenState={setMainScreenState}
            setCurrentPage={setCurrentPage}
          />
        );
      case 'myEvaluation':
        // ★ MyEvaluation に API_URL を渡す (MyEvaluation.js側も修正が必要)
        return <MyEvaluation setCurrentPage={setCurrentPage} apiUrl={API_URL} />;
      case 'review':
        // ★ Review に API_URL を渡す (Review.js側も修正が必要)
        return <Review setCurrentPage={setCurrentPage} apiUrl={API_URL} />;
      case 'comments':
        // ★ Comments に API_URL を渡す (Comments.js側も修正が必要)
        return <Comments apiUrl={API_URL} />;
      default:
        return <About />;
    }
  };

  // ★ 接続状態を示すためのバナーのスタイル
  const statusBannerStyle = {
    padding: '10px',
    textAlign: 'center',
    fontWeight: 'bold',
    color: 'white',
    position: 'fixed',
    width: '100%',
    top: 0,
    left: 0,
    zIndex: 1000,
  };


  return (
    <div className={`app-container ${isSidebarOpen ? 'sidebar-open' : ''}`}>
      {/* ★ 接続状態に応じてバナーを表示 */}
      {serverStatus === 'offline' && (
        <div style={{ ...statusBannerStyle, backgroundColor: '#e74c3c' /* 赤 */ }}>
          サーバー接続が切断されました
        </div>
      )}
      {serverStatus === 'connecting' && (
        <div style={{ ...statusBannerStyle, backgroundColor: '#f39c12' /* オレンジ */ }}>
          サーバーに接続中...
        </div>
      )}

      <Sidebar
        currentPage={currentPage}
        setCurrentPage={setCurrentPage}
        toggleSidebar={toggleSidebar}
        isOpen={isSidebarOpen}
      />

      {!isSidebarOpen && (
        <button onClick={toggleSidebar} className="hamburger-menu-closed">
          <span></span>
          <span></span>
          <span></span>
        </button>
      )}

      {/* ★ バナーの高さを考慮して main-content の padding-top を調整 */}
      <div className="main-content" style={{ paddingTop: serverStatus !== 'online' ? '40px' : '0' }}>
        {renderPage()}
      </div>
    </div>
  );
}

export default App;