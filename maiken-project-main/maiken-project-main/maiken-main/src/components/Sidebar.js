// src/components/Sidebar.js

import React from 'react';

// 🔴 変更点: propsとして isOpen を追加 🔴
const Sidebar = ({ currentPage, setCurrentPage, toggleSidebar, isOpen }) => {
  const sidebarItems = [
    { id: 'about', label: '説明・使い方' },
    { id: 'calendar', label: 'カレンダー機能' },
    { id: 'main', label: '自分の評価+レビュー' },
    { id: 'comments', label: 'コメント閲覧機能' },
  ];

  return (
    // 🔴 変更点: isOpenがtrueの場合に 'open' クラスを追加 🔴
    <div className={`sidebar-container ${isOpen ? 'open' : ''}`}>
      <button onClick={toggleSidebar} className="hamburger-menu">
        <span></span>
        <span></span>
        <span></span>
      </button>

      <div className="sidebar-title">まいけん</div>

      <ul className="sidebar-menu">
        {sidebarItems.map((item) => (
          <li
            key={item.id}
            onClick={() => setCurrentPage(item.id)}
            className={`sidebar-item ${currentPage === item.id ? 'selected' : ''}`}
          >
            {item.label}
          </li>
        ))}
      </ul>
    </div>
  );
};

export default Sidebar;