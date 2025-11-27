// src/pages/Calendar.js
import React, { useState } from 'react';

const Calendar = () => {
  const [currentDate, setCurrentDate] = useState(new Date());
  const [selectedDay, setSelectedDay] = useState(null);
  const [selectedWeekDay, setSelectedWeekDay] = useState(null);

  const getDaysInMonth = (year, month) => {
    return new Date(year, month + 1, 0).getDate();
  };

  const getFirstDayOfMonth = (year, month) => {
    return new Date(year, month, 1).getDay();
  };

  const year = currentDate.getFullYear();
  const month = currentDate.getMonth();
  const monthName = currentDate.toLocaleString('default', { month: 'long' });

  const daysInMonth = getDaysInMonth(year, month);
  const firstDay = getFirstDayOfMonth(year, month);
  const calendarDays = [];

  for (let i = 0; i < firstDay; i++) {
    calendarDays.push('');
  }

  for (let i = 1; i <= daysInMonth; i++) {
    calendarDays.push(i);
  }

  const goToPreviousMonth = () => {
    setCurrentDate(new Date(year, month - 1, 1));
    setSelectedDay(null);
    setSelectedWeekDay(null);
  };

  const goToNextMonth = () => {
    setCurrentDate(new Date(year, month + 1, 1));
    setSelectedDay(null);
    setSelectedWeekDay(null);
  };

  // 日付がクリックされたときの処理
  const handleDayClick = (day) => {
    if (!day) return;

    if (day === selectedDay) {
      // 既に選択されている日付を再度クリックした場合、選択を解除
      setSelectedDay(null);
      setSelectedWeekDay(null);
    } else {
      // 新しい日付を選択
      const clickedDate = new Date(year, month, day);
      const weekDayName = clickedDate.toLocaleString('default', { weekday: 'long' });
      setSelectedDay(day);
      setSelectedWeekDay(weekDayName);
    }
  };

  const weekDays = ['日', '月', '火', '水', '木', '金', '土'];

  return (
    <div className="calendar">
      <h2 className="page-title">React シンプルカレンダー</h2>
      <div className="header">
        <button onClick={goToPreviousMonth}>&lt;</button>
        <h2 className="header-title">{year}年 {monthName}</h2>
        <button onClick={goToNextMonth}>&gt;</button>
      </div>
      <div className="weekdays">
        {weekDays.map((day) => (
          <div key={day} className="weekday">{day}</div>
        ))}
      </div>
      <div className="days">
        {calendarDays.map((day, index) => (
          <div
            key={index}
            className={`day ${day !== '' && day === selectedDay ? 'selected' : ''}`}
            onClick={() => handleDayClick(day)}
          >
            {day}
          </div>
        ))}
      </div>

      {/* 選択された日付と曜日を常時表示するエリア */}
      <div className="selected-info">
        <div className="info-box">
          <div className="box-title">日にち</div>
          <div className="box-content">{selectedDay || ''}</div>
        </div>
        <div className="info-box">
          <div className="box-title">曜日</div>
          <div className="box-content">{selectedWeekDay || ''}</div>
        </div>
      </div>
    </div>
  );
};

export default Calendar;