import React from 'react';

const MainScreen = ({ mainScreenState, setMainScreenState, setCurrentPage }) => {
  const { selectedDate, selectedTime, selectedMeal } = mainScreenState;

  const isButtonEnabled = selectedDate && selectedTime && selectedMeal;

  const getDayOfWeek = (dateString) => {
    if (!dateString) return '';
    const date = new Date(dateString);
    const dayOfWeek = date.getDay();
    const days = ['日', '月', '火', '水', '木', '金', '土'];
    return days[dayOfWeek];
  };

  const handleStateChange = (field, value) => {
    setMainScreenState(prevState => ({
      ...prevState,
      [field]: value
    }));
  };

  return (
    <div className="screen-container">
      <h2 className="page-title">自分の評価+レビュー</h2>

      <div className="setting-item">
        <label>何年何月何日何曜日か</label>
        <input type="date" value={selectedDate} onChange={(e) => handleStateChange('selectedDate', e.target.value)} />
        <span>{selectedDate && ` (${getDayOfWeek(selectedDate)}曜日)`}</span>
      </div>

      <div className="setting-item">
        <label>朝・昼・晩のどれか</label>
        <select value={selectedTime} onChange={(e) => handleStateChange('selectedTime', e.target.value)}>
          <option value="">選択してください</option>
          <option value="朝">朝</option>
          <option value="昼">昼</option>
          <option value="晩">晩</option>
        </select>
      </div>

      <div className="setting-item">
        <label>A定食・B定食・どちらも食べていない</label>
        <select value={selectedMeal} onChange={(e) => handleStateChange('selectedMeal', e.target.value)}>
          <option value="">選択してください</option>
          <option value="A定食">A定食</option>
          <option value="B定食">B定食</option>
          <option value="どちらも食べていない">どちらも食べていない</option>
        </select>
      </div>

      <hr />

      <div className="button-group">
        <button onClick={() => setCurrentPage('myEvaluation')} disabled={!isButtonEnabled}>
          自分の評価
        </button>
        <button onClick={() => setCurrentPage('review')} disabled={!isButtonEnabled}>
          レビュー
        </button>
      </div>
    </div>
  );
};

export default MainScreen;