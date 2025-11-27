import React from 'react';

// MaikenIntro component
const MaikenIntro = () => {
  return (
    <div>
      <h2 >まいけんの説明</h2>
      <p>
        "まいけん" は鶴友寮の寮食専用アプリの事です。
        <br></br>
        食事へのコメントをしたり、他の人の食事の評価を確認することが出来ます。
        <br></br>
        このサイトを使用することで自らの食生活の評価や献立の確認が出来ます。
      </p>
      <h2>まいけんの機能</h2>
      <ul>
        <li type="sqare">食生活の評価の確認</li>
        <li type="sqare">食事へのコメント</li>
        <li type="sqare">食事へのコメントの閲覧</li>
        <li type="sqare">その日の献立の確認</li>
      </ul>
    </div>
  );
};

// MaikenUsage component
const MaikenUsage = () => {
  return (
    <div >
      <h2>まいけんの使い方</h2>
      <ol>
        <li>左上のボタンからサイドバーを開き、他のページに移動。</li>
        <li>カレンダー機能では、選択した日の献立を閲覧することが出来ます。</li>
        <li>自分の評価・レビューでは、料理への評価が出来ます。</li>
        <li>コメント閲覧機能では、タイムライン形式で食事へのコメントが閲覧できます。</li>
      </ol>
    </div>
  );
};

const About = () => {
  return (
    <div>
      <h1>説明・使い方</h1>
      <MaikenIntro />
      <MaikenUsage />
    </div>
  );
};

export default About;
