// 1. 必要なモジュールを読み込む
const express = require("express");
const multer = require("multer");
const path = require("path");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const admin = require("firebase-admin");
const cron = require("node-cron");

// 2. Firebase Admin SDKの初期化
let db;
try {
    // Render等の環境では 'serviceAccountKey.json' はシークレットファイルとして生成される
    const serviceAccount = require("./serviceAccountKey.json");
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
    db = admin.firestore();
    console.log("Firebase Admin SDK initialized successfully.");
} catch (e) {
    console.error("❌ Firebase Admin SDKの初期化に失敗しました。");
    console.error("ヒント: serviceAccountKey.json がルートディレクトリに存在するか、RenderのSecret Files設定を確認してください。");
    console.error("エラー詳細:", e.message);
    process.exit(1); // サーバーを起動せずに終了
}

// 3. Expressアプリの初期化
const app = express();
// ★ Renderなどのクラウド環境では process.env.PORT が自動設定されるため必須
const port = process.env.PORT || 3000;

// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
// ★ 修正: CORS設定
// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
const allowedOrigins = [
    'http://localhost:3001', // Reactのローカル開発サーバー
    'https://jt1tbf88-3001.asse.devtunnels.ms', // トンネルURL
    
    // ★★★ 追加: 指定されたURL ★★★
    'https://maikendeploy.onrender.com', 

    // 環境変数 FRONTEND_URL が設定されていれば追加
    process.env.FRONTEND_URL 
].filter(Boolean); // nullやundefinedを除外

app.use(cors({
    origin: function (origin, callback) {
        // Postmanやcurlなどのサーバー間通信は許可
        if (!origin) return callback(null, true);

        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'このオリジンからのCORSリクエストは許可されていません: ' + origin;
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    }
}));

// ★ セキュリティ向上: リクエストボディのサイズ制限
app.use(express.json({ limit: '10mb' })); 
app.use(express.urlencoded({ extended: true, limit: '10mb' }));


// --- Multer（画像アップロード）のセットアップ ---
const uploadDir = "uploads";
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}
// アップロードされた画像を公開設定
app.use("/uploads", express.static(path.join(__dirname, uploadDir)));

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir + "/"),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const randomName = crypto.randomBytes(16).toString("hex");
        cb(null, randomName + ext);
    },
});

const fileFilter = (req, file, cb) => {
    const allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (allowedMimes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('許可されていないファイルタイプです。 (jpeg, png, gif, webpのみ)'), false);
    }
};

const upload = multer({ 
    storage: storage, 
    fileFilter: fileFilter,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB制限
});


// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
// ★ Firebase認証ミドルウェア
// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
const authMiddleware = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send({ message: '認証トークンが必要です。' });
    }

    const idToken = authHeader.split('Bearer ')[1];
    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        req.user = decodedToken;
        next();
    } catch (error) {
        console.error("IDトークン検証エラー:", error.code);
        res.status(403).send({ message: '認証に失敗しました。トークンが無効か期限切れです。' });
    }
};


// --- APIエンドポイント ---

/**
 * ヘルスチェック
 */
app.get("/health", (req, res) => {
    res.status(200).json({ status: "ok", port: port });
});

// --- 献立 (Meals) GET ---
app.get("/meals", async (req, res) => {
    try {
        const mealsSnapshot = await db.collection("meals").orderBy("createdAt", "desc").get();
        const meals = mealsSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.status(200).json(meals);
    } catch (error) {
        console.error("Meals GET Error:", error);
        res.status(500).send({ message: "献立データの取得失敗" });
    }
});

app.get("/meals/:mealId", async (req, res) => {
    try {
        const { mealId } = req.params;
        const doc = await db.collection("meals").doc(mealId).get();
        if (!doc.exists) return res.status(404).send({ message: "献立が見つかりません。" });
        res.status(200).json({ id: doc.id, ...doc.data() });
    } catch (error) {
        console.error("Meal GET Error:", error);
        res.status(500).send({ message: "取得エラー" });
    }
});

app.get("/meals/:mealId/comments", async (req, res) => {
    try {
        const { mealId } = req.params;
        const snapshot = await db.collection("meals").doc(mealId).collection("comments").orderBy("createdAt", "desc").get();
        const comments = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.status(200).json(comments);
    } catch (error) {
        console.error("Comments GET Error:", error);
        res.status(500).send({ message: "コメント取得エラー" });
    }
});

// --- レビュー (Reviews) ---

app.get("/reviews", async (req, res) => {
    try {
        const snapshot = await db.collection("reviews").orderBy("createdAt", "desc").get();
        const reviews = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.status(200).json(reviews);
    } catch (error) {
        console.error("Reviews GET Error:", error);
        res.status(500).send({ message: "レビュー取得エラー" });
    }
});

app.post("/reviews", authMiddleware, async (req, res) => {
    try {
        const { comment } = req.body;
        const userId = req.user.uid;

        if (!comment) return res.status(400).send({ message: "コメントが不足しています。" });

        const docRef = await db.collection("reviews").add({
            comment,
            userId,
            likeCount: 0,
            likedBy: [],
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        res.status(201).send({ message: "レビュー登録完了", reviewId: docRef.id });
    } catch (error) {
        console.error("Review POST Error:", error);
        res.status(500).send({ message: "レビュー登録エラー" });
    }
});

app.post("/reviews/:reviewId/like", authMiddleware, async (req, res) => {
    const { reviewId } = req.params;
    const userId = req.user.uid;
    const reviewRef = db.collection("reviews").doc(reviewId);

    try {
        await db.runTransaction(async (transaction) => {
            const doc = await transaction.get(reviewRef);
            if (!doc.exists) throw "Review not found";

            const data = doc.data();
            const likedBy = data.likedBy || [];

            if (likedBy.includes(userId)) {
                transaction.update(reviewRef, {
                    likedBy: admin.firestore.FieldValue.arrayRemove(userId),
                    likeCount: admin.firestore.FieldValue.increment(-1)
                });
            } else {
                transaction.update(reviewRef, {
                    likedBy: admin.firestore.FieldValue.arrayUnion(userId),
                    likeCount: admin.firestore.FieldValue.increment(1)
                });
            }
        });
        res.status(200).send({ message: "いいね更新完了" });
    } catch (error) {
        console.error("Review Like Error:", error);
        res.status(500).send({ message: "いいね更新エラー" });
    }
});

// ★ 管理者専用: レビュー削除
app.delete("/reviews/:reviewId", authMiddleware, async (req, res) => {
    const { reviewId } = req.params;
    const userId = req.user.uid;
    const isAdmin = req.user.admin;

    if (!isAdmin) {
        return res.status(403).json({ message: "管理者権限が必要です。" });
    }

    try {
        const reviewRef = db.collection("reviews").doc(reviewId);
        const doc = await reviewRef.get();

        if (!doc.exists) return res.status(404).json({ message: "レビューが見つかりません。" });

        await reviewRef.delete();
        console.log(`管理者(${userId}) がレビュー(${reviewId}) を削除しました。`);
        res.status(200).json({ message: "削除しました。" });
    } catch (error) {
        console.error(`削除エラー:`, error);
        res.status(500).json({ message: "削除処理中にエラーが発生しました。" });
    }
});


// --- 自己評価 (Evaluations) ---
app.post("/evaluations", authMiddleware, async (req, res) => {
    try {
        const { foodAmounts, mealId } = req.body;
        const userId = req.user.uid;

        if (!foodAmounts || !mealId) return res.status(400).send({ message: "必須項目不足" });

        const docRef = await db.collection("evaluations").add({
            foodAmounts,
            userId,
            mealId,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        res.status(201).send({ message: "自己評価登録完了", evaluationId: docRef.id });
    } catch (error) {
        console.error("Evaluation POST Error:", error);
        res.status(500).send({ message: "登録エラー" });
    }
});


// --- 献立 (Meals) POST ---
app.post("/meals", authMiddleware, (req, res, next) => {
    upload.single("image")(req, res, (err) => {
        if (err) return res.status(400).send({ message: "画像アップロードエラー: " + err.message });
        if (!req.file) return res.status(400).send({ message: "画像が選択されていません。" });
        next();
    });
}, async (req, res) => {
    try {
        const mealData = JSON.parse(req.body.mealData);
        const imageUrl = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;
        const userId = req.user.uid;

        const docRef = await db.collection("meals").add({
            ...mealData,
            userId,
            imageUrl,
            likeCount: 0,
            likedBy: [],
            isArchived: false,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        res.status(201).send({ message: "献立登録完了", mealId: docRef.id });
    } catch (error) {
        console.error("Firestore Error:", error);
        res.status(500).send({ message: "保存エラー" });
    }
});

app.post("/meals/:mealId/like", authMiddleware, async (req, res) => {
    const { mealId } = req.params;
    const userId = req.user.uid;
    const mealRef = db.collection("meals").doc(mealId);

    try {
        await db.runTransaction(async (transaction) => {
            const doc = await transaction.get(mealRef);
            if (!doc.exists) throw "Meal not found";

            const data = doc.data();
            const likedBy = data.likedBy || [];

            if (likedBy.includes(userId)) {
                transaction.update(mealRef, {
                    likedBy: admin.firestore.FieldValue.arrayRemove(userId),
                    likeCount: admin.firestore.FieldValue.increment(-1)
                });
            } else {
                transaction.update(mealRef, {
                    likedBy: admin.firestore.FieldValue.arrayUnion(userId),
                    likeCount: admin.firestore.FieldValue.increment(1)
                });
            }
        });
        res.status(200).send({ message: "いいね更新完了" });
    } catch (error) {
        console.error("Like Error:", error);
        res.status(500).send({ message: "いいねエラー" });
    }
});

app.post("/meals/:mealId/comments", authMiddleware, async (req, res) => {
    const { mealId } = req.params;
    const { text } = req.body;
    const userId = req.user.uid;

    if (!text) return res.status(400).send({ message: "コメントが必要です。" });

    try {
        const docRef = await db.collection("meals").doc(mealId).collection("comments").add({
            userId,
            text,
            likeCount: 0,
            likedBy: [],
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        res.status(201).send({ message: "コメント投稿完了", commentId: docRef.id });
    } catch (error) {
        console.error("Comment Error:", error);
        res.status(500).send({ message: "投稿エラー" });
    }
});

app.post("/meals/:mealId/comments/:commentId/like", authMiddleware, async (req, res) => {
    const { mealId, commentId } = req.params;
    const userId = req.user.uid;
    const ref = db.collection("meals").doc(mealId).collection("comments").doc(commentId);

    try {
        await db.runTransaction(async (transaction) => {
            const doc = await transaction.get(ref);
            if (!doc.exists) throw "Comment not found";
            const data = doc.data();
            const likedBy = data.likedBy || [];

            if (likedBy.includes(userId)) {
                transaction.update(ref, {
                    likedBy: admin.firestore.FieldValue.arrayRemove(userId),
                    likeCount: admin.firestore.FieldValue.increment(-1)
                });
            } else {
                transaction.update(ref, {
                    likedBy: admin.firestore.FieldValue.arrayUnion(userId),
                    likeCount: admin.firestore.FieldValue.increment(1)
                });
            }
        });
        res.status(200).send({ message: "いいね更新完了" });
    } catch (error) {
        console.error("Comment Like Error:", error);
        res.status(500).send({ message: "いいねエラー" });
    }
});


// --- 5. アーカイブ処理 (毎日AM3:00) ---
cron.schedule('0 3 * * *', async () => {
    console.log('アーカイブ処理を開始...');
    const archivePeriodDays = 30;
    const now = new Date();
    const archiveDate = new Date(now.setDate(now.getDate() - archivePeriodDays));
    const archiveTimestamp = admin.firestore.Timestamp.fromDate(archiveDate);

    try {
        const snapshot = await db.collection('meals')
            .where('isArchived', '==', false)
            .where('createdAt', '<=', archiveTimestamp)
            .get();

        if (snapshot.empty) {
            console.log('アーカイブ対象なし');
            return;
        }

        const batch = db.batch();
        snapshot.docs.forEach(doc => {
            batch.update(doc.ref, { isArchived: true });
        });
        await batch.commit();
        console.log(`${snapshot.size}件をアーカイブしました。`);
    } catch (error) {
        console.error('アーカイブエラー:', error);
    }
}, { timezone: "Asia/Tokyo" });


// 6. サーバー起動
app.listen(port, () => {
    console.log(`🚀 サーバー起動: http://localhost:${port}`);
    console.log(`許可されたオリジン:`, allowedOrigins);
});