import { initializeApp } from 'firebase/app';
import { getFirestore } from 'firebase/firestore';

// Your web app's Firebase configuration!
const firebaseConfig = {
  apiKey: "AIzaSyChc6zo5ZH5QbGAdj9526jEeakvxaYg8js",
  authDomain: "maiken-2025.firebaseapp.com",
  projectId: "maiken-2025",
  storageBucket: "maiken-2025.firebasestorage.app",
  messagingSenderId: "106897039274",
  appId: "1:106897039274:web:812bd77ce5f3518bc255d3"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const db = getFirestore(app);

export { db };