import express from 'express';
import bodyParser from 'body-parser'; 
import mysql from 'mysql2'; 
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken'; 
import rateLimit from 'express-rate-limit'; 
import dotenv from 'dotenv' 

dotenv.config()

const secret_key = process.env.secret_key;
const app = express();
const port = 3000;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


app.listen(port, () => {
  console.log('Running on port ' + port);
  console.log('Server is running on http://localhost:' + port);
});

// Rate Limiter
const limiter = rateLimit({
  windowMs: 2 * 60 * 1000, // per 2 minutes
  max: 100, //100 reqs
  message: { message: "Too many requests from this IP, please try again later." }
});
app.use(limiter);

const SECRET_KEY = 'your_secret_key_here'; 

// Database Conn
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'asia_db'
});

db.connect(err => {
  if (err) throw err;
  console.log('Connected to MySQL!');
});


// Register
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('Missing username or password');

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = 'INSERT INTO users (username, password) VALUES (?, ?)';
    db.query(sql, [username, hashedPassword], (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).send('Username already taken');
        return res.status(500).send(err);
      }
      res.status(201).send('User registered');
    });
  } catch {
    res.status(500).send('Server error');
  }
});


// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('Missing username or password');

  const sql = 'SELECT * FROM users WHERE username = ?';
  db.query(sql, [username], async (err, results) => {
    if (err) return res.status(500).send(err);
    if (results.length === 0) return res.status(400).send('Invalid credentials');

    const user = results[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).send('Invalid credentials');

    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  });
});


function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).send('Access denied');

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).send('Invalid token');
    req.user = user;
    next();
  });
}


// Retrieve all blog
app.get('/posts', authenticateToken, (req, res) => {
  db.query('SELECT * FROM posts', (err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
});


// Retrieve specific blog
app.get('/posts/:id', authenticateToken, (req, res) => {
  db.query('SELECT * FROM posts WHERE id = ?', [req.params.id], (err, results) => {
    if (err) return res.status(500).send(err);
    if (results.length === 0) return res.status(404).send({ message: 'Post not found' });
    res.json(results[0]);
  });
});


// Create new blog
app.post('/posts', authenticateToken, (req, res) => {
  const { title, content, author } = req.body;
  const sql = 'INSERT INTO posts (title, content, author) VALUES (?, ?, ?)';
  db.query(sql, [title, content, author], (err, result) => {
    if (err) return res.status(500).send(err);
    res.status(201).json({ id: result.insertId, title, content, author });
  });
});


// Update blog
app.put('/posts/:id', authenticateToken, (req, res) => {
  const { title, content, author } = req.body;
  const sql = 'UPDATE posts SET title = ?, content = ?, author = ? WHERE id = ?';
  db.query(sql, [title, content, author, req.params.id], (err) => {
    if (err) return res.status(500).send(err);
    res.json({ id: req.params.id, title, content, author });
  });
});


// Delete blog
app.delete('/posts/:id', authenticateToken, (req, res) => {
  db.query('DELETE FROM posts WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).send(err);
    res.json({ message: 'Post deleted', id: req.params.id });
  });
});




// let posts = [
//     {
//         title: "This is my first blog",
//         content: "Join me as I navigate the ups and downs of learning.",
//         author: "Eri"
//         },
//       {
//         title: "Welcome to my Blog: Part 2",
//         content: "This blog describes my journey balancing freelancing and school, focusing on the difficulties.",
//         author: "Joyce"
//       },
//       {
//         title: "Glad You're Here – Blog Series, Part 3",
//         content: "This is about my desire to own whatever I wanted.",
//         author: "Baybay"
//       },
//       {
//         title: "Hello Again! I'm back.",
//         content: "Highlights from my unforgettable cultural journey through beautiful Japan.",
//         author: "Ekaa"
//       },
//       {
//         title: "Part 5 of My Blog Journey!",
//         content: "Learn to reduce stress and live more in the moment.",
//         author: "Seiji"
//       }
// ]


