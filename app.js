const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3');
const path = require('path');
const ejs = require('ejs');
const app = express();

app.engine('ejs', ejs.renderFile);
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'secret', resave: true, saveUninitialized: true }));

app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const db = new sqlite3.Database('db/bancocix.sqlite', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
  if (err) {
    console.error(err.message);
  } else {
    console.log('Connected to the database.');
  }
});

app.get('/', (req, res) => {
  res.render('home', { user: req.session.user });
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const username = req.body.username;

  // Insere o novo usuário no banco de dados
  db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], (err) => {
    if (err) {
      console.error(err.message);
      return res.redirect('/register');
    }
    res.redirect('/login');
  });
});

app.get('/login', (req, res) => {
  res.render('login', { errorMessage: '' });
});

app.post('/login', async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Consulta o banco de dados para encontrar o usuário
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err) {
      console.error(err.message);
      return res.redirect('/login');
    }

    if (user && await bcrypt.compare(password, user.password)) {
      req.session.user = user;
      res.redirect('/');
    } else {
      res.render('login', { errorMessage: 'Usuário não encontrado ou senha incorreta.' });
    }
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.render('logout');
  });
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
