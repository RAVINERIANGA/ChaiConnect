const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');

const app = express();
const port = 3000;

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));


const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views/index.html'));
});

// DB connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'DBSB3272',
  database: 'chaiconnect'
});

db.connect(err => {
  if (err) throw err;
  console.log('Connected to MySQL');
});

// Register route
app.post('/register', upload.single('profilePicture'), async (req, res) => {
  const { full_name, id_no, email, phone_no, location, gender, password, confirm_password } = req.body;
  const profilePicture = req.file ? req.file.filename : null;

  if (password !== confirm_password) {
    return res.send('Passwords do not match');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    // Step 1: Insert into `users` table
    const userInsertQuery = `
      INSERT INTO users (name, id_number, email, password, phone, gender, role)
      VALUES (?, ?, ?, ?, ?, ?, 'farmer')
    `;
    const userValues = [full_name, id_no, email, hashedPassword, phone_no, gender];

    db.query(userInsertQuery, userValues, (err, result) => {
      if (err) {
        console.error(err);
        return res.send('Error inserting into users table');
      }

      const userId = result.insertId;

      // Step 2: Insert into `farmer_profile` table
      const profileInsertQuery = `
        INSERT INTO farmer_profile (farmer_id, location, profile_picture)
        VALUES (?, ?, ?)
      `;
      const profileValues = [userId, location, profilePicture];

      db.query(profileInsertQuery, profileValues, (err) => {
        if (err) {
          console.error(err);
          return res.send('Error inserting into farmer_profile table');
        }

        res.send('Registration successful!');
      });
    });

  } catch (error) {
    console.error(error);
    res.send('Something went wrong during registration');
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { identifier, password } = req.body;

  const query = 'SELECT * FROM users WHERE email = ? OR id_number = ?';
  db.query(query, [identifier, identifier], async (err, results) => {
    if (err) {
      console.error(err);
      return res.send('Database error');
    }

    if (results.length === 0) {
      return res.send('User not found');
    }

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.send('Incorrect password');
    }

    // Redirect to dashboard based on role
    switch (user.role) {
      case 'farmer':
        return res.sendFile(path.join(__dirname, 'views/farmer_dashboard.html'));
      case 'admin':
        return res.sendFile(path.join(__dirname, 'views/admin_dashboard.html'));
      case 'extension_officer':
        return res.sendFile(path.join(__dirname, 'views/extension_dashboard.html'));
      case 'factory_staff':
        return res.sendFile(path.join(__dirname, 'views/factory_dashboard.html'));
      default:
        return res.send('Unknown role');
    }
  });
});


// Start server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});