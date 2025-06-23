const mysql = require('mysql');
const bcrypt = require('bcrypt');

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'DBSB3272',
  database: 'chaiconnect',
  port:3307
});

db.connect(err => {
  if (err) throw err;
  console.log('Connected');
});

async function addAdmin() {
  const name = 'Brenda Kendi';
  const id_number = 98765432;
  const email = 'bkendi@chaiconnect.com';
  const phone = '0706141418';
  const gender = 'female';
  const password = 'Chaiconnect2025';
  const permissions = 'all';

  const hashedPassword = await bcrypt.hash(password, 10);

  db.query(
    'INSERT INTO users (name, id_number, email, password, phone, gender, role, must_change_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [name, id_number, email, hashedPassword, phone, gender, 'admin', false],
    (err, result) => {
      if (err) throw err;
      const userId = result.insertId;

      db.query(
        'INSERT INTO admins (user_id, permissions) VALUES (?, ?)',
        [userId, permissions],
        (err2) => {
          if (err2) throw err2;
          console.log('Admin added successfully');
          db.end();
        }
      );
    }
  );
}

addAdmin();
