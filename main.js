const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');

const app = express();
const port = 3000;

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: 'chaiconnect-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
 

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const deliveryStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const fs = require('fs');
    const uploadDir = 'uploads/deliveries';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const deliveryUpload = multer({ storage: deliveryStorage });
const upload = multer({ storage });


app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
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

function logActivity(userId, action, details = '') {
  const query = `INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)`;
  db.query(query, [userId, action, details], (err) => {
    if (err) console.error('Failed to log activity:', err);
  });
}

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
      INSERT INTO users (name, id_number, email, password, phone, gender, role, must_change_password)
      VALUES (?, ?, ?, ?, ?, ?, 'farmer', false)
    `;
    const userValues = [full_name, id_no, email, hashedPassword, phone_no, gender];

    db.query(userInsertQuery, userValues, (err, result) => {
      if (err) {
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
      //return res.json({ success: false, message: 'User not found' });
    }

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.send('Incorrect password');
      //return res.json({ success: false, message: 'Incorrect password' });
    }

    // Check if the user is suspended (any role)
    db.query('SELECT * FROM suspended_accounts WHERE user_id = ?', [user.user_id], (suspErr, suspResults) => {
      if (suspErr) {
        console.error('Suspension check error:', suspErr);
        return res.send('Error checking suspension status');
      }

      if (suspResults.length > 0) {
        return res.send('Your account has been suspended. Please contact the admin.');
      }

      // Not suspended → proceed with login
      proceedWithLogin(req, res, user);
    });
  });
});

function proceedWithLogin(req, res, user) {
  logActivity(user.user_id, 'Login', `${user.role} logged in`);

    //store UserID in session
    req.session.userId = user.user_id;
    req.session.role = user.role;
    req.session.name = user.name;

  // ✅ Check if must change password
  if (user.must_change_password) {
    return res.sendFile(path.join(__dirname, 'public/change_password.html'));
  }

  // Redirect to dashboard based on role
  switch (user.role) {
    case 'farmer':
      return res.sendFile(path.join(__dirname, 'public/farmer_dashboard.html'));
    case 'admin':
      return res.sendFile(path.join(__dirname, 'public/admin_dashboard.html'));
    case 'extension_officer':
      return res.sendFile(path.join(__dirname, 'public/extension_officer_dashboard.html'));
    case 'factory_staff':
      return res.sendFile(path.join(__dirname, 'public/factory_staff_dashboard.html'));
    default:
      return res.send('Unknown role');
  }
}
app.get('/manage_users.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/manage_users.html'));
});

// GET all users
app.get('/admin/users', (req, res) => {
  const query = `
    SELECT user_id, name, email, phone, role 
    FROM users 
    WHERE role != 'admin'
  `;
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json(results);
  });
});

//UPDATE user
app.put('/admin/users/:id', (req, res) => {
  const { id } = req.params;
  const { name, email, phone, role } = req.body;

  if (!name || !email || !phone || !role) {
    return res.status(400).json({ success: false, message: 'Missing fields' });
  }

  const query = `
    UPDATE users SET name = ?, email = ?, phone = ?, role = ? WHERE user_id = ?
  `;
  db.query(query, [name, email, phone, role, id], (err, result) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error' });
    if (result.affectedRows === 0)
      return res.status(404).json({ success: false, message: 'User not found' });

    res.json({ success: true });
  });
});

// DELETE user

app.delete('/admin/users/:id', (req, res) => {
  const userId = req.params.id;

  const deleteQueries = [
    { query: 'DELETE FROM activity_logs WHERE user_id = ?', params: [userId] },
    { query: 'DELETE FROM factory_staff WHERE user_id = ?', params: [userId] },
    { query: 'DELETE FROM extension_officers WHERE user_id = ?', params: [userId] },
    { query: 'DELETE FROM admins WHERE user_id = ?', params: [userId] },
    { query: 'DELETE FROM farmer_profile WHERE farmer_id = ?', params: [userId] },
    { query: 'DELETE FROM deliveries WHERE farmer_id = ? OR staff_id = ?', params: [userId, userId] },
    { query: 'DELETE FROM payments WHERE farmer_id = ?', params: [userId] },
    { query: 'DELETE FROM complaints WHERE farmer_id = ?', params: [userId] },
    { query: 'DELETE FROM training_records WHERE officer_id = ?', params: [userId] },
    { query: 'DELETE FROM feedback WHERE farmer_id = ?', params: [userId] },
    { query: 'DELETE FROM policy_documents WHERE uploaded_by = ?', params: [userId] },
    { query: 'DELETE FROM farmer_mismatch_flags WHERE farmer_id = ? OR staff_id = ?', params: [userId, userId] },
    { query: 'DELETE FROM suspended_accounts WHERE user_id = ?', params: [userId] },
    { query: 'DELETE FROM user_alerts_read WHERE user_id = ?', params: [userId] }
  ];

  db.beginTransaction((err) => {
    if (err) {
      console.error('Transaction start failed:', err);
      return res.status(500).json({ success: false, message: 'Transaction start failed' });
    }

    const runQuery = (index = 0) => {
      if (index >= deleteQueries.length) {
        // All related deletes done, now delete user
        return db.query('DELETE FROM users WHERE user_id = ?', [userId], (err, result) => {
          if (err) {
            return db.rollback(() => {
              console.error('Final delete failed:', err);
              res.status(500).json({ success: false, message: 'User delete failed' });
            });
          }

          db.commit((err) => {
            if (err) {
              return db.rollback(() => {
                console.error('Commit failed:', err);
                res.status(500).json({ success: false, message: 'Transaction commit failed' });
              });
            }

            return res.json({ success: true, message: 'User deleted successfully' });
          });
        });
      }

      const { query, params } = deleteQueries[index];
      db.query(query, params, (err) => {
        if (err) {
          return db.rollback(() => {
            console.error(`Error on ${query}:`, err);
            res.status(500).json({ success: false, message: 'Related deletion failed' });
          });
        }

        runQuery(index + 1);
      });
    };

    runQuery(); // Start sequential deletion
  });
});

//Assign role page
app.post('/admin/assign-role', (req, res) => {
  const { name, id_number, email, phone, gender, role, position, region, specialization } = req.body;

  if (!name || !id_number || !email || !phone || !gender || !role) {
    return res.status(400).json({ success: false, message: 'All fields required' });
  }

  const tempPassword = crypto.randomBytes(4).toString('hex');
  bcrypt.hash(tempPassword, 10, (err, hashedPassword) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: 'Error hashing password' });
    }

    const userQuery = `
      INSERT INTO users (name, id_number, email, password, phone, gender, role, must_change_password)
      VALUES (?, ?, ?, ?, ?, ?, ?, true)
    `;
    db.query(userQuery, [name, id_number, email, hashedPassword, phone, gender, role], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: 'Database error inserting user' });
      }

      const userId = result.insertId;

      if (role === 'factory_staff') {
        db.query('INSERT INTO factory_staff (user_id, position) VALUES (?, ?)', [userId, position || ''], (err2) => {
          if (err2) {
            console.error(err2);
            return res.status(500).json({ success: false, message: 'Error inserting factory staff' });
          }
          res.json({ success: true, tempPassword });
        });
      } else if (role === 'extension_officer') {
        db.query('INSERT INTO extension_officers (user_id, region, specialization) VALUES (?, ?, ?)', [userId, region || '', specialization || ''], (err3) => {
          if (err3) {
            console.error(err3);
            return res.status(500).json({ success: false, message: 'Error inserting extension officer' });
          }
          res.json({ success: true, tempPassword });
        });
      } else {
        res.status(400).json({ success: false, message: 'Invalid role' });
      }
    });
  });
});

//change password
app.post('/change-password', (req, res) => {
  const userId = req.session.userId;
  const { newPassword } = req.body;

  if (!userId) {
    return res.status(401).json({ success: false, message: 'Not logged in' });
  }

  bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: 'Error hashing password' });
    }

    db.query(
      'UPDATE users SET password = ?, must_change_password = false WHERE user_id = ?',
      [hashedPassword, userId],
      (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ success: false, message: 'Database error' });
        }
        //Redirect to the correct dashboard
        const role = req.session.role;
        let dashboardPath = '';

        switch (role) {
          case 'farmer':
            dashboardPath = '/farmer_dashboard.html';
            break;
          case 'admin':
            dashboardPath = '/admin_dashboard.html';
            break;
          case 'extension_officer':
            dashboardPath = '/extension_officer_dashboard.html';
            break;
          case 'factory_staff':
            dashboardPath = '/factory_staff_dashboard.html';
            break;
          default:
            dashboardPath = '/';
        }


        res.json({ success: true, redirectTo: dashboardPath });
      }
    );
  });
});

// Dashboard stats API route
app.get('/api/dashboard-stats', (req, res) => {
  const stats = {
    totalFarmers: 0,
    totalFactoryStaff: 0,
    totalExtensionOfficers: 0,
    teaDeliveredToday: 0,
    teaDeliveredThisMonth: 0,
    teaDeliveredOverall: 0
  };

  const farmerQuery = `SELECT COUNT(*) AS count FROM users WHERE role = 'farmer'`;
  const staffQuery = `SELECT COUNT(*) AS count FROM users WHERE role = 'factory_staff'`;
  const officerQuery = `SELECT COUNT(*) AS count FROM users WHERE role = 'extension_officer'`;
  const teaQuery = `SELECT IFNULL(SUM(quantity_kg), 0) AS total FROM deliveries WHERE delivery_date = CURDATE()`;
  const teaMonthQuery = `SELECT IFNULL(SUM(quantity_kg), 0) AS total FROM deliveries WHERE MONTH(delivery_date) = MONTH(CURDATE()) AND YEAR(delivery_date) = YEAR(CURDATE())`;
  const teaOverallQuery = `SELECT IFNULL(SUM(quantity_kg), 0) AS total FROM deliveries`;

  db.query(farmerQuery, (err, farmerResult) => {
    if (err) return res.status(500).json({ error: 'DB error (farmers)' });

    stats.totalFarmers = farmerResult[0].count;

    db.query(staffQuery, (err2, staffResult) => {
      if (err2) return res.status(500).json({ error: 'DB error (staff)' });

      stats.totalFactoryStaff = staffResult[0].count;

      db.query(officerQuery, (err3, officerResult) => {
        if (err3) return res.status(500).json({ error: 'DB error (officers)' });

        stats.totalExtensionOfficers = officerResult[0].count;

        db.query(teaQuery, (err4, teaResult) => {
          if (err4) return res.status(500).json({ error: 'DB error (tea)' });

          stats.teaDeliveredToday = teaResult[0].total;
          db.query(teaMonthQuery, (err5, teaMonthResult) => {
            if (err5) return res.status(500).json({ error: 'DB error (tea month)' });

            stats.teaDeliveredThisMonth = teaMonthResult[0].total;

            db.query(teaOverallQuery, (err6, teaOverallResult) => {
              if (err6) return res.status(500).json({ error: 'DB error (tea overall)' });

              stats.teaDeliveredOverall = teaOverallResult[0].total;

          res.json(stats);
            });
          });
        });
      });
    });
  });
});

//Read Admin name
app.get('/api/me', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  res.json({
    name: req.session.name,
    role: req.session.role,
  });
});

// Set payment rate - Admin
// Save new rate
app.post('/admin/payment-rate', (req, res) => {
  const { quality_grade, price_per_kg } = req.body;
  const query = `
    INSERT INTO payment_rates (quality_grade, price_per_kg)
    VALUES (?, ?)
  `;
  db.query(query, [quality_grade, price_per_kg], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false });
    }
    res.json({ success: true });
  });
});

// Fetch current rates
app.get('/admin/payment-rates', (req, res) => {
  const query = `
    SELECT quality_grade, price_per_kg, effective_date
    FROM payment_rates
    ORDER BY effective_date DESC
  `;
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false });
    }
    res.json(results);
  });
});

// Update complaint status
app.put('/admin/complaints/:id', (req, res) => {
  const complaintId = req.params.id;
  const { status } = req.body;

  const allowed = ['open', 'in_progress', 'resolved'];
  if (!allowed.includes(status)) {
    return res.status(400).json({ success: false, message: 'Invalid status' });
  }

  db.query(
    'UPDATE complaints SET status = ? WHERE complaint_id = ?',
    [status, complaintId],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false });
      }
      res.json({ success: true });
    }
  );
});

// Analytics data

app.get('/admin/analytics', (req, res) => {
  const todayQuery = `
    SELECT quality_grade, IFNULL(SUM(quantity_kg), 0) AS total
    FROM deliveries
    WHERE delivery_date = CURDATE()
    GROUP BY quality_grade
  `;

  const weekQuery = `
    SELECT delivery_date, IFNULL(SUM(quantity_kg), 0) AS total
    FROM deliveries
    WHERE delivery_date >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
    GROUP BY delivery_date
    ORDER BY delivery_date
  `;

  const feedbackQuery = `
    SELECT u.name AS officer, AVG(f.rating) AS avg_rating
    FROM feedback f
    JOIN training_records t ON f.training_id = t.training_id
    JOIN users u ON t.officer_id = u.user_id
    GROUP BY officer
  `;

  const statusCountQuery = `
    SELECT status, COUNT(*) AS count
    FROM deliveries
    GROUP BY status
  `;

  const topFarmersQuery = `
    SELECT u.name, SUM(d.quantity_kg) AS total
    FROM deliveries d
    JOIN users u ON d.farmer_id = u.user_id
    GROUP BY d.farmer_id
    ORDER BY total DESC
    LIMIT 5
  `;

  db.query(todayQuery, (err, todayRows) => {
    if (err) return res.status(500).json({ error: err });

    db.query(weekQuery, (err2, weekRows) => {
      if (err2) return res.status(500).json({ error: err2 });

      db.query(feedbackQuery, (err3, feedbackRows) => {
        if (err3) return res.status(500).json({ error: err3 });

        db.query(statusCountQuery, (err4, statusRows) => {
          if (err4) return res.status(500).json({ error: err4 });

          db.query(topFarmersQuery, (err5, topFarmersRows) => {
            if (err5) return res.status(500).json({ error: err5 });

            // Format the output
            const todayByGrade = ['A', 'B', 'C'].map(grade => {
              const row = todayRows.find(r => r.quality_grade === grade);
              return row ? parseFloat(row.total) : 0;
            });

            const weekDates = weekRows.map(r => r.delivery_date.toISOString().slice(5)); // MM-DD
            const weekDeliveryAmounts = weekRows.map(r => parseFloat(r.total));

            const officerNames = feedbackRows.map(r => r.officer);
            const officerAvgRatings = feedbackRows.map(r => parseFloat(r.avg_rating).toFixed(2));

            const deliveryStatusCounts = ['pending', 'graded', 'completed'].map(status => {
              const row = statusRows.find(r => r.status === status);
              return row ? parseInt(row.count) : 0;
            });

            const topFarmers = topFarmersRows.map(row => ({
              name: row.name,
              total: parseFloat(row.total)
            }));

            res.json({
              todayByGrade,
              weekDates,
              weekDeliveryAmounts,
              officerNames,
              officerAvgRatings,
              deliveryStatusCounts,
              topFarmers
            });
          });
        });
      });
    });
  });
});

//Deliveries route - Factory Staff
app.post('/factory/deliveries', upload.single('photo'), (req, res) => {
  const { id_number, quantity_kg, quality_grade, status } = req.body;
  const staff_id = req.session.userId;
  const photoFile = req.file;

  const validStatuses = ['pending', 'graded', 'completed'];
  if (!id_number || !quantity_kg || !quality_grade || !status || !staff_id) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  if (!validStatuses.includes(status)) {
    return res.status(400).json({ success: false, message: 'Invalid status value' });
  }

  const findFarmer = 'SELECT user_id FROM users WHERE id_number = ? AND role = "farmer"';

  db.query(findFarmer, [id_number], (err, results) => {
    if (err) {
      console.error('Error finding farmer:', err);
      return res.status(500).json({ success: false, message: 'Server error during farmer lookup' });
    }

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Farmer not found' });
    }

    const farmer_id = results[0].user_id;
    const photo_url = photoFile ? `/uploads/deliveries/${photoFile.filename}` : null;

    const insertDelivery = `
      INSERT INTO deliveries (farmer_id, staff_id, quantity_kg, quality_grade, delivery_date, photo_url, status)
      VALUES (?, ?, ?, ?, CURDATE(), ?, ?)
    `;

    db.query(
      insertDelivery,
      [farmer_id, staff_id, quantity_kg, quality_grade, photo_url, status],
      (err2) => {
        if (err2) {
          console.error('Error inserting delivery:', err2);
          return res.status(500).json({ success: false, message: 'Failed to record delivery' });
        }

        res.json({ success: true, message: 'Delivery recorded successfully!' });
      }
    );
  });
});

//Update deliveries - Factory Staff
//In various steps
//View all deliveries
app.get('/factory/deliveries/all', (req, res) => {
  const sql = `
    SELECT 
      d.delivery_id,
      f.name AS farmer_name,
      f.id_number,
      s.name AS staff_name,
      d.delivery_date,
      d.quantity_kg,
      d.quality_grade,
      d.status
    FROM deliveries d
    JOIN users f ON d.farmer_id = f.user_id
    JOIN users s ON d.staff_id = s.user_id
    ORDER BY d.delivery_date DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error('Error fetching deliveries:', err);
      return res.status(500).json({ success: false, message: 'Server error' });
    }

    // Format date
    results.forEach(delivery => {
      delivery.delivery_date = new Date(delivery.delivery_date).toISOString().slice(0, 10);
    });


    res.json({
      success: true,
      deliveries: results
    });
  });
});

// GET deliveries by farmer ID number
app.get('/factory/deliveries/by-id-number/:id_number', (req, res) => {
  const { id_number } = req.params;

  const sql = `
    SELECT 
      d.delivery_id,
      f.name AS farmer_name,
      f.id_number,
      s.name AS staff_name,
      d.delivery_date,
      d.quantity_kg,
      d.quality_grade,
      d.status
    FROM deliveries d
    JOIN users f ON d.farmer_id = f.user_id
    JOIN users s ON d.staff_id = s.user_id
    WHERE f.id_number = ?
    ORDER BY d.delivery_date DESC
  `;

  db.query(sql, [id_number], (err, results) => {
    if (err) {
      console.error('Error fetching delivery by ID number:', err);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
    // Format date
    results.forEach(delivery => {
      delivery.delivery_date = new Date(delivery.delivery_date).toISOString().slice(0, 10);
    });


    res.json({
      success: true,
      deliveries: results
    });
  });
});
//editing
app.get('/factory/deliveries/:id', (req, res) => {
  const deliveryId = req.params.id;
  const sql = `
    SELECT 
      d.delivery_id,
      f.name AS farmer_name,
      f.id_number,
      s.name AS staff_name,
      d.delivery_date,
      d.quantity_kg,
      d.quality_grade,
      d.status
    FROM deliveries d
    JOIN users f ON d.farmer_id = f.user_id
    JOIN users s ON d.staff_id = s.user_id
    WHERE d.delivery_id = ?
  `;

  db.query(sql, [deliveryId], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Server error' });
    if (results.length === 0) return res.status(404).json({ success: false, message: 'Delivery not found' });

    res.json({ success: true, delivery: results[0] });
  });
});
//updating for editing
app.put('/factory/deliveries/:id', (req, res) => {
  const deliveryId = req.params.id;
  const { quantity_kg, quality_grade, status } = req.body;

  const validStatuses = ['pending', 'graded', 'completed'];
  if (!quantity_kg || !quality_grade || !status || !validStatuses.includes(status)) {
    return res.status(400).json({ success: false, message: 'Invalid input' });
  }

  const sql = `
    UPDATE deliveries
    SET quantity_kg = ?, quality_grade = ?, status = ?
    WHERE delivery_id = ?
  `;

  db.query(sql, [quantity_kg, quality_grade, status, deliveryId], (err, result) => {
    if (err) return res.status(500).json({ success: false, message: 'Update failed' });
    if (result.affectedRows === 0) return res.status(404).json({ success: false, message: 'Delivery not found' });

    res.json({ success: true, message: 'Delivery updated successfully!' });
  });
});

// GET all farmers - for validate farmers for Factory Staff
app.get('/factory/farmers/all', (req, res) => {
  const sql = `
    SELECT 
      u.user_id, u.name, u.id_number, u.phone, u.email, u.created_at,
      fp.location, fp.profile_picture
    FROM users u
    LEFT JOIN farmer_profile fp ON u.user_id = fp.farmer_id
    WHERE u.role = 'farmer'
    ORDER BY u.created_at DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error('Error fetching farmers:', err);
      return res.status(500).json({ success: false, message: 'Server error' });
    }

    results.forEach(farmer => {
      farmer.created_at = new Date(farmer.created_at).toISOString().slice(0, 10);
    });

    res.json({ success: true, farmers: results });
  });
});

//Flag mismatch - Validating farmers by FS(Factory Staff)
app.post('/factory/farmers/flag-mismatch', (req, res) => {
  const { user_id, reason } = req.body;
  const staff_id = req.session.userId;

  if (!staff_id || !user_id || !reason) {
    return res.status(400).json({ success: false, message: 'Missing info' });
  }

  const sql = `
    INSERT INTO farmer_mismatch_flags (farmer_id, staff_id, reason)
    VALUES (?, ?, ?)
  `;
  db.query(sql, [user_id, staff_id, reason], (err) => {
    if (err) {
      console.error('Error logging mismatch:', err);
      return res.status(500).json({ success: false });
    }
    res.json({ success: true });
  });
});

// Admin: View all mismatch reports
app.get('/admin/farmer-mismatches', (req, res) => {
  const sql = `
    SELECT 
      fmf.flag_id,
      farmers.user_id,
      farmers.name AS name,
      farmers.id_number,
      fp.profile_picture,
      staff.name AS flagged_by,
      fmf.reason,
      fmf.flagged_at
    FROM farmer_mismatch_flags fmf
    JOIN users farmers ON fmf.farmer_id = farmers.user_id
    LEFT JOIN farmer_profile fp ON farmers.user_id = fp.farmer_id
    JOIN users staff ON fmf.staff_id = staff.user_id
    ORDER BY fmf.flagged_at DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error('Error fetching mismatches:', err);
      return res.status(500).json({ success: false });
    }
    res.json({ success: true, mismatches: results });
  });
});

//Admin Route to Suspend a Farmer and remove mismatch flag
app.post('/admin/suspend/:userId', (req, res) => {
  const userId = req.params.userId;
  const adminId = req.session.userId;
  const { reason } = req.body;

  if (!adminId || req.session.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }
  const dbConn = db;
  dbConn.beginTransaction(err => {
    if (err) {
      console.error('Transaction error:', err);
      return res.status(500).json({ success: false, message: 'Transaction start failed' });
    }
    // Step 1: Insert into suspended_accounts
    const insertSuspension = `
      INSERT INTO suspended_accounts (user_id, suspended_by, reason)
      VALUES (?, ?, ?)
      ON DUPLICATE KEY UPDATE reason = VALUES(reason), suspended_at = CURRENT_TIMESTAMP
    `;

    dbConn.query(insertSuspension, [userId, adminId, reason || 'No reason provided'], (suspendErr) => {
      if (suspendErr) {
        return dbConn.rollback(() => {
          console.error('Suspension error:', suspendErr);
          res.status(500).json({ success: false, message: 'Failed to suspend user' });
        });
      }
      // Step 2: Delete from mismatch flags
      const deleteMismatch = `DELETE FROM farmer_mismatch_flags WHERE farmer_id = ?`;

      dbConn.query(deleteMismatch, [userId], (deleteErr) => {
        if (deleteErr) {
          return dbConn.rollback(() => {
            console.error('Delete mismatch error:', deleteErr);
            res.status(500).json({ success: false, message: 'Failed to remove mismatch flag' });
          });
        }

        // Step 3: Commit transaction
        dbConn.commit(commitErr => {
          if (commitErr) {
            return dbConn.rollback(() => {
              console.error('Commit error:', commitErr);
              res.status(500).json({ success: false, message: 'Failed to complete suspension' });
            });
          }

          res.json({ success: true, message: 'User suspended and removed from mismatches' });
        });
      });
    });
  });
});
//Admin Route to Unsuspend
app.delete('/admin/unsuspend/:userId', (req, res) => {
  const userId = req.params.userId;

  if (!req.session.userId || req.session.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  db.query('DELETE FROM suspended_accounts WHERE user_id = ?', [userId], (err) => {
    if (err) {
      console.error('Unsuspension error:', err);
      return res.status(500).json({ success: false });
    }
    res.json({ success: true, message: 'User unsuspended' });
  });
});

//List all suspended accounts for Admin
app.get('/admin/suspended-users', (req, res) => {
  if (req.session.role !== 'admin') return res.status(403).json({ success: false });

  const query = `
    SELECT 
      u.user_id, u.name, u.email, u.id_number, u.role,
      s.reason, s.suspended_at
    FROM suspended_accounts s
    JOIN users u ON s.user_id = u.user_id
    ORDER BY s.suspended_at DESC
  `;

  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ success: false });
    res.json({ success: true, users: results });
  });
});

//unflag user - Admin
app.delete('/admin/unflag/:userId', (req, res) => {
  const { userId } = req.params;

  if (!req.session.userId || req.session.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  const deleteQuery = `DELETE FROM farmer_mismatch_flags WHERE farmer_id = ?`;

  db.query(deleteQuery, [userId], (err, result) => {
    if (err) {
      console.error('Unflag error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'No flag found for this user' });
    }

    res.json({ success: true, message: 'Farmer unflagged successfully' });
  });
});

// Factory Staff: View grading summary
app.get('/factory/grading-summary', (req, res) => {
  if (!req.session.userId || req.session.role !== 'factory_staff') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  const sql = `
    SELECT quality_grade, COUNT(*) AS total_deliveries, SUM(quantity_kg) AS total_weight
    FROM deliveries
    GROUP BY quality_grade
    ORDER BY quality_grade
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error('Grading summary error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, summary: results });
  });
});

//Delivery patterns
app.get('/factory/delivery-patterns', (req, res) => {
  const sql = `
    SELECT 
      DATE(delivery_date) AS day,
      COUNT(*) AS total_deliveries,
      SUM(quantity_kg) AS total_kg
    FROM deliveries
    WHERE status IN ('graded', 'completed')
    GROUP BY day
    ORDER BY day DESC
    LIMIT 7
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error('Error fetching delivery patterns:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, data: results });
  });
});

//Admin - create an alert
app.post('/admin/create-alert', (req, res) => {
  const { title, message, role } = req.body;
  const query = `INSERT INTO system_alerts (title, message, role) VALUES (?, ?, ?)`;
  db.query(query, [title, message, role], (err) => {
    if (err) {
      console.error('Alert creation error:', err);
      return res.status(500).json({ success: false, message: 'Failed to create alert.' });
    }
    res.json({ success: true, message: 'Alert created successfully!' });
  });
});

//User fetches alerts
app.get('/alerts', (req, res) => {
  const role = req.session.role;
  const user_id = req.session.userId;

  if (!role || !user_id) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }
  const query = `
    SELECT sa.*, ur.alert_id AS read_by_user
    FROM system_alerts sa
    LEFT JOIN user_alerts_read ur ON sa.alert_id = ur.alert_id AND ur.user_id = ?
    WHERE sa.role = ? OR sa.role = 'all'
    ORDER BY sa.created_at DESC
  `;
  db.query(query, [user_id, role], (err, results) => {
    if (err) {
      console.error('Alert fetch error:', err);
      return res.status(500).json({ success: false });
    }
    res.json({ success: true, alerts: results });
  });
});


//Mark Alerts As Read Route
app.post('/alerts/mark-read', (req, res) => {
  const user_id = req.session.userId; 
  const alert_id = req.body.alert_id;

  if (!user_id || !alert_id) {
    return res.status(400).json({ success: false, message: 'Missing user ID or alert ID' });
  }

  const query = `
    INSERT IGNORE INTO user_alerts_read (user_id, alert_id)
    VALUES (?, ?)
  `;
  
  db.query(query, [user_id, alert_id], (err) => {
    if (err) {
      console.error('Error marking alert as read:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, message: 'Alert marked as read' });
  });
});

//Alerts Count route
app.get('/alerts/count', (req, res) => {
  const role = req.session.role;
  const user_id = req.session.userId; 
  
  if (!role || !user_id) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }

  const query = `
    SELECT COUNT(*) AS count
    FROM system_alerts sa
    LEFT JOIN user_alerts_read ur ON sa.alert_id = ur.alert_id AND ur.user_id = ?
    WHERE (sa.role = ? OR sa.role = 'all') AND ur.alert_id IS NULL
  `;
  
  db.query(query, [user_id, role], (err, results) => {
    if (err) {
      console.error('Alert count error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, count: results[0].count });
  });
});

//Alerts count
app.get('/alerts/count', (req, res) => {
  const role = req.session.role;
  if (!role) return res.status(401).json({ success: false });

  const query = `
    SELECT COUNT(*) AS count
    FROM system_alerts
    WHERE role = ? OR role = 'all'
  `;
  db.query(query, [role], (err, results) => {
    if (err) {
      console.error('Alert count error:', err);
      return res.status(500).json({ success: false });
    }
    res.json({ success: true, count: results[0].count });
  });
});


//Logout
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ success: false });
    }
    res.clearCookie('connect.sid'); // Clear session cookie
    res.json({ success: true });
  });
});

//Farmer Payment Summary 
app.get('/farmer/paymentsummary', (req, res) => {
  const farmerId = req.session.userId;

  if (!farmerId || req.session.role !== 'farmer') {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  const query = `
    SELECT p.amount, p.payment_date, d.quantity_kg, d.quality_grade, 
           p.payment_method, p.status
    FROM payments p
    LEFT JOIN deliveries d ON p.delivery_id = d.delivery_id
    WHERE p.farmer_id = ?
    ORDER BY p.payment_date DESC
  `;

  db.query(query, [farmerId], (err, results) => {
    if (err) {
      console.error('Payment summary query failed:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    const totalEarnings = results.reduce((sum, row) => sum + parseFloat(row.amount || 0), 0);
    const lastPayment = results[0] || {};
    const lastPaymentAmount = lastPayment.amount || 0;
    const lastPaymentDate = lastPayment.payment_date || null;
    const quantity = lastPayment.quantity_kg || 1;
    const currentRate = lastPaymentAmount && quantity ? (lastPaymentAmount / quantity).toFixed(2) : 0;

    res.json({
      success: true,
      summary: {
        totalEarnings: totalEarnings.toFixed(2),
        lastPaymentAmount,
        lastPaymentDate,
        currentRate
      },
      payments: results
    });
  });
});

//Issue Payment Route - Admin 
// Issue Payment Route - Admin (for mysql)
app.post('/admin/issue-payment', (req, res) => {
  const { farmer_id, delivery_id, amount, payment_method } = req.body;

  if (!farmer_id || !delivery_id || !amount || !payment_method) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  // Step 1: Check if payment already exists
  const checkQuery = `SELECT * FROM payments WHERE delivery_id = ? AND status = 'completed'`;
  db.query(checkQuery, [delivery_id], (err, results) => {
    if (err) {
      console.error('Error checking existing payment:', err);
      return res.status(500).json({ success: false, message: 'Server error' });
    }

    if (results.length > 0) {
      return res.status(409).json({ success: false, message: 'Payment already completed for this delivery' });
    }

    // Step 2: Insert new payment
    const insertQuery = `
      INSERT INTO payments (farmer_id, delivery_id, amount, payment_date, payment_method, status)
      VALUES (?, ?, ?, CURDATE(), ?, 'completed')
    `;
    db.query(insertQuery, [farmer_id, delivery_id, amount, payment_method], (err2, result) => {
      if (err2) {
        console.error('Error inserting payment:', err2);
        return res.status(500).json({ success: false, message: 'Server error' });
      }

      // Step 3: Optionally update delivery status
      const updateQuery = `UPDATE deliveries SET status = 'completed' WHERE delivery_id = ?`;
      db.query(updateQuery, [delivery_id], (err3) => {
        if (err3) {
          console.error('Error updating delivery status:', err3);
          return res.status(500).json({ success: false, message: 'Server error after payment' });
        }

        res.json({ success: true, payment_id: result.insertId });
      });
    });
  });
});

//Default deliveries before they are issued. 
app.get('/admin/unpaid-deliveries', (req, res) => {
  const sql = `
    SELECT d.delivery_id, d.farmer_id, d.quantity_kg, d.delivery_date, d.quality_grade,
           u.name AS farmer_name, pr.price_per_kg
    FROM deliveries d
    JOIN users u ON d.farmer_id = u.user_id
    JOIN payment_rates pr ON d.quality_grade = pr.quality_grade
    LEFT JOIN payments p ON d.delivery_id = p.delivery_id AND p.status = 'completed'
    WHERE d.status = 'completed' AND p.payment_id IS NULL
    ORDER BY d.delivery_date DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error('Error fetching unpaid deliveries:', err);
      return res.status(500).json({ message: 'Server error' });
    }

    res.json(results);
  });
});

//upload policy documents - admin
app.post('/admin/upload-policy', upload.single('policyFile'), (req, res) => {
  const { title, description} = req.body;
  const file = req.file;
  const uploaded_by = req.session.userId;

  if (!title || !file || !uploaded_by) {
    return res.status(400).send('Missing required fields');
  }

  const filePath = `/uploads/policies/${file.filename}`;
  const insertQuery = `
    INSERT INTO policy_documents (title, description, file_path, uploaded_by)
    VALUES (?, ?, ?, ?)
  `;

  db.query(insertQuery, [title, description || '', filePath, uploaded_by], (err) => {
    if (err) {
      console.error('DB error:', err);
      return res.status(500).send('Database error');
    }

    return res.status(200).json({ success: true, message: 'Policy uploaded successfully' });
  });
});

//View policies 
app.get('/policies', (req, res) => {
  const query = `
    SELECT title, description, file_path, uploaded_at
    FROM policy_documents
    ORDER BY uploaded_at DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching policies:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(results);
  });
});

// Finance Report: total payments per farmer
app.get('/admin/report/finance', (req, res) => {
  const query = `
    SELECT u.name AS farmer_name, SUM(p.amount) AS total_earned, COUNT(p.payment_id) AS total_payments
    FROM payments p
    JOIN users u ON p.farmer_id = u.user_id
    GROUP BY p.farmer_id
    ORDER BY total_earned DESC
  `;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(results);
  });
});

// Training Report: training sessions and officer names
app.get('/admin/report/training', (req, res) => {
  const query = `
    SELECT tr.training_topic, tr.training_date, u.name AS officer_name, tr.summary
    FROM training_records tr
    JOIN users u ON tr.officer_id = u.user_id
    ORDER BY tr.training_date DESC
  `;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(results);
  });
});

// Productivity Report: quantity delivered per farmer
app.get('/admin/report/productivity', (req, res) => {
  const query = `
    SELECT u.name AS farmer_name, COUNT(d.delivery_id) AS deliveries, 
           SUM(d.quantity_kg) AS total_kg, 
           ROUND(SUM(d.quantity_kg)/COUNT(d.delivery_id), 2) AS avg_kg
    FROM deliveries d
    JOIN users u ON d.farmer_id = u.user_id
    GROUP BY d.farmer_id
    ORDER BY total_kg DESC
  `;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(results);
  });
});

// GET user profile
app.get('/my-profile', (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.status(401).json({ error: 'Not logged in' });

  const query = 'SELECT user_id, name, email, phone, gender, id_number, role FROM users WHERE user_id = ?';
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching profile:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(results[0]);
  });
});

// POST to update user profile
app.post('/my-profile/update', (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.status(401).json({ error: 'Not logged in' });

  const { name, email, phone } = req.body;
  if (!name || !email || !phone) return res.status(400).json({ error: 'Missing fields' });

  const query = 'UPDATE users SET name = ?, email = ?, phone = ? WHERE user_id = ?';
  db.query(query, [name, email, phone, userId], (err) => {
    if (err) {
      console.error('Error updating profile:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ success: true });
  });
});

// POST to change password
app.post('/my-profile/change-password', async (req, res) => {
  const userId = req.session.userId;
  const { currentPassword, newPassword } = req.body;

  if (!userId || !currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  db.query('SELECT password FROM users WHERE user_id = ?', [userId], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length === 0) return res.status(404).json({ error: 'User not found' });

    const match = await bcrypt.compare(currentPassword, results[0].password);
    if (!match) return res.status(401).json({ error: 'Incorrect current password' });

    const hashed = await bcrypt.hash(newPassword, 10);
    db.query('UPDATE users SET password = ?, must_change_password = FALSE WHERE user_id = ?', [hashed, userId], (err) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true });
    });
  });
});

// GET /payments - View all completed payments with optional filters/search
app.get('/admin/payments', (req, res) => {
  const { search, paymentMethod, startDate, endDate, region } = req.query;

  let baseQuery = `
    SELECT 
      p.payment_id,
      p.amount,
      p.payment_date,
      p.payment_method,
      u.name AS farmer_name,
      u.id_number,
      fp.location AS farmer_region
    FROM payments p
    JOIN users u ON p.farmer_id = u.user_id
    LEFT JOIN farmer_profile fp ON u.user_id = fp.farmer_id
    WHERE p.status = 'completed'
  `;

  const params = [];

  if (search) {
    baseQuery += ` AND (u.name LIKE ? OR u.id_number LIKE ?)`;
    params.push(`%${search}%`, `%${search}%`);
  }

  if (paymentMethod) {
    baseQuery += ` AND p.payment_method = ?`;
    params.push(paymentMethod);
  }

  if (startDate) {
    baseQuery += ` AND p.payment_date >= ?`;
    params.push(startDate);
  }

  if (endDate) {
    baseQuery += ` AND p.payment_date <= ?`;
    params.push(endDate);
  }

  if (region) {
    baseQuery += ` AND fp.location LIKE ?`;
    params.push(`%${region}%`);
  }

  baseQuery += ' ORDER BY p.payment_date DESC';

  db.query(baseQuery, params, (err, results) => {
    if (err) {
      console.error('Error fetching payments:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(results);
  });
});

//System Logs - Admin side
app.get('/admin/system-logs', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;

  const search = req.query.search || '';
  const role = req.query.role || '';
  const action = req.query.action || '';

  let countQuery = `SELECT COUNT(*) as total FROM activity_logs al LEFT JOIN users u ON al.user_id = u.user_id WHERE 1=1`;
  let dataQuery = `
    SELECT al.*, u.name AS user, u.role
    FROM activity_logs al
    LEFT JOIN users u ON al.user_id = u.user_id
    WHERE 1=1
  `;

  const filters = [];
  if (search) {
    countQuery += ` AND u.name LIKE ?`;
    dataQuery += ` AND u.name LIKE ?`;
    filters.push(`%${search}%`);
  }
  if (role) {
    countQuery += ` AND u.role = ?`;
    dataQuery += ` AND u.role = ?`;
    filters.push(role);
  }
  if (action) {
    countQuery += ` AND al.action = ?`;
    dataQuery += ` AND al.action = ?`;
    filters.push(action);
  }

  dataQuery += ` ORDER BY al.created_at DESC LIMIT ? OFFSET ?`;
  const dataFilters = [...filters, limit, offset];

  db.query(countQuery, filters, (err, countResult) => {
    if (err) {
      console.error('Error counting logs:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    const total = countResult[0].total;
    const totalPages = Math.ceil(total / limit);

    db.query(dataQuery, dataFilters, (err, logResults) => {
      if (err) {
        console.error('Error fetching logs:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }

      const actionQuery = `SELECT DISTINCT action FROM activity_logs ORDER BY action ASC`;
      db.query(actionQuery, (err, actionResults) => {
        const allActions = actionResults.map(a => a.action);
        res.json({
          page,
          totalPages,
          logs: logResults,
          allActions
        });
      });
    });
  });
});






















// Start server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});