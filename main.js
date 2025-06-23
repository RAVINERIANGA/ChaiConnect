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
  db.query('SELECT user_id, name, email, phone, role FROM users', (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json(results);
  });
});

//UPDATE user
app.put('/admin/users/:id', (req, res) => {
  const userId = req.params.id;
  const { name, email, phone, role } = req.body;


  if (!name || !email || !phone || !role) {
    return res.status(400).json({ success: false, message: 'Missing fields' });
  }

  const query = `
    UPDATE users
    SET name = ?, email = ?, phone = ?, role = ?
    WHERE user_id = ?
  `;

  db.query(query, [name, email, phone, role, userId], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({ success: true, message: 'User updated successfully' });
  });
});

// DELETE user
app.delete('/admin/users/:id', (req, res) => {
  const userId = req.params.id;
  db.query('DELETE FROM users WHERE user_id = ?', [userId], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false });
    }
    res.json({ success: true });
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
            dashboardPath = '/farmer_dashboard';
            break;
          case 'admin':
            dashboardPath = '/admin_dashboard';
            break;
          case 'extension_officer':
            dashboardPath = '/extension_dashboard';
            break;
          case 'factory_staff':
            dashboardPath = '/factory_staff_dashboard';
            break;
          default:
            dashboardPath = '/';
        }


        res.redirect(dashboardPath);
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
    teaDeliveredToday: 0
  };

  const farmerQuery = `SELECT COUNT(*) AS count FROM users WHERE role = 'farmer'`;
  const staffQuery = `SELECT COUNT(*) AS count FROM users WHERE role = 'factory_staff'`;
  const officerQuery = `SELECT COUNT(*) AS count FROM users WHERE role = 'extension_officer'`;
  const teaQuery = `SELECT IFNULL(SUM(quantity_kg), 0) AS total FROM deliveries WHERE delivery_date = CURDATE()`;

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
          res.json(stats);
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
    role: req.session.role
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
    SELECT quality_grade, IFNULL(SUM(quantity_kg),0) AS total
    FROM deliveries
    WHERE delivery_date = CURDATE()
    GROUP BY quality_grade;
  `;
  const weekQuery = `
    SELECT delivery_date, IFNULL(SUM(quantity_kg),0) AS total
    FROM deliveries
    WHERE delivery_date >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
    GROUP BY delivery_date
    ORDER BY delivery_date;
  `;
  const feedbackQuery = `
    SELECT u.name AS officer, AVG(f.rating) AS avg_rating
    FROM feedback f
    JOIN training_records t ON f.training_id = t.training_id
    JOIN users u ON t.officer_id = u.user_id
    GROUP BY officer
    HAVING COUNT(*) >= 1;
  `;

  db.query(todayQuery, (err, todayRows) => {
    if (err) return res.status(500).send(err);
    db.query(weekQuery, (err2, weekRows) => {
      if (err2) return res.status(500).send(err2);
      db.query(feedbackQuery, (err3, feedbackRows) => {
        if (err3) return res.status(500).send(err3);

        const todayByGrade = ['A','B','C'].map(g => {
          const row = todayRows.find(r => r.quality_grade === g);
          return row ? parseFloat(row.total) : 0;
        });
        const weekDates = weekRows.map(r => r.delivery_date.toISOString().slice(5));
        const weekDeliveryAmounts = weekRows.map(r => parseFloat(r.total));
        const officerNames = feedbackRows.map(r => r.officer);
        const officerAvgRatings = feedbackRows.map(r => parseFloat(r.avg_rating).toFixed(2));

        res.json({ todayByGrade, weekDates, weekDeliveryAmounts, officerNames, officerAvgRatings });
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
  const dbConn=db;
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








// Start server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});