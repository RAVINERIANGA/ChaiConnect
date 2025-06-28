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
  database: 'chaiconnect',
  port:3307
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
    role: req.session.role,
    firstTimeUser: req.session.mustChangePassword || false
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

        const todayByGrade = ['A', 'B', 'C'].map(g => {
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

// API endpoint to get assigned farmers for the logged-in extension officer
app.get('/api/assigned-farmers', async (req, res) => {
    try {
        // In a real app, you would get the officer ID from the authenticated user's session
        const officerId = req.query.officerId || 1; // Default to 1 for demo
        
        const [farmers] = await pool.query(`
            SELECT 
                u.user_id, 
                u.name, 
                u.email, 
                u.phone, 
                u.gender, 
                u.id_number,
                fp.location,
                fp.farm_size,
                fp.crop_type,
                MAX(fv.visit_date) as last_visit
            FROM 
                users u
            JOIN 
                farmer_profile fp ON u.user_id = fp.user_id
            LEFT JOIN 
                farmer_visits fv ON u.user_id = fv.farmer_id
            WHERE 
                u.extension_officer_id = ?
            GROUP BY 
                u.user_id
            ORDER BY 
                u.name
        `, [officerId]);
        
        res.json(farmers);
    } catch (error) {
        console.error('Error fetching assigned farmers:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// API endpoint to get detailed farmer information
app.get('/api/farmer-details/:id', async (req, res) => {
    try {
        const farmerId = req.params.id;
        
        const [farmer] = await pool.query(`
            SELECT 
                u.*, 
                fp.*,
                (SELECT MAX(visit_date) FROM farmer_visits WHERE farmer_id = ?) as last_visit
            FROM 
                users u
            JOIN 
                farmer_profile fp ON u.user_id = fp.user_id
            WHERE 
                u.user_id = ?
        `, [farmerId, farmerId]);
        
        if (farmer.length === 0) {
            return res.status(404).json({ error: 'Farmer not found' });
        }
        
        res.json(farmer[0]);
    } catch (error) {
        console.error('Error fetching farmer details:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// API endpoint to schedule a visit
app.post('/api/schedule-visit', async (req, res) => {
    try {
        const { farmerId, date, purpose } = req.body;
        // In a real app, you would get the officer ID from the authenticated user's session
        const officerId = 1; // Default to 1 for demo
        
        await pool.query(`
            INSERT INTO farmer_visits 
                (farmer_id, officer_id, visit_date, purpose, status) 
            VALUES 
                (?, ?, ?, ?, 'scheduled')
        `, [farmerId, officerId, date, purpose]);
        
        res.json({ success: true, message: 'Visit scheduled successfully' });
    } catch (error) {
        console.error('Error scheduling visit:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
// Add these endpoints to your existing server.js

// API endpoint to get unassigned farmers
app.get('/api/unassigned-farmers', async (req, res) => {
    try {
        const [farmers] = await pool.query(`
            SELECT 
                u.user_id, 
                u.name, 
                u.email, 
                u.phone
            FROM 
                users u
            WHERE 
                u.role = 'farmer' AND 
                u.extension_officer_id IS NULL
            ORDER BY 
                u.name
        `);
        
        res.json(farmers);
    } catch (error) {
        console.error('Error fetching unassigned farmers:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// API endpoint to get all extension officers
app.get('/api/extension-officers', async (req, res) => {
    try {
        const [officers] = await pool.query(`
            SELECT 
                user_id, 
                name, 
                email, 
                phone
            FROM 
                users
            WHERE 
                role = 'extension_officer'
            ORDER BY 
                name
        `);
        
        res.json(officers);
    } catch (error) {
        console.error('Error fetching extension officers:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// API endpoint to get current assignments
app.get('/api/current-assignments', async (req, res) => {
    try {
        const [assignments] = await pool.query(`
            SELECT 
                f.user_id as farmer_id,
                f.name as farmer_name,
                e.user_id as officer_id,
                e.name as officer_name,
                DATE_FORMAT(f.created_at, '%Y-%m-%d') as assigned_since
            FROM 
                users f
            JOIN 
                users e ON f.extension_officer_id = e.user_id
            WHERE 
                f.role = 'farmer' AND 
                f.extension_officer_id IS NOT NULL
            ORDER BY 
                f.name
        `);
        
        res.json(assignments);
    } catch (error) {
        console.error('Error fetching current assignments:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// API endpoint to assign a farmer to an officer
app.post('/api/assign-farmer', async (req, res) => {
    try {
        const { farmerId, officerId } = req.body;
        
        await pool.query(`
            UPDATE users 
            SET extension_officer_id = ? 
            WHERE user_id = ? AND role = 'farmer'
        `, [officerId, farmerId]);
        
        res.json({ success: true, message: 'Farmer assigned successfully' });
    } catch (error) {
        console.error('Error assigning farmer:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// API endpoint to unassign a farmer
app.post('/api/unassign-farmer', async (req, res) => {
    try {
        const { farmerId } = req.body;
        
        await pool.query(`
            UPDATE users 
            SET extension_officer_id = NULL 
            WHERE user_id = ? AND role = 'farmer'
        `, [farmerId]);
        
        res.json({ success: true, message: 'Farmer unassigned successfully' });
    } catch (error) {
        console.error('Error unassigning farmer:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
// Start server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});