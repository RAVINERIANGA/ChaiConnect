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

    // Step 1: Insert into users table
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

      // Step 2: Insert into farmer_profile table
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
  const userId = req.params.id;
  const { name, email, phone, role } = req.body;


  if (!name || !email || !phone || !role) {
    return res.status(400).json({ success: false, message: 'Missing fields' });
  }

  const query = `
    UPDATE users SET name = ?, email = ?, phone = ?, role = ? WHERE user_id = ?
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
app.get('/api/assigned-farmers', (req, res) => {
    const officerId = req.session.userId;

    if (!officerId) {
        return res.status(401).json({ error: 'Not logged in' });
    }

    const query = `
        SELECT 
            u.user_id, 
            u.name, 
            u.email, 
            u.phone, 
            u.gender, 
            u.id_number,
            fp.location
        FROM 
            users u
        JOIN 
            farmer_profile fp ON u.user_id = fp.farmer_id
        JOIN 
            farmer_assignments fa ON u.user_id = fa.farmer_id
        JOIN 
            extension_officers eo ON fa.officer_id = eo.officer_id
        WHERE 
            eo.user_id = ? AND
            u.role = 'farmer'
        ORDER BY 
            u.name
    `;

    db.query(query, [officerId], (error, farmers) => {
        if (error) {
            console.error('Error fetching assigned farmers:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
        res.json(farmers);
    });
});

// API endpoint to get unassigned farmers
app.get('/api/unassigned-farmers', (req, res) => {
    const query = `
    SELECT 
        u.user_id, 
        u.name, 
        u.email, 
        u.phone,
        fp.location AS region
    FROM 
        users u
    JOIN 
        farmer_profile fp ON u.user_id = fp.farmer_id
    LEFT JOIN 
        farmer_assignments fa ON u.user_id = fa.farmer_id
    WHERE 
        u.role = 'farmer' AND 
        fa.farmer_id IS NULL
    ORDER BY 
        u.name
`;


    db.query(query, (error, farmers) => {
        if (error) {
            console.error('Error fetching unassigned farmers:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
        res.json(farmers);
    });
});

// API endpoint to get all extension officers
app.get('/api/extension-officers', (req, res) => {
    const query = `
        SELECT 
            eo.officer_id,
            u.user_id, 
            u.name, 
            u.email, 
            u.phone, 
            eo.region,
            eo.specialization
        FROM 
            users u
        JOIN 
            extension_officers eo ON u.user_id = eo.user_id
        WHERE 
            u.role = 'extension_officer'
        ORDER BY 
            u.name
    `;

    db.query(query, (error, officers) => {
        if (error) {
            console.error('Error fetching extension officers:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
        res.json(officers);
    });
});

// API endpoint to get current assignments
app.get('/api/current-assignments', (req, res) => {
    const query = `
        SELECT 
            f.user_id as farmer_id,
            f.name as farmer_name,
            u.user_id as officer_user_id,
            u.name as officer_name,
            eo.officer_id,
            DATE_FORMAT(fa.assigned_at, '%Y-%m-%d') as assigned_since
        FROM 
            users f
        JOIN 
            farmer_assignments fa ON f.user_id = fa.farmer_id
        JOIN 
            extension_officers eo ON fa.officer_id = eo.officer_id
        JOIN 
            users u ON eo.user_id = u.user_id
        WHERE 
            f.role = 'farmer'
        ORDER BY 
            f.name
    `;

    db.query(query, (error, assignments) => {
        if (error) {
            console.error('Error fetching current assignments:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
        res.json(assignments);
    });
});

// API endpoint to assign a farmer to an officer
app.post('/api/assign-farmer', (req, res) => {
    const { farmerId, officerId } = req.body; // officerId here is the officer_id from extension_officers table

    const query = `
        INSERT INTO farmer_assignments 
            (farmer_id, officer_id) 
        VALUES 
            (?, ?)
        ON DUPLICATE KEY UPDATE 
            officer_id = VALUES(officer_id),
            assigned_at = CURRENT_TIMESTAMP
    `;

    db.query(query, [farmerId, officerId], (error, result) => {
        if (error) {
            console.error('Error assigning farmer:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
        res.json({ success: true, message: 'Farmer assigned successfully' });
    });
});

// API endpoint to unassign a farmer
app.post('/api/unassign-farmer', (req, res) => {
    const { farmerId } = req.body;

    const query = `
        DELETE FROM farmer_assignments 
        WHERE farmer_id = ?
    `;

    db.query(query, [farmerId], (error, result) => {
        if (error) {
            console.error('Error unassigning farmer:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
        res.json({ success: true, message: 'Farmer unassigned successfully' });
    });
});

// API endpoint to get detailed farmer information
app.get('/api/farmer-details/:id', (req, res) => {
    const farmerId = req.params.id;

    const query = `
        SELECT 
            u.*, 
            fp.*
        FROM 
            users u
        JOIN 
            farmer_profile fp ON u.user_id = fp.farmer_id
        WHERE 
            u.user_id = ?
    `;

    db.query(query, [farmerId], (error, farmer) => {
        if (error) {
            console.error('Error fetching farmer details:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (farmer.length === 0) {
            return res.status(404).json({ error: 'Farmer not found' });
        }

        res.json(farmer[0]);
    });
});


// Start server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});