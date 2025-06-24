const express = require('express');
const router = express.Router();
const db = require('../db');

// GET assigned farmers for an extension officer
router.get('/:officerId/farmers', (req, res) => {
  const officerId = req.params.officerId;
  const query = `
    SELECT u.id, u.name, fp.region
    FROM users u
    JOIN farmer_profile fp ON u.id = fp.user_id
    WHERE fp.region = (
      SELECT region FROM extension_officers WHERE officer_id = ?
    )
  `;
  db.query(query, [officerId], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results);
  });
});

// POST schedule farm visit
router.post('/visits', (req, res) => {
  const { officer_id, farmer_id, visit_date, notes } = req.body;
  const query = `
    INSERT INTO farm_visits (officer_id, farmer_id, visit_date, notes)
    VALUES (?, ?, ?, ?)
  `;
  db.query(query, [officer_id, farmer_id, visit_date, notes], (err, result) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ message: 'Farm visit scheduled' });
  });
});

// GET all visits for an officer
router.get('/:officerId/visits', (req, res) => {
  db.query(
    'SELECT * FROM farm_visits WHERE officer_id = ?',
    [req.params.officerId],
    (err, results) => {
      if (err) return res.status(500).json({ error: err });
      res.json(results);
    }
  );
});

// POST upload training material
router.post('/training', (req, res) => {
  const { officer_id, title, description, file_url } = req.body;
  db.query(
    'INSERT INTO training_materials (officer_id, title, description, file_url) VALUES (?, ?, ?, ?)',
    [officer_id, title, description, file_url],
    (err, result) => {
      if (err) return res.status(500).json({ error: err });
      res.json({ message: 'Training material uploaded' });
    }
  );
});

// GET complaints in officer’s region
router.get('/:officerId/complaints', (req, res) => {
  const officerId = req.params.officerId;
  const query = `
    SELECT c.id, c.message, c.status, u.name AS farmer_name
    FROM complaints c
    JOIN users u ON c.farmer_id = u.id
    JOIN farmer_profile fp ON u.id = fp.user_id
    WHERE fp.region = (
      SELECT region FROM extension_officers WHERE officer_id = ?
    )
  `;
  db.query(query, [officerId], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results);
  });
});
