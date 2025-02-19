const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const port = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

// Database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'real_estate_crm'
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to database:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied' });
    }

    jwt.verify(token, 'your_jwt_secret', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Routes

// Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], async (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(401).json({ error: 'User not found' });
        }

        const user = results[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            'your_jwt_secret',
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    });
});

// Leads Routes
app.get('/api/leads', authenticateToken, (req, res) => {
    let query = `
        SELECT l.*, p.title as property_title, u.name as agent_name 
        FROM leads l 
        LEFT JOIN properties p ON l.property_id = p.id 
        LEFT JOIN users u ON l.assigned_to = u.id
        WHERE 1=1
    `;
    const params = [];

    if (req.query.status) {
        query += ' AND l.status = ?';
        params.push(req.query.status);
    }

    if (req.query.assignedTo) {
        query += ' AND l.assigned_to = ?';
        params.push(req.query.assignedTo);
    }

    if (req.query.searchTerm) {
        query += ' AND (l.name LIKE ? OR l.email LIKE ? OR l.phone LIKE ?)';
        const searchTerm = `%${req.query.searchTerm}%`;
        params.push(searchTerm, searchTerm, searchTerm);
    }

    db.query(query, params, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to fetch leads' });
        }
        res.json(results);
    });
});

app.post('/api/leads', authenticateToken, (req, res) => {
    const lead = {
        ...req.body,
        created_at: new Date(),
        created_by: req.user.id
    };

    db.query('INSERT INTO leads SET ?', lead, (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to create lead' });
        }
        res.json({ id: result.insertId, ...lead });
    });
});

app.get('/api/leads/:id', authenticateToken, (req, res) => {
    const query = `
        SELECT l.*, p.title as property_title, u.name as agent_name 
        FROM leads l 
        LEFT JOIN properties p ON l.property_id = p.id 
        LEFT JOIN users u ON l.assigned_to = u.id 
        WHERE l.id = ?
    `;

    db.query(query, [req.params.id], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to fetch lead' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'Lead not found' });
        }
        res.json(results[0]);
    });
});

app.put('/api/leads/:id', authenticateToken, (req, res) => {
    const lead = {
        ...req.body,
        updated_at: new Date(),
        updated_by: req.user.id
    };

    db.query('UPDATE leads SET ? WHERE id = ?', [lead, req.params.id], (err) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to update lead' });
        }
        res.json({ id: req.params.id, ...lead });
    });
});

app.delete('/api/leads/:id', authenticateToken, (req, res) => {
    db.query('DELETE FROM leads WHERE id = ?', [req.params.id], (err) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to delete lead' });
        }
        res.json({ message: 'Lead deleted successfully' });
    });
});

// Site Visits Routes
app.post('/api/site-visits', authenticateToken, (req, res) => {
    const visit = {
        ...req.body,
        status: 'scheduled',
        created_at: new Date(),
        created_by: req.user.id
    };

    db.query('INSERT INTO site_visits SET ?', visit, (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to schedule site visit' });
        }
        res.json({ id: result.insertId, ...visit });
    });
});

// Followups Routes
app.post('/api/followups', authenticateToken, (req, res) => {
    const followup = {
        ...req.body,
        status: 'pending',
        created_at: new Date(),
        created_by: req.user.id
    };

    db.query('INSERT INTO followups SET ?', followup, (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to create followup' });
        }
        res.json({ id: result.insertId, ...followup });
    });
});

// Get lead details with site visits and followups
app.get('/api/leads/:id/details', authenticateToken, (req, res) => {
    const leadQuery = `
        SELECT l.*, p.title as property_title, u.name as agent_name 
        FROM leads l 
        LEFT JOIN properties p ON l.property_id = p.id 
        LEFT JOIN users u ON l.assigned_to = u.id 
        WHERE l.id = ?
    `;

    const visitsQuery = `
        SELECT sv.*, p.title as property_title 
        FROM site_visits sv 
        LEFT JOIN properties p ON sv.property_id = p.id 
        WHERE sv.lead_id = ?
    `;

    const followupsQuery = `
        SELECT f.*, u.name as created_by_name 
        FROM followups f 
        LEFT JOIN users u ON f.created_by = u.id 
        WHERE f.lead_id = ?
    `;

    db.query(leadQuery, [req.params.id], (err, leadResults) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to fetch lead details' });
        }

        if (leadResults.length === 0) {
            return res.status(404).json({ error: 'Lead not found' });
        }

        const lead = leadResults[0];

        db.query(visitsQuery, [req.params.id], (err, visitResults) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Failed to fetch site visits' });
            }

            db.query(followupsQuery, [req.params.id], (err, followupResults) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ error: 'Failed to fetch followups' });
                }

                res.json({
                    ...lead,
                    site_visits: visitResults,
                    followups: followupResults
                });
            });
        });
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
