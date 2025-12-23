const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'ac-maintenance-secret-2024';

app.use(cors());
app.use(express.json());

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize database
async function initDatabase() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Technicians table
    await client.query(`
      CREATE TABLE IF NOT EXISTS technicians (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        phone VARCHAR(50),
        email VARCHAR(255),
        specialization VARCHAR(100),
        status VARCHAR(50) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Clients table
    await client.query(`
      CREATE TABLE IF NOT EXISTS clients (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        phone VARCHAR(50),
        email VARCHAR(255),
        address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Work orders table
    await client.query(`
      CREATE TABLE IF NOT EXISTS work_orders (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES clients(id),
        technician_id INTEGER REFERENCES technicians(id),
        title VARCHAR(255) NOT NULL,
        description TEXT,
        status VARCHAR(50) DEFAULT 'pending',
        priority VARCHAR(50) DEFAULT 'normal',
        scheduled_date DATE,
        scheduled_time VARCHAR(20),
        completed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Materials table
    await client.query(`
      CREATE TABLE IF NOT EXISTS materials (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        stock INTEGER DEFAULT 0,
        unit VARCHAR(50),
        min_stock INTEGER DEFAULT 5,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Work order materials table
    await client.query(`
      CREATE TABLE IF NOT EXISTS work_order_materials (
        id SERIAL PRIMARY KEY,
        work_order_id INTEGER REFERENCES work_orders(id) ON DELETE CASCADE,
        material_id INTEGER REFERENCES materials(id),
        quantity INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query('COMMIT');
    console.log('✅ Database tables created');

    await seedData(client);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Database initialization error:', err);
  } finally {
    client.release();
  }
}

async function seedData(client) {
  try {
    // Check if admin exists
    const adminCheck = await client.query('SELECT * FROM users WHERE username = $1', ['admin']);
    
    if (adminCheck.rows.length === 0) {
      const hashedPassword = bcrypt.hashSync('Admin2025!', 10);
      await client.query(
        'INSERT INTO users (username, password, role) VALUES ($1, $2, $3)',
        ['admin', hashedPassword, 'admin']
      );
      console.log('✅ Admin user created (admin/Admin2025!)');
    }

    // Sample technicians
    const techCheck = await client.query('SELECT COUNT(*) as count FROM technicians');
    if (parseInt(techCheck.rows[0].count) === 0) {
      const technicians = [
        ['Juan Pérez', '+506-8888-1111', 'juan@email.com', 'Residencial'],
        ['María González', '+506-8888-2222', 'maria@email.com', 'Comercial'],
        ['Carlos Rodríguez', '+506-8888-3333', 'carlos@email.com', 'Industrial']
      ];
      
      for (const tech of technicians) {
        await client.query(
          'INSERT INTO technicians (name, phone, email, specialization) VALUES ($1, $2, $3, $4)',
          tech
        );
      }
      console.log('✅ Sample technicians created');
    }

    // Sample materials
    const matCheck = await client.query('SELECT COUNT(*) as count FROM materials');
    if (parseInt(matCheck.rows[0].count) === 0) {
      const materials = [
        ['Gas R-410A', 'Refrigerante', 20, 'kg', 5],
        ['Filtros de aire', 'Filtros estándar', 50, 'unidad', 10],
        ['Capacitor', 'Universal', 15, 'unidad', 5]
      ];
      
      for (const mat of materials) {
        await client.query(
          'INSERT INTO materials (name, description, stock, unit, min_stock) VALUES ($1, $2, $3, $4, $5)',
          mat
        );
      }
      console.log('✅ Sample materials created');
    }
  } catch (err) {
    console.error('Seed data error:', err);
  }
}
// Backup/Restore endpoints
app.get('/api/backup/export', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  
  try {
    const backup = {
      version: '1.0',
      date: new Date().toISOString(),
      technicians: (await pool.query('SELECT * FROM technicians')).rows,
      clients: (await pool.query('SELECT * FROM clients')).rows,
      work_orders: (await pool.query('SELECT * FROM work_orders')).rows,
      materials: (await pool.query('SELECT * FROM materials')).rows,
      users: (await pool.query('SELECT id, username, role, created_at FROM users')).rows
    };
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=backup-${new Date().toISOString().split('T')[0]}.json`);
    res.send(JSON.stringify(backup, null, 2));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/backup/restore', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  
  const client = await pool.connect();
  try {
    const { technicians, clients, work_orders, materials } = req.body;
    
    await client.query('BEGIN');
    
    // Clear existing data (except users)
    await client.query('DELETE FROM work_order_materials');
    await client.query('DELETE FROM work_orders');
    await client.query('DELETE FROM materials');
    await client.query('DELETE FROM clients');
    await client.query('DELETE FROM technicians');
    
    // Restore technicians
    for (const tech of technicians || []) {
      await client.query(
        'INSERT INTO technicians (id, name, phone, email, specialization, status) VALUES ($1, $2, $3, $4, $5, $6)',
        [tech.id, tech.name, tech.phone, tech.email, tech.specialization, tech.status]
      );
    }
    
    // Restore clients
    for (const cli of clients || []) {
      await client.query(
        'INSERT INTO clients (id, name, phone, email, address) VALUES ($1, $2, $3, $4, $5)',
        [cli.id, cli.name, cli.phone, cli.email, cli.address]
      );
    }
    
    // Restore materials
    for (const mat of materials || []) {
      await client.query(
        'INSERT INTO materials (id, name, description, stock, unit, min_stock) VALUES ($1, $2, $3, $4, $5, $6)',
        [mat.id, mat.name, mat.description, mat.stock, mat.unit, mat.min_stock]
      );
    }
    
    // Restore work orders
    for (const wo of work_orders || []) {
      await client.query(
        'INSERT INTO work_orders (id, client_id, technician_id, title, description, status, priority, scheduled_date, scheduled_time) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
        [wo.id, wo.client_id, wo.technician_id, wo.title, wo.description, wo.status, wo.priority, wo.scheduled_date, wo.scheduled_time]
      );
    }
    
    await client.query('COMMIT');
    res.json({ message: 'Backup restored successfully' });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});
// Auth middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Routes
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Users management
app.get('/api/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  try {
    const result = await pool.query('SELECT id, username, role, created_at FROM users ORDER BY username');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  const { username, password, role } = req.body;
  try {
    const hashedPassword = bcrypt.hashSync(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username, role',
      [username, hashedPassword, role]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  const { password, role } = req.body;
  try {
    if (password) {
      const hashedPassword = bcrypt.hashSync(password, 10);
      await pool.query(
        'UPDATE users SET password = $1, role = $2 WHERE id = $3',
        [hashedPassword, role, req.params.id]
      );
    } else {
      await pool.query('UPDATE users SET role = $1 WHERE id = $2', [role, req.params.id]);
    }
    res.json({ message: 'User updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Technicians
app.get('/api/technicians', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM technicians ORDER BY name');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/technicians', authenticateToken, async (req, res) => {
  const { name, phone, email, specialization } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO technicians (name, phone, email, specialization) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, phone, email, specialization]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/technicians/:id', authenticateToken, async (req, res) => {
  const { name, phone, email, specialization, status } = req.body;
  try {
    await pool.query(
      'UPDATE technicians SET name=$1, phone=$2, email=$3, specialization=$4, status=$5 WHERE id=$6',
      [name, phone, email, specialization, status, req.params.id]
    );
    res.json({ message: 'Updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/technicians/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM technicians WHERE id=$1', [req.params.id]);
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Clients
app.get('/api/clients', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM clients ORDER BY name');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/clients', authenticateToken, async (req, res) => {
  const { name, phone, email, address } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO clients (name, phone, email, address) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, phone, email, address]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Work Orders
app.get('/api/work-orders', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT wo.*, c.name as client_name, t.name as technician_name
      FROM work_orders wo
      LEFT JOIN clients c ON wo.client_id = c.id
      LEFT JOIN technicians t ON wo.technician_id = t.id
      ORDER BY wo.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/work-orders', authenticateToken, async (req, res) => {
  const { client_id, technician_id, title, description, status, priority, scheduled_date, scheduled_time } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO work_orders (client_id, technician_id, title, description, status, priority, scheduled_date, scheduled_time) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [client_id, technician_id, title, description, status, priority, scheduled_date, scheduled_time]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/work-orders/:id', authenticateToken, async (req, res) => {
  const { client_id, technician_id, title, description, status, priority, scheduled_date, scheduled_time } = req.body;
  try {
    await pool.query(
      `UPDATE work_orders SET client_id=$1, technician_id=$2, title=$3, description=$4, status=$5, priority=$6, scheduled_date=$7, scheduled_time=$8 WHERE id=$9`,
      [client_id, technician_id, title, description, status, priority, scheduled_date, scheduled_time, req.params.id]
    );
    res.json({ message: 'Updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/work-orders/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM work_orders WHERE id=$1', [req.params.id]);
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Materials
app.get('/api/materials', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM materials ORDER BY name');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/materials', authenticateToken, async (req, res) => {
  const { name, description, stock, unit, min_stock } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO materials (name, description, stock, unit, min_stock) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, description, stock, unit, min_stock]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/materials/:id', authenticateToken, async (req, res) => {
  const { name, description, stock, unit, min_stock } = req.body;
  try {
    await pool.query(
      'UPDATE materials SET name=$1, description=$2, stock=$3, unit=$4, min_stock=$5 WHERE id=$6',
      [name, description, stock, unit, min_stock, req.params.id]
    );
    res.json({ message: 'Updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/materials/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM materials WHERE id=$1', [req.params.id]);
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Initialize and start server
initDatabase().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
  });
});