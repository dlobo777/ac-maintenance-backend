const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'tu-secreto-super-seguro-cambiar-en-produccion';

app.use(cors());
app.use(express.json());

// Database setup
const dbPath = process.env.NODE_ENV === 'production' 
  ? '/opt/render/project/src/database.sqlite'
  : path.join(__dirname, 'database.sqlite');

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Database connected');
    initDatabase();
  }
});

// Initialize database
function initDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Technicians table
    db.run(`CREATE TABLE IF NOT EXISTS technicians (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      phone TEXT,
      email TEXT,
      specialization TEXT,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Clients table
    db.run(`CREATE TABLE IF NOT EXISTS clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      phone TEXT,
      email TEXT,
      address TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Work orders table
    db.run(`CREATE TABLE IF NOT EXISTS work_orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id INTEGER,
      technician_id INTEGER,
      title TEXT NOT NULL,
      description TEXT,
      status TEXT DEFAULT 'pending',
      priority TEXT DEFAULT 'normal',
      scheduled_date DATE,
      scheduled_time TEXT,
      completed_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (client_id) REFERENCES clients(id),
      FOREIGN KEY (technician_id) REFERENCES technicians(id)
    )`);

    // Materials table
    db.run(`CREATE TABLE IF NOT EXISTS materials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      stock INTEGER DEFAULT 0,
      unit TEXT,
      min_stock INTEGER DEFAULT 5,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Work order materials table
    db.run(`CREATE TABLE IF NOT EXISTS work_order_materials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      work_order_id INTEGER,
      material_id INTEGER,
      quantity INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (work_order_id) REFERENCES work_orders(id),
      FOREIGN KEY (material_id) REFERENCES materials(id)
    )`);

    // Technician availability table
    db.run(`CREATE TABLE IF NOT EXISTS technician_availability (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      technician_id INTEGER,
      date DATE NOT NULL,
      available BOOLEAN DEFAULT 1,
      notes TEXT,
      FOREIGN KEY (technician_id) REFERENCES technicians(id)
    )`);

    // Seed initial data
    seedData();
  });
}

function seedData() {
  // Check if admin exists
  db.get('SELECT * FROM users WHERE username = ?', ['admin'], (err, row) => {
    if (!row) {
      const hashedPassword = bcrypt.hashSync('admin', 10);
      db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', 
        ['admin', hashedPassword, 'admin']);
      console.log('Admin user created');
    }
  });

  // Add sample technicians
  db.get('SELECT COUNT(*) as count FROM technicians', (err, row) => {
    if (row.count === 0) {
      const technicians = [
        ['Juan Pérez', '+506 8888-1111', 'juan@email.com', 'Residencial'],
        ['María González', '+506 8888-2222', 'maria@email.com', 'Comercial'],
        ['Carlos Rodríguez', '+506 8888-3333', 'carlos@email.com', 'Industrial'],
      ];
      
      technicians.forEach(tech => {
        db.run('INSERT INTO technicians (name, phone, email, specialization) VALUES (?, ?, ?, ?)', tech);
      });
      console.log('Sample technicians created');
    }
  });

  // Add sample materials
  db.get('SELECT COUNT(*) as count FROM materials', (err, row) => {
    if (row.count === 0) {
      const materials = [
        ['Gas R-410A', 'Refrigerante para AC', 20, 'kg', 5],
        ['Filtros de aire', 'Filtros estándar', 50, 'unidad', 10],
        ['Capacitor', 'Capacitor universal', 15, 'unidad', 5],
        ['Tuberías de cobre', 'Tubo 1/4"', 100, 'metros', 20],
        ['Cable eléctrico', 'Cable calibre 12', 200, 'metros', 30],
      ];
      
      materials.forEach(mat => {
        db.run('INSERT INTO materials (name, description, stock, unit, min_stock) VALUES (?, ?, ?, ?, ?)', mat);
      });
      console.log('Sample materials created');
    }
  });
}

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// Routes

// Auth
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

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
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });
  });
});

// Technicians
app.get('/api/technicians', authenticateToken, (req, res) => {
  db.all('SELECT * FROM technicians ORDER BY name', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.post('/api/technicians', authenticateToken, (req, res) => {
  const { name, phone, email, specialization } = req.body;
  
  db.run('INSERT INTO technicians (name, phone, email, specialization) VALUES (?, ?, ?, ?)',
    [name, phone, email, specialization],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID, name, phone, email, specialization, status: 'active' });
    }
  );
});

app.put('/api/technicians/:id', authenticateToken, (req, res) => {
  const { name, phone, email, specialization, status } = req.body;
  
  db.run('UPDATE technicians SET name = ?, phone = ?, email = ?, specialization = ?, status = ? WHERE id = ?',
    [name, phone, email, specialization, status, req.params.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Technician updated' });
    }
  );
});

app.delete('/api/technicians/:id', authenticateToken, (req, res) => {
  db.run('DELETE FROM technicians WHERE id = ?', [req.params.id], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Technician deleted' });
  });
});

// Clients
app.get('/api/clients', authenticateToken, (req, res) => {
  db.all('SELECT * FROM clients ORDER BY name', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.post('/api/clients', authenticateToken, (req, res) => {
  const { name, phone, email, address } = req.body;
  
  db.run('INSERT INTO clients (name, phone, email, address) VALUES (?, ?, ?, ?)',
    [name, phone, email, address],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID, name, phone, email, address });
    }
  );
});

// Work Orders
app.get('/api/work-orders', authenticateToken, (req, res) => {
  const query = `
    SELECT wo.*, 
           c.name as client_name,
           t.name as technician_name
    FROM work_orders wo
    LEFT JOIN clients c ON wo.client_id = c.id
    LEFT JOIN technicians t ON wo.technician_id = t.id
    ORDER BY wo.created_at DESC
  `;
  
  db.all(query, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.post('/api/work-orders', authenticateToken, (req, res) => {
  const { client_id, technician_id, title, description, status, priority, scheduled_date, scheduled_time } = req.body;
  
  db.run(`INSERT INTO work_orders 
    (client_id, technician_id, title, description, status, priority, scheduled_date, scheduled_time) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [client_id, technician_id, title, description, status, priority, scheduled_date, scheduled_time],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID });
    }
  );
});

app.put('/api/work-orders/:id', authenticateToken, (req, res) => {
  const { client_id, technician_id, title, description, status, priority, scheduled_date, scheduled_time } = req.body;
  
  db.run(`UPDATE work_orders 
    SET client_id = ?, technician_id = ?, title = ?, description = ?, 
        status = ?, priority = ?, scheduled_date = ?, scheduled_time = ?
    WHERE id = ?`,
    [client_id, technician_id, title, description, status, priority, scheduled_date, scheduled_time, req.params.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Work order updated' });
    }
  );
});

app.delete('/api/work-orders/:id', authenticateToken, (req, res) => {
  db.run('DELETE FROM work_orders WHERE id = ?', [req.params.id], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Work order deleted' });
  });
});

// Materials
app.get('/api/materials', authenticateToken, (req, res) => {
  db.all('SELECT * FROM materials ORDER BY name', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.post('/api/materials', authenticateToken, (req, res) => {
  const { name, description, stock, unit, min_stock } = req.body;
  
  db.run('INSERT INTO materials (name, description, stock, unit, min_stock) VALUES (?, ?, ?, ?, ?)',
    [name, description, stock, unit, min_stock],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID, name, description, stock, unit, min_stock });
    }
  );
});

app.put('/api/materials/:id', authenticateToken, (req, res) => {
  const { name, description, stock, unit, min_stock } = req.body;
  
  db.run('UPDATE materials SET name = ?, description = ?, stock = ?, unit = ?, min_stock = ? WHERE id = ?',
    [name, description, stock, unit, min_stock, req.params.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Material updated' });
    }
  );
});

app.delete('/api/materials/:id', authenticateToken, (req, res) => {
  db.run('DELETE FROM materials WHERE id = ?', [req.params.id], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Material deleted' });
  });
});

// Work Order Materials
app.get('/api/work-orders/:id/materials', authenticateToken, (req, res) => {
  const query = `
    SELECT wom.*, m.name, m.unit
    FROM work_order_materials wom
    JOIN materials m ON wom.material_id = m.id
    WHERE wom.work_order_id = ?
  `;
  
  db.all(query, [req.params.id], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.post('/api/work-orders/:id/materials', authenticateToken, (req, res) => {
  const { material_id, quantity } = req.body;
  const work_order_id = req.params.id;
  
  // Insert material usage
  db.run('INSERT INTO work_order_materials (work_order_id, material_id, quantity) VALUES (?, ?, ?)',
    [work_order_id, material_id, quantity],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      // Update material stock
      db.run('UPDATE materials SET stock = stock - ? WHERE id = ?',
        [quantity, material_id],
        function(err) {
          if (err) {
            return res.status(500).json({ error: err.message });
          }
          res.json({ id: this.lastID, message: 'Material added and stock updated' });
        }
      );
    }
  );
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});