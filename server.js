const express  = require('express');
const mysql    = require('mysql2');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const dotenv   = require('dotenv');
const path     = require('path');
const https    = require('https');

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Database ─────────────────────────────────────
let db;

if (process.env.DATABASE_URL) {
  console.log('📡 DATABASE_URL found');
  console.log('🔗 URL length:', process.env.DATABASE_URL.length);
  
  try {
    console.log('🔄 Attempting connection...');
    db = mysql.createConnection(process.env.DATABASE_URL);
    
    db.connect((err) => {
      if (err) {
        console.log('❌ CONNECTION FAILED');
        console.log('📛 Error code:', err.code);
        console.log('💬 Error message:', err.message);
      } else {
        console.log('✅ CONNECTED TO MYSQL');
        
        db.query('SELECT 1 + 1 AS result', (err, results) => {
          if (err) {
            console.log('❌ Test query failed:', err.message);
          } else {
            console.log('✅ Test query successful');
          }
        });
      }
    });
  } catch (err) {
    console.log('❌ CRITICAL ERROR:', err.message);
  }
} else {
  console.log('❌ No DATABASE_URL found');
  console.log('Using local config instead');
  
  db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'toku_app'
  });
  
  db.connect((err) => {
    if (err) console.error('❌ Local DB Error:', err.message);
    else console.log('✅ Connected to Local MySQL');
  });
}

// Helper: generate referral code
function generateCode(name) {
  return name.replace(/\s+/g,'').substring(0,4).toUpperCase() +
         Math.floor(1000 + Math.random() * 9000);
}

// Auth middleware
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Not logged in' });
  try {
    const token = auth.split(' ')[1];
    req.user    = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Session expired, please log in again' });
  }
}

// ════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════

app.post('/api/signup', async (req, res) => {
  const { full_name, email, password, referral_code } = req.body;
  if (!full_name || !email || !password)
    return res.status(400).json({ message: 'All fields are required' });

  db.query('SELECT id FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (results.length > 0)
      return res.status(409).json({ message: 'Email already registered' });

    const hashed  = await bcrypt.hash(password, 10);
    const refCode = generateCode(full_name);
    let referredBy = null;
    
    if (referral_code) {
      const [refUser] = await db.promise().query(
        'SELECT id FROM users WHERE referral_code = ?', [referral_code]
      );
      if (refUser.length > 0) referredBy = refUser[0].id;
    }

    db.query(
      'INSERT INTO users (full_name, email, password, referral_code, referred_by) VALUES (?,?,?,?,?)',
      [full_name, email, hashed, refCode, referredBy],
      (err, result) => {
        if (err) return res.status(500).json({ message: 'Database error: ' + err.message });
        const token = jwt.sign(
          { id: result.insertId, name: full_name, email },
          process.env.JWT_SECRET,
          { expiresIn: '7d' }
        );
        res.status(201).json({ message: 'Account created!', token, name: full_name });
      }
    );
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: 'All fields are required' });

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (results.length === 0)
      return res.status(401).json({ message: 'Invalid email or password' });

    const user  = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ message: 'Invalid email or password' });

    const token = jwt.sign(
      { id: user.id, name: user.full_name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({
      message: 'Login successful',
      token,
      name: user.full_name,
      balance: user.balance,
      referral_code: user.referral_code
    });
  });
});

// ════════════════════════════════════════════════
//  USER ROUTES
// ════════════════════════════════════════════════

app.get('/api/profile', authMiddleware, (req, res) => {
  db.query(
    `SELECT u.id, u.full_name, u.email, u.balance, u.referral_code,
            i.id as inv_id, i.daily_return, i.days_claimed,
            i.start_date, i.end_date, i.status as inv_status,
            p.name as package_name, p.price as package_price
     FROM users u
     LEFT JOIN investments i ON i.user_id = u.id AND i.status = 'active'
     LEFT JOIN packages p ON p.id = i.package_id
     WHERE u.id = ?`,
    [req.user.id],
    (err, results) => {
      if (err) return res.status(500).json({ message: 'Error fetching profile' });
      res.json(results[0] || {});
    }
  );
});

app.get('/api/packages', (req, res) => {
  db.query('SELECT * FROM packages WHERE is_active = 1', (err, results) => {
    if (err) return res.status(500).json({ message: 'Error fetching packages' });
    res.json(results);
  });
});

// ════════════════════════════════════════════════
//  PAYSTACK ROUTES
// ════════════════════════════════════════════════

app.post('/api/pay/initialize', authMiddleware, (req, res) => {
  const { package_id } = req.body;

  db.query('SELECT * FROM packages WHERE id = ?', [package_id], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ message: 'Package not found' });
    }

    const pkg = results[0];
    const amount = pkg.price * 100;
    const ref = 'TOKU_' + Date.now() + '_' + req.user.id;

    db.query(
      'INSERT INTO transactions (user_id, package_id, amount, paystack_ref) VALUES (?,?,?,?)',
      [req.user.id, package_id, pkg.price, ref],
      (err) => {
        if (err) {
          console.error('Transaction insert error:', err);
          return res.status(500).json({ message: 'Could not create transaction' });
        }

        const params = JSON.stringify({
          email: req.user.email,
          amount: amount,
          reference: ref,
          callback_url: `${process.env.APP_URL || 'https://toku-app.onrender.com'}/user/verify.html`
        });

        const options = {
          hostname: 'api.paystack.co',
          port: 443,
          path: '/transaction/initialize',
          method: 'POST',
          headers: {
            Authorization: `Bearer ${process.env.PAYSTACK_SECRET}`,
            'Content-Type': 'application/json'
          }
        };

        const paystackReq = https.request(options, paystackRes => {
          let data = '';
          paystackRes.on('data', chunk => data += chunk);
          paystackRes.on('end', () => {
            try {
              const response = JSON.parse(data);
              if (response.status) {
                res.json({ authorization_url: response.data.authorization_url, reference: ref });
              } else {
                console.error('Paystack init error:', response);
                res.status(500).json({ message: 'Paystack error: ' + response.message });
              }
            } catch (e) {
              console.error('Parse error:', e);
              res.status(500).json({ message: 'Invalid Paystack response' });
            }
          });
        });

        paystackReq.on('error', (e) => {
          console.error('Network error:', e);
          res.status(500).json({ message: 'Network error connecting to Paystack' });
        });

        paystackReq.write(params);
        paystackReq.end();
      }
    );
  });
});

app.get('/api/pay/verify/:reference', authMiddleware, (req, res) => {
  const { reference } = req.params;
  const options = {
    hostname: 'api.paystack.co',
    port: 443,
    path: `/transaction/verify/${reference}`,
    method: 'GET',
    headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET}` }
  };

  https.get(options, paystackRes => {
    let data = '';
    paystackRes.on('data', chunk => data += chunk);
    paystackRes.on('end', async () => {
      try {
        const response = JSON.parse(data);
        if (response.status && response.data.status === 'success') {
          db.query(
            'SELECT * FROM transactions WHERE paystack_ref = ? AND user_id = ?',
            [reference, req.user.id],
            async (err, txResults) => {
              if (err || txResults.length === 0) {
                return res.status(404).json({ success: false, message: 'Transaction not found' });
              }
              const tx = txResults[0];
              if (tx.status === 'success') {
                return res.json({ success: true, activated: true, message: 'Already activated' });
              }

              await db.promise().query('UPDATE transactions SET status = "success" WHERE paystack_ref = ?', [reference]);
              const [pkgRows] = await db.promise().query('SELECT * FROM packages WHERE id = ?', [tx.package_id]);
              if (!pkgRows.length) throw new Error('Package not found');
              const pkg = pkgRows[0];

              const today = new Date();
              const endDate = new Date();
              endDate.setDate(today.getDate() + pkg.duration_days);

              await db.promise().query(
                `INSERT INTO investments (user_id, package_id, amount, daily_return, start_date, end_date, days_claimed, last_claim_date)
                 VALUES (?, ?, ?, ?, ?, ?, 0, NULL)`,
                [req.user.id, tx.package_id, tx.amount, pkg.daily_return, today, endDate]
              );

              await db.promise().query('UPDATE users SET has_invested = 1 WHERE id = ?', [req.user.id]);

              const [refRows] = await db.promise().query(
                `SELECT referred_by FROM users WHERE id = ? AND has_invested = 1 AND referred_by IS NOT NULL`,
                [req.user.id]
              );
              if (refRows.length > 0 && refRows[0].referred_by) {
                const referrerId = refRows[0].referred_by;
                const bonus = tx.amount * 0.10;
                const [existing] = await db.promise().query('SELECT id FROM referrals WHERE referred_id = ?', [req.user.id]);
                if (existing.length === 0) {
                  await db.promise().query(
                    'INSERT INTO referrals (referrer_id, referred_id, package_price, bonus_amount) VALUES (?,?,?,?)',
                    [referrerId, req.user.id, tx.amount, bonus]
                  );
                  await db.promise().query('UPDATE users SET balance = balance + ? WHERE id = ?', [bonus, referrerId]);
                }
              }

              res.json({ success: true, activated: true, message: 'Package activated!' });
            }
          );
        } else {
          await db.promise().query('UPDATE transactions SET status = "failed" WHERE paystack_ref = ?', [reference]);
          res.status(400).json({ success: false, message: 'Payment not successful' });
        }
      } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error during verification' });
      }
    });
  }).on('error', e => res.status(500).json({ success: false, message: 'Paystack network error' }));
});

// ════════════════════════════════════════════════
//  DAILY CLAIM
// ════════════════════════════════════════════════

app.post('/api/claim', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  try {
    const [invRows] = await db.promise().query(
      `SELECT * FROM investments 
       WHERE user_id = ? AND status = 'active' AND days_claimed < (SELECT duration_days FROM packages WHERE id = package_id)`,
      [userId]
    );
    if (invRows.length === 0) {
      return res.status(400).json({ message: 'No active investment available to claim' });
    }
    const inv = invRows[0];

    const now = new Date();
    const lastClaim = inv.last_claim_date ? new Date(inv.last_claim_date) : new Date(inv.start_date);
    const hoursSince = (now - lastClaim) / (1000 * 3600);
    if (hoursSince < 23.5) {
      return res.status(400).json({ message: 'Already claimed within 24 hours. Come back later.' });
    }

    const amount = inv.daily_return;
    const newDaysClaimed = inv.days_claimed + 1;
    const isCompleted = newDaysClaimed >= 7;

    await db.promise().query('START TRANSACTION');
    await db.promise().query('INSERT INTO claims (user_id, investment_id, amount, claim_date) VALUES (?, ?, ?, NOW())', [userId, inv.id, amount]);
    await db.promise().query(`UPDATE investments SET days_claimed = ?, last_claim_date = NOW(), status = ? WHERE id = ?`, [newDaysClaimed, isCompleted ? 'completed' : 'active', inv.id]);
    await db.promise().query('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, userId]);
    await db.promise().query('COMMIT');

    res.json({ message: `✅ ₦${amount} claimed successfully!`, amount, days_remaining: isCompleted ? 0 : 7 - newDaysClaimed });
  } catch (err) {
    await db.promise().query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: 'Claim failed. Try again.' });
  }
});

app.get('/api/user/claim-status', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  try {
    const [invRows] = await db.promise().query(
      `SELECT i.*, p.duration_days FROM investments i JOIN packages p ON i.package_id = p.id WHERE i.user_id = ? AND i.status = 'active'`,
      [userId]
    );
    if (invRows.length === 0) return res.json({ active: false });
    const inv = invRows[0];
    const startDate = new Date(inv.last_claim_date || inv.start_date);
    const now = new Date();
    const nextClaimTime = new Date(startDate.getTime() + 24 * 60 * 60 * 1000);
    const countdown = Math.max(0, nextClaimTime - now);
    const canClaimNow = countdown === 0 ? 1 : 0;
    res.json({ active: true, canClaimNow, earningsPerPeriod: inv.daily_return, countdown, pendingAmount: canClaimNow ? inv.daily_return : 0 });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ════════════════════════════════════════════════
//  WITHDRAWAL
// ════════════════════════════════════════════════

app.post('/api/withdraw', authMiddleware, (req, res) => {
  const { amount, bank_name, account_no, account_name } = req.body;
  if (!amount || !bank_name || !account_no || !account_name) return res.status(400).json({ message: 'All fields are required' });
  if (amount < 500) return res.status(400).json({ message: 'Minimum withdrawal is ₦500' });

  db.query('SELECT balance FROM users WHERE id = ?', [req.user.id], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    const balance = results[0].balance;
    if (balance < amount) return res.status(400).json({ message: 'Insufficient balance' });

    db.query('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, req.user.id], (err) => {
      if (err) return res.status(500).json({ message: 'Update failed' });
      db.query('INSERT INTO withdrawals (user_id, amount, bank_name, account_no, account_name) VALUES (?,?,?,?,?)', [req.user.id, amount, bank_name, account_no, account_name], (err) => {
        if (err) return res.status(500).json({ message: 'Withdrawal request failed' });
        res.json({ message: 'Withdrawal request submitted! We will process it shortly.' });
      });
    });
  });
});

app.get('/api/withdrawals', authMiddleware, (req, res) => {
  db.query('SELECT * FROM withdrawals WHERE user_id = ? ORDER BY created_at DESC', [req.user.id], (err, results) => res.json(results));
});

// ════════════════════════════════════════════════
//  REFERRAL & STATS
// ════════════════════════════════════════════════

app.get('/api/referrals', authMiddleware, (req, res) => {
  db.query(`SELECT r.*, u.full_name as referred_name, u.email as referred_email FROM referrals r JOIN users u ON u.id = r.referred_id WHERE r.referrer_id = ? ORDER BY r.created_at DESC`, [req.user.id], (err, results) => res.json(results));
});

app.get('/api/claims', authMiddleware, (req, res) => {
  db.query(`SELECT c.*, p.name as package_name FROM claims c JOIN investments i ON i.id = c.investment_id JOIN packages p ON p.id = i.package_id WHERE c.user_id = ? ORDER BY c.created_at DESC`, [req.user.id], (err, results) => res.json(results));
});

app.get('/api/stats', authMiddleware, (req, res) => {
  const uid = req.user.id;
  Promise.all([
    db.promise().query('SELECT SUM(amount) as total FROM investments WHERE user_id = ?', [uid]),
    db.promise().query('SELECT SUM(amount) as total FROM claims WHERE user_id = ?', [uid]),
    db.promise().query("SELECT SUM(amount) as total FROM withdrawals WHERE user_id = ? AND status != 'rejected'", [uid]),
    db.promise().query('SELECT SUM(bonus_amount) as total FROM referrals WHERE referrer_id = ?', [uid]),
  ]).then(([inv, claims, withdrawals, referrals]) => {
    res.json({
      total_invested: inv[0][0].total || 0,
      total_earned: claims[0][0].total || 0,
      total_withdrawn: withdrawals[0][0].total || 0,
      referral_earned: referrals[0][0].total || 0,
    });
  }).catch(err => res.status(500).json({ error: 'Stats error' }));
});

// ════════════════════════════════════════════════
//  ADMIN ROUTES
// ════════════════════════════════════════════════

app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM users WHERE email = ? AND is_admin = 1', [email], async (err, results) => {
    if (err || results.length === 0) return res.status(401).json({ message: 'Invalid admin credentials' });
    const admin = results[0];
    const match = await bcrypt.compare(password, admin.password);
    if (!match) return res.status(401).json({ message: 'Invalid admin credentials' });
    const token = jwt.sign({ id: admin.id, name: admin.full_name, email: admin.email, isAdmin: true }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ message: 'Admin login successful', token, isAdmin: true });
  });
});

app.get('/api/admin/overview', (req, res) => {
  Promise.all([
    db.promise().query('SELECT COUNT(*) as total FROM users'),
    db.promise().query('SELECT COUNT(*) as total FROM investments'),
    db.promise().query("SELECT SUM(amount) as total FROM transactions WHERE status = 'success'"),
    db.promise().query("SELECT COUNT(*) as total FROM withdrawals WHERE status = 'pending'"),
  ]).then(([users, investments, revenue, pending]) => {
    res.json({
      total_users: users[0][0].total || 0,
      total_investments: investments[0][0].total || 0,
      total_revenue: revenue[0][0].total || 0,
      pending_withdrawals: pending[0][0].total || 0,
    });
  }).catch(err => res.status(500).json({ error: 'Failed to load dashboard data' }));
});

app.get('/api/admin/withdrawals', (req, res) => {
  db.query(`SELECT w.*, u.full_name, u.email FROM withdrawals w JOIN users u ON u.id = w.user_id ORDER BY w.created_at DESC`, (err, results) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch withdrawals' });
    res.json(results);
  });
});

app.post('/api/admin/withdrawals/:id', (req, res) => {
  const { status } = req.body;
  const withdrawalId = req.params.id;
  db.query('UPDATE withdrawals SET status = ? WHERE id = ?', [status, withdrawalId], (err) => {
    if (err) return res.status(500).json({ message: 'Update failed' });
    if (status === 'rejected') {
      db.query('SELECT user_id, amount FROM withdrawals WHERE id = ?', [withdrawalId], (err, results) => {
        if (!err && results.length > 0) {
          db.query('UPDATE users SET balance = balance + ? WHERE id = ?', [results[0].amount, results[0].user_id]);
        }
      });
    }
    res.json({ message: `Withdrawal ${status}` });
  });
});

app.get('/api/admin/investments', (req, res) => {
  db.query(`SELECT i.*, u.full_name, u.email, p.name as package_name, p.duration_days FROM investments i JOIN users u ON u.id = i.user_id JOIN packages p ON p.id = i.package_id ORDER BY i.created_at DESC`, (err, results) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch investments' });
    res.json(results);
  });
});

app.get('/api/admin/users', (req, res) => {
  db.query(`SELECT id, full_name, email, balance, has_invested, referral_code, created_at, is_admin FROM users ORDER BY created_at DESC`, (err, results) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch users' });
    res.json(results);
  });
});

app.get('/api/test-db', (req, res) => {
  if (!db) {
    return res.json({ error: 'Database not connected' });
  }
  db.query('SELECT NOW() as time', (err, result) => {
    if (err) {
      res.json({ error: err.message, code: err.code });
    } else {
      res.json({ success: true, time: result[0].time });
    }
  });
});

// Temporary setup endpoint - CREATE ALL TABLES
app.get('/api/setup-admin', async (req, res) => {
  console.log('Setup endpoint called - creating tables');
  
  try {
    // Create tables
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        full_name VARCHAR(100) NOT NULL,
        email VARCHAR(150) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        balance DECIMAL(10,2) DEFAULT 0,
        referral_code VARCHAR(50) UNIQUE,
        referred_by INT NULL,
        has_invested TINYINT DEFAULT 0,
        is_admin TINYINT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS packages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(50) NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        daily_return DECIMAL(10,2) NOT NULL,
        duration_days INT DEFAULT 7,
        is_active TINYINT DEFAULT 1
      )
    `);
    
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS investments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        package_id INT NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        daily_return DECIMAL(10,2) NOT NULL,
        start_date DATE NOT NULL,
        end_date DATE NOT NULL,
        days_claimed INT DEFAULT 0,
        last_claim_date DATETIME NULL,
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (package_id) REFERENCES packages(id)
      )
    `);
    
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS transactions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        package_id INT NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        paystack_ref VARCHAR(100) UNIQUE,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS claims (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        investment_id INT NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        claim_date DATE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (investment_id) REFERENCES investments(id)
      )
    `);
    
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS withdrawals (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        bank_name VARCHAR(100) NOT NULL,
        account_no VARCHAR(50) NOT NULL,
        account_name VARCHAR(100) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    
    await db.promise().query(`
      CREATE TABLE IF NOT EXISTS referrals (
        id INT AUTO_INCREMENT PRIMARY KEY,
        referrer_id INT NOT NULL,
        referred_id INT NOT NULL,
        package_price DECIMAL(10,2) NOT NULL,
        bonus_amount DECIMAL(10,2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (referrer_id) REFERENCES users(id),
        FOREIGN KEY (referred_id) REFERENCES users(id)
      )
    `);
    
    // Insert packages
    await db.promise().query(`
      INSERT IGNORE INTO packages (name, price, daily_return, duration_days) VALUES
      ('Starter', 500, 100, 7),
      ('Basic', 1000, 200, 7),
      ('Standard', 2000, 400, 7),
      ('Premium', 5000, 1000, 7),
      ('VIP', 10000, 2000, 7)
    `);
    
    // Insert admin user
    await db.promise().query(`
      INSERT INTO users (full_name, email, password, referral_code, is_admin, balance) 
      VALUES ('Admin User', 'admin@toku.com', '$2a$10$N9qo8uLOickgx2ZMRZoMy.MrJqGzYKFjJdj9M5qQYkIqWqZjvBJGm', 'ADMIN1234', 1, 0)
      ON DUPLICATE KEY UPDATE is_admin = 1
    `);
    
    res.json({ success: true, message: 'All tables created! Admin user ready. Login at /admin/login.html' });
    
  } catch (err) {
    console.error('Setup error:', err);
    res.json({ success: false, error: err.message });
  }
});

// FIXED: Add phone column correctly
app.get('/api/fix-signup', async (req, res) => {
  try {
    // Check if phone column exists
    const [columns] = await db.promise().query(`
      SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'phone'
    `);
    
    if (columns.length === 0) {
      await db.promise().query(`ALTER TABLE users ADD COLUMN phone VARCHAR(20) NULL`);
      res.json({ success: true, message: 'Phone column added successfully!' });
    } else {
      res.json({ success: true, message: 'Phone column already exists.' });
    }
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

app.get('/api/reset-admin', async (req, res) => {
  try {
    // Hash for "admin123"
    const hashedPassword = '$2a$10$N9qo8uLOickgx2ZMRZoMy.MrJqGzYKFjJdj9M5qQYkIqWqZjvBJGm';
    
    await db.promise().query(`
      UPDATE users SET password = ? WHERE email = 'admin@toku.com'
    `, [hashedPassword]);
    
    res.json({ success: true, message: 'Admin password reset to: admin123' });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

app.get('/api/create-admin', async (req, res) => {
  try {
    // Create admin user
    const [result] = await db.promise().query(`
      INSERT INTO users (full_name, email, password, referral_code, is_admin, balance) 
      VALUES (
        'Super Admin', 
        'admin@toku.com', 
        '$2a$10$N9qo8uLOickgx2ZMRZoMy.MrJqGzYKFjJdj9M5qQYkIqWqZjvBJGm', 
        'ADMIN2024', 
        1, 
        0
      )
      ON DUPLICATE KEY UPDATE 
        is_admin = 1,
        password = '$2a$10$N9qo8uLOickgx2ZMRZoMy.MrJqGzYKFjJdj9M5qQYkIqWqZjvBJGm'
    `);
    
    // Verify admin was created
    const [admin] = await db.promise().query(`
      SELECT id, email, full_name, is_admin FROM users WHERE email = 'admin@toku.com'
    `);
    
    res.json({ 
      success: true, 
      message: 'Admin user created!',
      admin: admin[0]
    });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

app.get('/api/create-direct-admin', async (req, res) => {
  try {
    // First, let's see what's in the users table
    const [existing] = await db.promise().query(`SELECT * FROM users WHERE email = 'admin@toku.com'`);
    
    // Hash for "admin123"
    const hashedPassword = '$2a$10$N9qo8uLOickgx2ZMRZoMy.MrJqGzYKFjJdj9M5qQYkIqWqZjvBJGm';
    
    let result;
    if (existing.length > 0) {
      // Update existing user
      result = await db.promise().query(`
        UPDATE users 
        SET password = ?, is_admin = 1, full_name = 'Super Admin'
        WHERE email = 'admin@toku.com'
      `, [hashedPassword]);
      res.json({ 
        success: true, 
        action: 'updated',
        message: 'Admin user updated! Password: admin123'
      });
    } else {
      // Create new user
      result = await db.promise().query(`
        INSERT INTO users (full_name, email, password, referral_code, is_admin, balance) 
        VALUES ('Super Admin', 'admin@toku.com', ?, 'ADMIN001', 1, 0)
      `, [hashedPassword]);
      res.json({ 
        success: true, 
        action: 'created',
        message: 'Admin user created! Password: admin123'
      });
    }
    
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});
// ── Start Server ──────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});