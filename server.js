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
// Database connection (works with both local and cloud)
let db;
if (process.env.DATABASE_URL) {
  // For cloud deployment (TiDB Cloud)
  db = mysql.createConnection(process.env.DATABASE_URL);
} else {
  // For local development
  db = mysql.createConnection({
    host:     process.env.DB_HOST || 'localhost',
    user:     process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'toku_app'
  });
}

db.connect(err => {
  if (err) console.error('❌ DB Error:', err.message);
  else     console.log('✅ Connected to MySQL');
});

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
        if (err) return res.status(500).json({ message: 'Database error' });
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
      name:          user.full_name,
      balance:       user.balance,
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

// Get all packages (single definition)
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
    const amount = pkg.price * 100; // Paystack uses kobo
    const ref = 'TOKU_' + Date.now() + '_' + req.user.id;

    // Save pending transaction
    db.query(
      'INSERT INTO transactions (user_id, package_id, amount, paystack_ref) VALUES (?,?,?,?)',
      [req.user.id, package_id, pkg.price, ref],
      (err) => {
        if (err) {
          console.error('Transaction insert error:', err);
          return res.status(500).json({ message: 'Could not create transaction' });
        }

        // Call Paystack API
        const params = JSON.stringify({
          email: req.user.email,
          amount: amount,
          reference: ref,
          callback_url: `${process.env.APP_URL || 'http://localhost:3000'}/user/verify.html`  // ✅ Hardcoded for local testing
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
                res.json({ 
                  authorization_url: response.data.authorization_url, 
                  reference: ref 
                });
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

// Verify payment (called from verify.html)
app.get('/api/pay/verify/:reference', authMiddleware, (req, res) => {
  const { reference } = req.params;
  const options = {
    hostname: 'api.paystack.co',
    port:     443,
    path:     `/transaction/verify/${reference}`,
    method:   'GET',
    headers:  { Authorization: `Bearer ${process.env.PAYSTACK_SECRET}` }
  };

  https.get(options, paystackRes => {
    let data = '';
    paystackRes.on('data', chunk => data += chunk);
    paystackRes.on('end', async () => {
      try {
        const response = JSON.parse(data);
        if (response.status && response.data.status === 'success') {
          // Get transaction
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

              // Mark transaction as successful
              await db.promise().query(
                'UPDATE transactions SET status = "success" WHERE paystack_ref = ?',
                [reference]
              );

              // Get package details
              const [pkgRows] = await db.promise().query(
                'SELECT * FROM packages WHERE id = ?', [tx.package_id]
              );
              if (!pkgRows.length) throw new Error('Package not found');
              const pkg = pkgRows[0];

              const today   = new Date();
              const endDate = new Date();
              endDate.setDate(today.getDate() + pkg.duration_days);

              // Create investment
              await db.promise().query(
                `INSERT INTO investments 
                 (user_id, package_id, amount, daily_return, start_date, end_date, days_claimed, last_claim_date)
                 VALUES (?, ?, ?, ?, ?, ?, 0, NULL)`,
                [req.user.id, tx.package_id, tx.amount, pkg.daily_return, today, endDate]
              );

              // Mark user as invested (for referral)
              await db.promise().query(
                'UPDATE users SET has_invested = 1 WHERE id = ?',
                [req.user.id]
              );

              // Handle referral bonus (only once per referred user)
              const [refRows] = await db.promise().query(
                `SELECT referred_by FROM users WHERE id = ? AND has_invested = 1 AND referred_by IS NOT NULL`,
                [req.user.id]
              );
              if (refRows.length > 0 && refRows[0].referred_by) {
                const referrerId = refRows[0].referred_by;
                const bonus = tx.amount * 0.10;
                // Check if bonus already paid
                const [existing] = await db.promise().query(
                  'SELECT id FROM referrals WHERE referred_id = ?', [req.user.id]
                );
                if (existing.length === 0) {
                  await db.promise().query(
                    'INSERT INTO referrals (referrer_id, referred_id, package_price, bonus_amount) VALUES (?,?,?,?)',
                    [referrerId, req.user.id, tx.amount, bonus]
                  );
                  await db.promise().query(
                    'UPDATE users SET balance = balance + ? WHERE id = ?',
                    [bonus, referrerId]
                  );
                }
              }

              res.json({ success: true, activated: true, message: 'Package activated!' });
            }
          );
        } else {
          await db.promise().query(
            'UPDATE transactions SET status = "failed" WHERE paystack_ref = ?',
            [reference]
          );
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
//  DAILY CLAIM (FIXED)
// ════════════════════════════════════════════════

app.post('/api/claim', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  try {
    // Get active investment (only one active allowed)
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
    if (hoursSince < 23.5) { // Allow 30 mins grace
      return res.status(400).json({ message: 'Already claimed within 24 hours. Come back later.' });
    }

    const amount = inv.daily_return;
    const newDaysClaimed = inv.days_claimed + 1;
    const isCompleted = newDaysClaimed >= (await getDurationDays(inv.package_id));

    // Begin transaction
    await db.promise().query('START TRANSACTION');

    // Insert claim record
    await db.promise().query(
      'INSERT INTO claims (user_id, investment_id, amount, claim_date) VALUES (?, ?, ?, NOW())',
      [userId, inv.id, amount]
    );

    // Update investment
    await db.promise().query(
      `UPDATE investments SET 
        days_claimed = ?, 
        last_claim_date = NOW(), 
        status = ? 
       WHERE id = ?`,
      [newDaysClaimed, isCompleted ? 'completed' : 'active', inv.id]
    );

    // Add to user balance
    await db.promise().query(
      'UPDATE users SET balance = balance + ? WHERE id = ?',
      [amount, userId]
    );

    await db.promise().query('COMMIT');

    res.json({
      message: `✅ ₦${amount} claimed successfully!`,
      amount,
      days_remaining: isCompleted ? 0 : (await getDurationDays(inv.package_id)) - newDaysClaimed
    });
  } catch (err) {
    await db.promise().query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: 'Claim failed. Try again.' });
  }
});

// Helper for package duration
async function getDurationDays(packageId) {
  const [rows] = await db.promise().query('SELECT duration_days FROM packages WHERE id = ?', [packageId]);
  return rows[0]?.duration_days || 7;
}

// Claim status endpoint (used by dashboard timer)
app.get('/api/user/claim-status', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  try {
    const [invRows] = await db.promise().query(
      `SELECT i.*, p.duration_days 
       FROM investments i 
       JOIN packages p ON i.package_id = p.id 
       WHERE i.user_id = ? AND i.status = 'active'`,
      [userId]
    );
    if (invRows.length === 0) {
      return res.json({ active: false });
    }
    const inv = invRows[0];
    const startDate = new Date(inv.last_claim_date || inv.start_date);
    const now = new Date();
    const nextClaimTime = new Date(startDate.getTime() + 24 * 60 * 60 * 1000);
    const countdown = Math.max(0, nextClaimTime - now);
    const canClaimNow = countdown === 0 ? 1 : 0;
    const pendingAmount = canClaimNow ? inv.daily_return : 0;

    res.json({
      active: true,
      canClaimNow,
      earningsPerPeriod: inv.daily_return,
      countdown,
      pendingAmount
    });
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
  if (!amount || !bank_name || !account_no || !account_name)
    return res.status(400).json({ message: 'All fields are required' });
  if (amount < 500)
    return res.status(400).json({ message: 'Minimum withdrawal is ₦500' });

  db.query('SELECT balance FROM users WHERE id = ?', [req.user.id], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    const balance = results[0].balance;
    if (balance < amount)
      return res.status(400).json({ message: 'Insufficient balance' });

    db.query('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, req.user.id], (err) => {
      if (err) return res.status(500).json({ message: 'Update failed' });
      db.query(
        'INSERT INTO withdrawals (user_id, amount, bank_name, account_no, account_name) VALUES (?,?,?,?,?)',
        [req.user.id, amount, bank_name, account_no, account_name],
        (err) => {
          if (err) return res.status(500).json({ message: 'Withdrawal request failed' });
          res.json({ message: 'Withdrawal request submitted! We will process it shortly.' });
        }
      );
    });
  });
});

app.get('/api/withdrawals', authMiddleware, (req, res) => {
  db.query(
    'SELECT * FROM withdrawals WHERE user_id = ? ORDER BY created_at DESC',
    [req.user.id],
    (err, results) => res.json(results)
  );
});

// ════════════════════════════════════════════════
//  REFERRAL & STATS
// ════════════════════════════════════════════════

app.get('/api/referrals', authMiddleware, (req, res) => {
  db.query(
    `SELECT r.*, u.full_name as referred_name, u.email as referred_email
     FROM referrals r
     JOIN users u ON u.id = r.referred_id
     WHERE r.referrer_id = ?
     ORDER BY r.created_at DESC`,
    [req.user.id],
    (err, results) => res.json(results)
  );
});

app.get('/api/claims', authMiddleware, (req, res) => {
  db.query(
    `SELECT c.*, p.name as package_name
     FROM claims c
     JOIN investments i ON i.id = c.investment_id
     JOIN packages p ON p.id = i.package_id
     WHERE c.user_id = ?
     ORDER BY c.created_at DESC`,
    [req.user.id],
    (err, results) => res.json(results)
  );
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
      total_invested:  inv[0][0].total        || 0,
      total_earned:    claims[0][0].total      || 0,
      total_withdrawn: withdrawals[0][0].total || 0,
      referral_earned: referrals[0][0].total   || 0,
    });
  }).catch(err => res.status(500).json({ error: 'Stats error' }));
});

// ════════════════════════════════════════════════
//  ADMIN ROUTES (simplified – keep your existing)
// ════════════════════════════════════════════════

// ════════════════════════════════════════════════
//  ADMIN ROUTES (FULLY CORRECTED)
// ════════════════════════════════════════════════

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  
  db.query('SELECT * FROM users WHERE email = ? AND is_admin = 1', [email], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(401).json({ message: 'Invalid admin credentials' });
    }
    
    const admin = results[0];
    const match = await bcrypt.compare(password, admin.password);
    
    if (!match) {
      return res.status(401).json({ message: 'Invalid admin credentials' });
    }
    
    const token = jwt.sign(
      { id: admin.id, name: admin.full_name, email: admin.email, isAdmin: true },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    
    res.json({ message: 'Admin login successful', token, isAdmin: true });
  });
});

// Admin Overview Dashboard Stats
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
  }).catch(err => {
    console.error('Admin overview error:', err);
    res.status(500).json({ error: 'Failed to load dashboard data' });
  });
});

// Get all withdrawals (for admin)
app.get('/api/admin/withdrawals', (req, res) => {
  db.query(
    `SELECT w.*, u.full_name, u.email FROM withdrawals w
     JOIN users u ON u.id = w.user_id
     ORDER BY w.created_at DESC`,
    (err, results) => {
      if (err) {
        console.error('Withdrawals error:', err);
        return res.status(500).json({ error: 'Failed to fetch withdrawals' });
      }
      res.json(results);
    }
  );
});

// Update withdrawal status (approve/reject)
app.post('/api/admin/withdrawals/:id', (req, res) => {
  const { status } = req.body;
  const withdrawalId = req.params.id;
  
  db.query('UPDATE withdrawals SET status = ? WHERE id = ?', [status, withdrawalId], (err) => {
    if (err) {
      console.error('Update error:', err);
      return res.status(500).json({ message: 'Update failed' });
    }
    
    // If rejected, refund the user
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

// Get all investments (for admin)
app.get('/api/admin/investments', (req, res) => {
  db.query(
    `SELECT i.*, u.full_name, u.email, p.name as package_name, p.duration_days
     FROM investments i
     JOIN users u ON u.id = i.user_id
     JOIN packages p ON p.id = i.package_id
     ORDER BY i.created_at DESC`,
    (err, results) => {
      if (err) {
        console.error('Investments error:', err);
        return res.status(500).json({ error: 'Failed to fetch investments' });
      }
      res.json(results);
    }
  );
});

// Get all users (for admin)
app.get('/api/admin/users', (req, res) => {
  db.query(
    `SELECT id, full_name, email, balance, has_invested, referral_code, created_at, is_admin
     FROM users 
     ORDER BY created_at DESC`,
    (err, results) => {
      if (err) {
        console.error('Users error:', err);
        return res.status(500).json({ error: 'Failed to fetch users' });
      }
      res.json(results);
    }
  );
});

//------------------
// Admin
//------------------


// Admin Login
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  
  db.query('SELECT * FROM users WHERE email = ? AND is_admin = 1', [email], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(401).json({ message: 'Invalid admin credentials' });
    }
    
    const admin = results[0];
    const match = await bcrypt.compare(password, admin.password);
    
    if (!match) {
      return res.status(401).json({ message: 'Invalid admin credentials' });
    }
    
    const token = jwt.sign(
      { id: admin.id, name: admin.full_name, email: admin.email, isAdmin: true },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    
    res.json({ message: 'Admin login successful', token, isAdmin: true });
  });
});
// ── Start Server ──────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});