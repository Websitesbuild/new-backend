import express from "express";
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import pg from 'pg';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github2';
import { Strategy as DiscordStrategy } from 'passport-discord';
import { Strategy as LocalStrategy } from 'passport-local';
import jwt from 'jsonwebtoken';

const app = express();
const port = 5000;

dotenv.config();

const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middleware
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://frontend-app-inky-three.vercel.app'
  ],
  credentials: true,
}));
app.use(express.json());

// JWT middleware
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ success: false, message: 'Invalid token' });
      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ success: false, message: 'No token provided' });
  }
}

// Passport strategies (unchanged, except for callback handling)
passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, async (email, password, done) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE usr_email = $1', [email]);
    const user = result.rows[0];
    if (!user) return done(null, false, { message: 'User not found' });

    const match = await bcrypt.compare(password, user.usr_password);
    if (!match) return done(null, false, { message: 'Incorrect password' });

    done(null, user);
  } catch (err) {
    done(err);
  }
}));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "https://new-backend-3jbn.onrender.com/auth/google/callback",
  passReqToCallback: true,
}, async (request, accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    const result = await pool.query('SELECT * FROM users WHERE usr_email = $1', [email]);
    let user = result.rows[0];
    if (!user) {
      const insertResult = await pool.query(
        'INSERT INTO users (usr_email, usr_password) VALUES ($1, $2) RETURNING *',
        [email, null]
      );
      user = insertResult.rows[0];
    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: "https://new-backend-3jbn.onrender.com/auth/github/callback",
  passReqToCallback: true
}, async (request, accessToken, refreshToken, profile, done) => {
  try {
    let email;
    if (profile.emails && profile.emails.length > 0) {
      email = profile.emails[0].value;
    } else {
      const res = await fetch('https://api.github.com/user/emails', {
        headers: {
          Authorization: `token ${accessToken}`,
          'User-Agent': 'Node.js',
        }
      });
      const emails = await res.json();
      const primaryEmail = emails.find(e => e.primary && e.verified);
      if (primaryEmail) {
        email = primaryEmail.email;
      } else {
        return done(new Error('No verified email found from GitHub'), null);
      }
    }
    const result = await pool.query('SELECT * FROM users WHERE usr_email = $1', [email]);
    let user = result.rows[0];
    if (!user) {
      const insertResult = await pool.query(
        'INSERT INTO users (usr_email, usr_password) VALUES ($1, $2) RETURNING *',
        [email, null]
      );
      user = insertResult.rows[0];
    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: "https://new-backend-3jbn.onrender.com/auth/discord/callback",
  scope: ['identify', 'email'],
  passReqToCallback: true
}, async (request, accessToken, refreshToken, profile, done) => {
  try {
    let email;
    if (profile.emails && profile.emails.length > 0) {
      email = profile.emails[0].value;
    } else {
      const res = await fetch('https://discord.com/api/users/@me', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'User-Agent': 'Node.js',
        }
      });
      const userData = await res.json();
      if (userData.email) {
        email = userData.email;
      } else {
        return done(new Error('No email found from Discord'), null);
      }
    }
    const result = await pool.query('SELECT * FROM users WHERE usr_email = $1', [email]);
    let user = result.rows[0];
    if (!user) {
      const insertResult = await pool.query(
        'INSERT INTO users (usr_email, usr_password) VALUES ($1, $2) RETURNING *',
        [email, null]
      );
      user = insertResult.rows[0];
    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

app.use(passport.initialize());

// ROUTES
app.get('/', (req, res) => {
  res.json([1, 2, 3, 4, 5]);
});

// Register
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (usr_email, usr_password) VALUES ($1, $2) RETURNING *',
      [email, hash]
    );
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error registering user', error: err.message });
  }
});

// Local login (returns JWT)
app.post('/login', (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err || !user) {
      return res.status(401).json({ success: false, message: info?.message || 'Login failed' });
    }
    // Create JWT
    const token = jwt.sign(
      { usr_id: user.usr_id, usr_email: user.usr_email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    const { usr_password, ...userData } = user;
    res.json({ success: true, user: userData, token });
  })(req, res, next);
});

// Google OAuth
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login', session: false }),
  (req, res) => {
    // Issue JWT and send to frontend (e.g., via query param or HTML postMessage)
    const token = jwt.sign(
      { usr_id: req.user.usr_id, usr_email: req.user.usr_email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    res.send(`
      <html>
        <body>
          <script>
            window.opener.postMessage({ success: true, token: "${token}" }, "https://frontend-app-inky-three.vercel.app");
            setTimeout(() => window.close(), 500);
          </script>
        </body>
      </html>
    `);
  }
);

// GitHub OAuth
app.get('/auth/github',
  passport.authenticate('github', { scope: ['user:email'] })
);

app.get('/auth/github/callback',
  passport.authenticate('github', { failureRedirect: '/login', session: false }),
  (req, res) => {
    const token = jwt.sign(
      { usr_id: req.user.usr_id, usr_email: req.user.usr_email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    res.send(`
      <html>
        <body>
          <script>
            window.opener && window.opener.focus();
            window.opener.postMessage({ success: true, token: "${token}" }, "https://frontend-app-inky-three.vercel.app");
            window.close();
          </script>
        </body>
      </html>
    `);
  }
);

// Discord OAuth
app.get('/auth/discord',
  passport.authenticate('discord', { scope: ['identify', 'email'] })
);

app.get('/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/login', session: false }),
  (req, res) => {
    const token = jwt.sign(
      { usr_id: req.user.usr_id, usr_email: req.user.usr_email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    res.send(`
      <html>
        <body>
          <script>
            window.opener.postMessage({ success: true, token: "${token}" }, "https://frontend-app-inky-three.vercel.app");
            window.close();
          </script>
        </body>
      </html>
    `);
  }
);

// Auth user (protected route)
app.get('/auth/user', authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE usr_id = $1', [req.user.usr_id]);
    if (!result.rows.length) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    const { usr_password, ...user } = result.rows[0];
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error fetching user', error: err.message });
  }
});

// Logout (client just deletes JWT)
app.get('/auth/logout', (req, res) => {
  res.redirect('https://frontend-app-inky-three.vercel.app');
});

// All other routes remain the same, but protect them with authenticateJWT if needed
// Example:
// app.get('/project/:id', authenticateJWT, async (req, res) => { ... });

app.get('/project/:id', authenticateJWT, async (req, res) => {
  const id = req.params.id;
  try {
    // Fetch the project by proj_id
    const result = await pool.query(
      'SELECT * FROM projects WHERE proj_id = $1',
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Project not found' });
    }
    res.status(200).json({ success: true, project: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error fetching project', error: err.message });
  }
});

// Get member by mem_id
app.get('/member/:id', authenticateJWT, async (req, res) => {
  const id = req.params.id;
  try {
    const result = await pool.query(
      'SELECT * FROM members WHERE mem_id = $1',
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Member not found' });
    }
    res.status(200).json({ success: true, member: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error fetching member', error: err.message });
  }
});

// Get upcoming project by id (assuming you have an upcoming_projects table)
app.get('/upcoming/:id', authenticateJWT, async (req, res) => {
  const id = req.params.id;
  try {
    const result = await pool.query(
      'SELECT * FROM upcoming_projects WHERE id = $1',
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Upcoming project not found' });
    }
    res.status(200).json({ success: true, upcoming: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error fetching upcoming project', error: err.message });
  }
});




app.get("/allMember", authenticateJWT, async (req, res) => {
  try {
    // Join members with users to get user email as well
    const result = await pool.query(`SELECT DISTINCT ON (usr_name) *
FROM members
ORDER BY usr_name, mem_id;
`);
    res.json({ success: true, members: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error fetching members', error: err.message });
  }
});

// ...existing code...

app.get("/allProjects", authenticateJWT, async (req, res) => {
  try {
    // Join projects with members to get member info if needed
    const result = await pool.query(`SELECT * FROM projects`);
    res.json({ success: true, projects: result.rows });
  } catch (err) {
    console.log(err)
    res.status(500).json({ success: false, message: 'Error fetching projects', error: err.message });
  }
})

app.get("/form/data", authenticateJWT, async(req,res)=>{
  try {
    const result = await pool.query("SELECT proj_id,proj_Name from projects");
    res.json({success:true,data:result.rows})
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error fetching projects', error: err.message });
  }
  
})



app.get('/project/:id/members', authenticateJWT, async (req, res) => {
  const projectId = req.params.id;
  try {
    const result = await pool.query(
      `SELECT m.*
       FROM members m
       JOIN member_projects mp ON m.mem_id = mp.mem_id
       WHERE mp.proj_id = $1`,
      [projectId]
    );
    res.json({ success: true, members: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error fetching members', error: err.message });
  }
});





app.post("/add/project", authenticateJWT, async (req, res) => {
  const { name, description, status, price, material, datetime } = req.body;
  // Use the datetime from the request if provided, otherwise use current time
    const date = datetime ? new Date(datetime) : new Date(); // fallback to now if not provided

  try {
    const result = await pool.query(
      `INSERT INTO projects(proj_Name, proj_Desc, status, price, material, date)
       VALUES($1, $2, $3, $4, $5, $6) RETURNING *`,
      [name, description, status, price, material, date]
    );
    res.json({ success: true, project: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error adding project', error: err.message });
  }
});

app.post("/add/member", authenticateJWT, async (req, res) => {
  const { usr_name, address, phone, proj_id } = req.body;
  if (!proj_id) {
    return res.status(400).json({ success: false, message: "Project is required for member" });
  }
  try {
    // Insert member without proj_id
    const result = await pool.query(
      `INSERT INTO members (usr_name, address, phone)
       VALUES ($1, $2, $3) RETURNING *`,
      [usr_name, address, phone]
    );
    const member = result.rows[0];
    // Add to member_projects
    await pool.query(
      'INSERT INTO member_projects (mem_id, proj_id) VALUES ($1, $2)',
      [member.mem_id, proj_id]
    );
    res.json({ success: true, member });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error adding member', error: err.message });
  }
});



app.delete('/delete/project/:id', authenticateJWT, async (req, res) => {
  const id = req.params.id;
  try {
    // Delete all related records first
    await pool.query('DELETE FROM member_projects WHERE proj_id = $1', [id]);
    await pool.query('DELETE FROM member_piece_history WHERE proj_id = $1', [id]);
    await pool.query('DELETE FROM member_payments WHERE proj_id = $1', [id]);
    // If you have members that should be deleted only if they belong exclusively to this project, handle that logic here

    // Now delete the project
    const result = await pool.query(
      'DELETE FROM projects WHERE proj_id = $1 RETURNING *',
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Project not found' });
    }
    res.json({ success: true, message: 'Project deleted successfully', project: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error deleting project', error: err.message });
  }
});


// Add a new piece record for a member in a project
app.post('/member/:mem_id/piece-history', authenticateJWT, async (req, res) => {
  const mem_id = req.params.mem_id;
  const { proj_id, piece_count, completed_at } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO member_piece_history (mem_id, proj_id, piece_count, completed_at)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [mem_id, proj_id, piece_count, completed_at || new Date()]
    );
    res.json({ success: true, record: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error adding piece record', error: err.message });
  }
});

// Get piece history for a member (optionally filter by project)
app.get('/member/:mem_id/piece-history', authenticateJWT, async (req, res) => {
  const mem_id = req.params.mem_id;
  const { proj_id } = req.query; // optional
  try {
    let result;
    if (proj_id) {
      result = await pool.query(
        'SELECT * FROM member_piece_history WHERE mem_id = $1 AND proj_id = $2 ORDER BY completed_at DESC',
        [mem_id, proj_id]
      );
    } else {
      result = await pool.query(
        'SELECT * FROM member_piece_history WHERE mem_id = $1 ORDER BY completed_at DESC',
        [mem_id]
      );
    }
    res.json({ success: true, history: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error fetching piece history', error: err.message });
  }
});



// Returns members not enrolled in the given project
app.get('/members/available', authenticateJWT, async (req, res) => {
  const exclude_proj_id = req.query.exclude_proj_id;
  try {
    const result = await pool.query(
      `SELECT * FROM members WHERE mem_id NOT IN (
         SELECT mem_id FROM members WHERE proj_id = $1
       )`,
      [exclude_proj_id]
    );
    res.json({ success: true, members: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error fetching available members', error: err.message });
  }
});

app.put('/member/:mem_id/edit', authenticateJWT, async (req, res) => {
  const mem_id = req.params.mem_id;
  const { usr_name, address, phone } = req.body;
  try {
    const result = await pool.query(
      'UPDATE members SET usr_name = $1, address = $2, phone = $3 WHERE mem_id = $4 RETURNING *',
      [usr_name, address, phone, mem_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: "Member not found" });
    }
    res.json({ success: true, member: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error updating member', error: err.message });
  }
});

// Add an existing member to a project
app.post('/member/:mem_id/add-to-project', authenticateJWT, async (req, res) => {
  const mem_id = req.params.mem_id;
  const { proj_id } = req.body;
  if (!proj_id) {
    return res.status(400).json({ success: false, message: "Project ID is required" });
  }
  try {
    await pool.query(
      'INSERT INTO member_projects (mem_id, proj_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [mem_id, proj_id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error adding member to project', error: err.message });
  }
});

// Remove member from a specific project (set proj_id to NULL)
app.put('/member/:mem_id/remove-from-project', authenticateJWT, async (req, res) => {
  const mem_id = req.params.mem_id;
  const { proj_id } = req.body;
  try {
    await pool.query(
      'DELETE FROM member_projects WHERE mem_id = $1 AND proj_id = $2',
      [mem_id, proj_id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error removing member from project', error: err.message });
  }
});


// Add a payment for a member
app.post('/member/:mem_id/payments', authenticateJWT, async (req, res) => {
  const mem_id = req.params.mem_id;
  const { proj_id, amount, remarks } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO member_payments (mem_id, proj_id, amount, remarks)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [mem_id, proj_id, amount, remarks || null]
    );
    res.json({ success: true, payment: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error adding payment', error: err.message });
  }
});

// Get payment history for a member in a project
app.get('/member/:mem_id/payments', authenticateJWT, async (req, res) => {
  const mem_id = req.params.mem_id;
  const { proj_id } = req.query;
  try {
    const result = await pool.query(
      `SELECT * FROM member_payments WHERE mem_id = $1 AND proj_id = $2 ORDER BY paid_at DESC`,
      [mem_id, proj_id]
    );
    res.json({ success: true, payments: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error fetching payments', error: err.message });
  }
});

app.get('/member/:mem_id/projects', authenticateJWT, async (req, res) => {
  const mem_id = req.params.mem_id;
  try {
    const result = await pool.query(
      `SELECT p.* FROM projects p
       JOIN member_projects mp ON p.proj_id = mp.proj_id
       WHERE mp.mem_id = $1`,
      [mem_id]
    );
    res.json({ success: true, projects: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error fetching projects for member', error: err.message });
  }
});

app.get('/projects/available', authenticateJWT, async (req, res) => {
  const mem_id = req.query.mem_id;
  try {
    // Get the project the member is already enrolled in
    const memberRes = await pool.query('SELECT proj_id FROM members WHERE mem_id = $1', [mem_id]);
    const enrolledProjId = memberRes.rows.length > 0 ? memberRes.rows[0].proj_id : null;
    let result;
    if (enrolledProjId) {
      result = await pool.query('SELECT * FROM projects WHERE proj_id != $1', [enrolledProjId]);
    } else {
      result = await pool.query('SELECT * FROM projects');
    }
    res.json({ success: true, projects: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error fetching available projects', error: err.message });
  }
});

// filepath: d:\Web Development\React\my-work-app\server\index.js
app.delete('/member/:mem_id', authenticateJWT, async (req, res) => {
  const mem_id = req.params.mem_id;
  try {
    await pool.query('DELETE FROM member_projects WHERE mem_id = $1', [mem_id]);
    await pool.query('DELETE FROM member_piece_history WHERE mem_id = $1', [mem_id]);
    await pool.query('DELETE FROM member_payments WHERE mem_id = $1', [mem_id]);
    await pool.query('DELETE FROM members WHERE mem_id = $1', [mem_id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error deleting member', error: err.message });
  }
});


app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});