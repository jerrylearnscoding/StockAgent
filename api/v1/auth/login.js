const { signJWT, checkPwd, kvGet, cors } = require('./_utils');

// Demo accounts (always available even without KV)
const DEMO_USERS = {
  admin: { id: 'u_admin', username: 'admin', nickname: '管理员', email: 'admin@stockagent.ai', password_hash: null, role: 'admin', _demoPwd: 'admin123' },
  demo:  { id: 'u_demo',  username: 'demo',  nickname: '演示用户', email: 'demo@stockagent.ai', password_hash: null, role: 'user',  _demoPwd: 'demo123' },
};

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ detail: '方法不允许' });

  // Accept both form-urlencoded and JSON
  let username, password;
  const ct = req.headers['content-type'] || '';
  if (ct.includes('urlencoded')) {
    // Vercel may parse as object or leave as string
    if (typeof req.body === 'object' && req.body !== null) {
      username = req.body.username;
      password = req.body.password;
    } else {
      const params = new URLSearchParams(req.body || '');
      username = params.get('username');
      password = params.get('password');
    }
  } else {
    username = req.body?.username;
    password = req.body?.password;
  }

  if (!username || !password) {
    return res.status(422).json({ detail: '用户名和密码不能为空' });
  }

  // Check demo accounts first
  let user = null;
  const demo = DEMO_USERS[username];
  if (demo && password === demo._demoPwd) {
    user = demo;
  } else {
    // Check KV registered users
    const stored = await kvGet(`user:${username}`);
    if (stored && checkPwd(password, stored.password_hash)) {
      user = stored;
    }
  }

  if (!user) {
    return res.status(401).json({ detail: '用户名或密码错误' });
  }

  const { password_hash, _demoPwd, ...safeUser } = user;
  const access_token  = signJWT({ sub: user.id, username: user.username, role: user.role }, 3600);
  const refresh_token = signJWT({ sub: user.id, username: user.username, type: 'refresh' }, 86400 * 30);

  return res.status(200).json({
    success: true,
    data: {
      access_token,
      refresh_token,
      token_type: 'bearer',
      user: safeUser,
    },
    message: '登录成功',
  });
};
