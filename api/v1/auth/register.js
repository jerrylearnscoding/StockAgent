const { signJWT, hashPwd, kvGet, kvSet, cors } = require('./_utils');

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ success: false, message: '方法不允许' });

  const { username, password, email, nickname } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ success: false, message: '用户名和密码不能为空' });
  }
  if (username.length < 3) return res.status(400).json({ success: false, message: '用户名至少3位' });
  if (password.length < 6) return res.status(400).json({ success: false, message: '密码至少6位' });

  // Check existing user
  const existing = await kvGet(`user:${username}`);
  if (existing) return res.status(400).json({ success: false, message: '用户名已存在' });

  const user = {
    id: `u_${Date.now().toString(36)}`,
    username,
    email: email || '',
    nickname: nickname || username,
    password_hash: hashPwd(password),
    role: 'user',
    created_at: new Date().toISOString(),
  };

  await kvSet(`user:${username}`, user);

  const { password_hash, ...safeUser } = user;
  const access_token  = signJWT({ sub: user.id, username, role: user.role }, 3600);
  const refresh_token = signJWT({ sub: user.id, username, type: 'refresh' }, 86400 * 30);

  return res.status(200).json({
    success: true,
    data: {
      access_token,
      refresh_token,
      token_type: 'bearer',
      user: safeUser,
    },
    message: '注册成功',
  });
};
