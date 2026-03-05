const { signJWT, verifyJWT, cors } = require('./_utils');

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const token = req.body?.refresh_token;
  if (!token) return res.status(400).json({ success: false, message: '缺少 refresh_token' });

  const payload = verifyJWT(token);
  if (!payload || payload.type !== 'refresh') {
    return res.status(401).json({ success: false, message: 'Token 无效或已过期，请重新登录' });
  }

  const access_token  = signJWT({ sub: payload.sub, username: payload.username, role: payload.role }, 3600);
  const refresh_token = signJWT({ sub: payload.sub, username: payload.username, type: 'refresh' }, 86400 * 30);

  return res.status(200).json({
    success: true,
    data: { access_token, refresh_token, token_type: 'bearer' },
  });
};
