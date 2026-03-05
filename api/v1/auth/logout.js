const { cors } = require('./_utils');
module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  return res.status(200).json({ success: true, message: '已登出' });
};
