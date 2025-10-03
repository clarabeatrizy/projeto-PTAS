const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ mensagem: 'Token não fornecido', erro: true });

  const [scheme, token] = authHeader.split(' ');
  if (!/^Bearer$/i.test(scheme)) {
    return res.status(401).json({ mensagem: 'Formato inválido', erro: true });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    return next();
  } catch (err) {
    return res.status(401).json({ mensagem: 'Token inválido ou expirado', erro: true });
  }
}

module.exports = authMiddleware;
