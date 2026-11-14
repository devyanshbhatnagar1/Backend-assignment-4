const jwt = require('jsonwebtoken');

// Parses the Cookie header manually (cookie-parser is not an allowed library).
function getCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  const match = header.split(';').map((c) => c.trim()).find((c) => c.startsWith(name + '='));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : null;
}

// Token can come from "Authorization: Bearer <token>" or the "token" cookie.
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  const token =
    (authHeader && authHeader.startsWith('Bearer ') && authHeader.slice(7)) ||
    getCookie(req, 'token');

  if (!token) return res.status(403).json({ message: 'No token provided' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET); // { id, role, iat, exp }
    next();
  } catch (err) {
    const message = err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token';
    return res.status(401).json({ message });
  }
}

// RBAC: allow only the listed roles.
function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied: insufficient permissions' });
    }
    next();
  };
}

module.exports = { authenticate, authorizeRoles };
