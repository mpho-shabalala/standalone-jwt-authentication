module.exports = function restrictTo(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ status: 'fail', statusCode: 403, message: 'Permission denied' });
    }
    next();
  };
};