const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const db = require("../users/users-model");

const restricted = (req, res, next) => {
  try {
    const token = req.headers.authorization;
    !token && next({ status: 401, message: "Token required" });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        return next({
          status: 401,
          message: "Token invalid",
          realErrorMessage: err.message,
        });
      }
      req.decodedJwt = decoded;
      next();
    });
  } catch (error) {
    next(error);
  }
};

const only = (role_name) => (req, res, next) => {
  req.decodedJwt.role_name === role_name
    ? next()
    : next({ status: 403, message: "This is not for you" });
};

const checkUsernameExists = async (req, res, next) => {
  try {
    const { username } = req.body;
    const user = await db.findBy({ username });

    if (user) {
      req.user = user;
      next();
    } else {
      next({ message: "Invalid credentials", status: 401 });
    }
  } catch (error) {
    next(error);
  }
};

const validateRoleName = async (req, res, next) => {
  if (req.body.role_name && req.body.role_name.trim()) {
    req.body.role_name = req.body.role_name.trim();
    let role_name = req.body.role_name;

    if (role_name === "admin") {
      next({ status: 422, message: "Role name can not be admin" });
    } else if (role_name.length > 32) {
      next({
        status: 422,
        message: "Role name can not be longer than 32 chars",
      });
    }
    req.role_name = role_name;
    next();
  } else {
    req.body.role_name = "student";
    next();
  }
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
