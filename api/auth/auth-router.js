const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");

const bcrypt = require("bcryptjs");
const tokenBuilder = require("./token-builder");
const Users = require("../users/users-model");

router.post("/register", validateRoleName, (req, res, next) => {
  let user = req.body;

  // bcrypting the password before saving
  const rounds = process.env.BCRYPT_ROUNDS || 8; // 2 ^ 8
  const hash = bcrypt.hashSync(user.password, rounds);

  user.password = hash;
  Users.add(user)
    .then((saved) => {
      res.status(201).json(saved);
    })
    .catch(next);
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  let { password } = req.body;
  const [user] = req.user;

  if (user && bcrypt.compareSync(password, user.password)) {
    const token = tokenBuilder(user);
    res.status(200).json({
      message: `${user.username} is back!`,
      token,
    });
  } else {
    next({ status: 401, message: "Invalid Credentials" });
  }
});

module.exports = router;
