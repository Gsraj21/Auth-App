const ensureAuthenticated = require('../Middlewares/Auth');

const router = require('express').Router();

router.get('/', ensureAuthenticated, (req, res) => {
    console.log("detail of user", req.user);
    res.status(200).json({
        msg:"welcome to the main page"
    })
});

module.exports = router;