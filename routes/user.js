const router = require('express').Router();
const ctrl = require('../controllers');
const passport = require('passport');
const { session } = require('passport');

router.get('/test', ctrl.user.test);
router.post('/register', ctrl.user.register);
router.post('/login', ctrl.user.login)
router.get('/profile', passport.authenticate('jwt', { session: false}), ctrl.user.profile)

module.exports = router;