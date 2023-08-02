const express = require('express')
const router = express.Router()

const passport = require('passport')
const bcrypt = require('bcryptjs')

const db = require('../../models')
const User = db.User

router.get('/login', (req, res) => {
  const userInput = req.session.userInput || {}
  delete req.session.userInput
  const login_error_msg = req.flash('error')
  return res.render('login', {
    login_error_msg,
    email: userInput.email
  })
})
//加入 middleware , 驗證 request 登入狀態
router.post('/login',
  (req, res, next) => {
    req.session.userInput = req.body
    next()
  }, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/users/login',
    failureFlash: true
  }))

router.get('/register', (req, res) => {
  res.render('register')
})

router.post('/register', (req, res) => {
  const { name, email, password, confirmPassword } = req.body
  const errors = []
  if (!name | !email | !password | !confirmPassword) {
    errors.push({ message: `所有欄位都是必填。` })
  }
  if (password !== confirmPassword) {
    errors.push({ message: `密碼與確認密碼不相符!` })
  }
  User.findOne({ where: { email } }).then(user => {
    if (user) {
      errors.push({ message: `這個Email已經註冊過了` })
    }
    if (errors.length) {
      return res.render('register', {
        errors,
        name,
        email,
        password,
        confirmPassword
      })
    }
    return bcrypt
      .genSalt(10)
      .then(salt => bcrypt.hash(password, salt))
      .then(hash => User.create({
        name,
        email,
        password: hash
      }))
      .then(() => res.redirect('/users/login'))
      .catch(err => console.log(err))
  })
})

router.get('/logout', (req, res) => {
  req.logout()
  req.flash('success_msg', '你已經成功登出')
  res.redirect('/users/login')
})

module.exports = router