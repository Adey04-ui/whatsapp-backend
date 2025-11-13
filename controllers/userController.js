import asyncHandler from 'express-async-handler'
import User from '../models/userModel.js'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

// Generate JWT
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '7d' })
}

// ==================== REGISTER ====================
const register = asyncHandler(async (req, res) => {
    const { name, email, phone, password } = req.body
  
    if (!name || !email || !phone || !password) {
      res.status(400)
      throw new Error('Please fill all fields')
    }
  
    const emailExists = await User.findOne({ email })
    const phoneExists = await User.findOne({ phone })

  
    if (emailExists) {
      res.status(400)
      throw new Error('Email already exists')
    }
    if (phoneExists) {
      res.status(400)
      throw new Error('Phone number already exists')
    }
  
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)
    
    if(!emailExists && !phoneExists){
      const profilePic = req.file?.path || 'https://res.cloudinary.com/dv2vh9w5o/image/upload/v1762165292/exc5prniqk1rpenkqqto.png'
    
      const user = await User.create({
        name,
        email,
        phone,
        password: hashedPassword,
        profilePic,
      })
      if (!user) {
        res.status(400)
        throw new Error('Unable to register user')
      }
    
      // Generate and set cookie BEFORE sending response
      const token = generateToken(user._id)
      res.cookie('jwt', token, {
        httpOnly: true,
        secure: true, // set to true in production
        sameSite: 'none',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      })
    
      res.status(201).json({
        _id: user.id,
        name: user.name,
        email: user.email,
        profilePic: user.profilePic,
      })
    }
  
})

// ==================== LOGIN ====================
const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body

  if(!email || email.trim() === "") {
    res.status(400)
    throw new Error('Please provide email')
  }

  if(!password || password.trim() === "") {
    res.status(400)
    throw new Error('Please provide password')
  }

  const user = await User.findOne({ email })
  if (!user) {
    res.status(400)
    throw new Error('Email does not exist')
  }

  const passwordMatch = await bcrypt.compare(password, user.password)
  if (!passwordMatch) {
    res.status(400)
    throw new Error('Invalid password')
  }

  const token = generateToken(user._id)
  res.cookie('jwt', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  })

  res.status(200).json({
    _id: user.id,
    name: user.name,
    email: user.email,
    profilePic: user.profilePic,
  })
})

// ==================== GET ME ====================
const getMe = asyncHandler(async (req, res) => {
  res.status(200).json({
    _id: req.user.id,
    name: req.user.name,
    email: req.user.email,
    profilePic: req.user.profilePic,
  })
})

// ==================== GET ALL ====================
const getAll = asyncHandler(async (req, res) => {
  const users = await User.find({})
  if (!users.length) {
    res.status(404)
    throw new Error('No users found')
  }
  res.status(200).json(users)
})

// ==================== LOG OUT ====================
const logout = asyncHandler(async (req, res) => {
  res.cookie("jwt", "", {
    httpOnly: true,
    expires: new Date(0),
    sameSite: "lax",
    secure: false
  })
  res.status(200).json({ message: "Logged out successfully" })
})

export { register, login, getMe, getAll, logout }
