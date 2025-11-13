import asyncHandler from 'express-async-handler'
import User from '../models/userModel.js'
import jwt from 'jsonwebtoken'

const protect = asyncHandler(async (req, res, next) => {
  const token = req.cookies?.jwt

  if (!token) {
    console.log('no token')
    res.status(401)
    throw new Error('Not authorized, no token')
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.user = await User.findById(decoded.id).select('-password')
    next()
  } catch (error) {
    console.error('Token verification failed:', error.message)
    res.status(401)
    throw new Error('Not authorized, invalid token')
  }
})

export { protect }
