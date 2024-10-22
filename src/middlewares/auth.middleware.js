import { ApiError } from "../utils/AipError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from 'jsonwebtoken'
import { User } from "../models/user.model.js";


export const verifyJWT = asyncHandler(async(req,res,next)=>
    {
        /*all we have to do:
            - get the hold on access token
            - generate a decoded object 
            - query the db to find the object with this id od decoded object
            - add that decoded object to the req (req.user)    
        */ 
        try {
            const token = req.cookies?.accessToken || req.header('Authorization')?.replace('Bearer','')
    
            if (!token) {
                throw new ApiError(401,'Unauthorized request')
            }
            // this will give a decoded object 
            const decodedToken = jwt.verify(token,process.env.ACCESS_TOKEN_SECRET)
    
            const user = await User.findById(decodedToken?._id).select('-password ')
    
            if (!user) {
                throw new ApiError(401,'Invalid access token')
            }
    
            req.user = user
    
            next()
        } catch (error) {
            throw new ApiError(401, error?.message || 'Invalid access token')
        }
    })