import { Router } from "express"
import { registerUser , logOutUser , loginUser ,refreshAccessToken , changeCurrentPassword,updateAccountDetails,getCurrentUser,verifyOTP} from "../controllors/user.controllor.js"
import { upload } from "../middlewares/multer.midddleware.js"   
import { verifyJWT } from "../middlewares/auth.middleware.js"
import { checkUser } from "../middlewares/openRouteAuth.middlewear.js"

const router = Router()

router.route('/register').post(registerUser)
router.route('/verify-otp').post(verifyOTP)
router.route('/login').post(loginUser)

// secured routes
router.route('/logout').post(verifyJWT,logOutUser)
router.route('/refresh-token').post(refreshAccessToken)
router.route("/change-password").patch(verifyJWT, changeCurrentPassword);
router.route("/update-profile").patch(verifyJWT, updateAccountDetails);
router.route("/get-current-user").get(verifyJWT, getCurrentUser);




export default router