import { Router } from 'express';
import { SuperAdminController } from '../controllers/superAdmin.controller';
import { requireSuperAdmin, verifyToken } from "../middlewares/auth.middleware";
import { ipRateLimiter } from '../middlewares/ip-lateLimmter';


const superAdminRouter = Router();
const superAdminController = new SuperAdminController();
superAdminRouter.post('/login', ipRateLimiter, superAdminController.login.bind(superAdminController));
superAdminRouter.post('/forgotPassword', superAdminController.forgotPassword.bind(superAdminController));
superAdminRouter.post('/resetPassword', superAdminController.resetPassword.bind(superAdminController));
superAdminRouter.post('/refreshToken', superAdminController.refreshToken.bind(superAdminController));
superAdminRouter.post("/subadmin", verifyToken, requireSuperAdmin, superAdminController.createSubAdmin.bind(superAdminController));

export default superAdminRouter;