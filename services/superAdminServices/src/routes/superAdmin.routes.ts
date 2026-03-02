import { Router } from 'express';
import { SuperAdminController } from '../controllers/superAdmin.controller';

const superAdminRouter = Router();
const superAdminController = new SuperAdminController();
superAdminRouter.post('/login', superAdminController.login.bind(superAdminController));
superAdminRouter.post('/forgotPassword', superAdminController.forgotPassword.bind(superAdminController));
superAdminRouter.post('/resetPassword', superAdminController.resetPassword.bind(superAdminController));
superAdminRouter.post('/refreshToken', superAdminController.refreshToken.bind(superAdminController));

export default superAdminRouter;