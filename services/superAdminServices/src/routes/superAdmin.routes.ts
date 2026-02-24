import { Router } from 'express';
import { AuthController } from '../controllers/superAdmin.controller';

const authRouter = Router();
const authController = new AuthController();
authRouter.post('/login', authController.login.bind(authController));
authRouter.post('/logout', authController.logout.bind(authController));

export { authRouter };