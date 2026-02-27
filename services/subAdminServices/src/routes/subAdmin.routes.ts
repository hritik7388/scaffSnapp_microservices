import { Router } from 'express';
import { SubAdminController } from '../controller/subAdmin.controller';

const subAdminRouter = Router();
const subAdminController = new SubAdminController();
subAdminRouter.post('/register',subAdminController.register.bind(subAdminController))
subAdminRouter.post('/login', subAdminController.login.bind(subAdminController));

export default subAdminRouter;