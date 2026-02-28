import { Router } from 'express';
import { SuperAdminController } from '../controllers/superAdmin.controller';

const superAdminRouter = Router();
const superAdminController = new SuperAdminController();
superAdminRouter.post('/login', superAdminController.login.bind(superAdminController));

export default superAdminRouter;