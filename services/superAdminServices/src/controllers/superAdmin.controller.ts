import { Request, Response } from 'express';
import { email, z } from 'zod';
import AuthService from '../service/superAdmin.service';
import { superAdminSchema } from '../schemas/superAdminSchema';
import { id } from 'zod/v4/locales';

 

export class AuthController {
   private authService: AuthService;

  constructor() {
    this.authService = new AuthService();
  }
 
  async login(req: Request, res: Response): Promise<any> {
    
  }

  async logout(req: Request, res: Response): Promise<any> {
    
  }
}