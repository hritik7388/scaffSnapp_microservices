import { Request, Response } from 'express'; 
import AuthService from '../service/superAdmin.service';
import { superAdminSchema } from '../schemas/superAdminSchema';


export class AuthController {
  private authService: AuthService;

  constructor() {
    this.authService = new AuthService();
  }

  async login(req: Request, res: Response): Promise<any> {
    const ip =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      req.socket.remoteAddress ||
      '';

    const parseResult = superAdminSchema.parse(req.body);
    const userData = await this.authService.login(parseResult, ip);
    return res.status(200).json({
      message: userData.message,
      tokens: userData.tokens,
    });

  }

  async logout(req: Request, res: Response): Promise<any> {

  }
}