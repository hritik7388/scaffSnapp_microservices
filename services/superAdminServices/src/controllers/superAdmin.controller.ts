import { Request, Response } from 'express';
import SuperAdminService from '../service/superAdmin.service';
import { superAdminSchema } from '../schemas/superAdminSchema';


export class SuperAdminController {
  private readonly superAdminAuthService: SuperAdminService;

  constructor() {
    this.superAdminAuthService = new SuperAdminService();
  }

  async login(req: Request, res: Response): Promise<any> {
    const ip =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      req.socket.remoteAddress ||
      '';

    const parseResult = superAdminSchema.parse(req.body);
    const userData = await this.superAdminAuthService.login(parseResult, ip);
    return res.status(200).json({
      message: userData.message,
      tokens: userData.tokens,

    });

  }

}