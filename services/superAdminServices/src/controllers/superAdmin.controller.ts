import { Request, Response } from 'express';
import SuperAdminService from '../service/superAdmin.service';
import { createSubAdminSchema, forgetPasswordSchema, refreshTokenSchema, resetPasswordSchema, superAdminSchema } from '../schemas/superAdminSchema';


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

  async forgotPassword(req: Request, res: Response): Promise<any> {
    const parseResult = forgetPasswordSchema.parse(req.body);
    const userData = await this.superAdminAuthService.forgotPassword(parseResult)
    return res.status(200).json({
        statusCode: 200,
        message: userData.message,
        resetToken: userData.resetToken,
      })
  }

  async resetPassword(req: Request, res: Response): Promise<any> {
    const parseResult=resetPasswordSchema.parse(req.body);
    const userData=await this.superAdminAuthService.resetPassword(parseResult);
    return res.status(200).json({
      statusCode:200,
      message:userData.message,

    })
  }
    async refreshToken(req: Request, res: Response): Promise<any> {
    const parseResult=refreshTokenSchema.parse(req.body);
    const userData=await this.superAdminAuthService.refreshToken(parseResult);
    return res.status(200).json({
      statusCode:200,
      message:userData.message,
        accessToken: userData.accessToken,
      refreshToken: userData.refreshToken,
      
    })
    
  }

  async createSubAdmin(req: Request, res: Response): Promise<any> { 
    const id=Number(req.userId)
    const parseResult=createSubAdminSchema.parse(req.body);
    const userData=await this.superAdminAuthService.createSubAdmin(id,parseResult);
    return res.status(200).json({
      statusCode:200, 
      message:userData.message,

      
    })
    
  }

}