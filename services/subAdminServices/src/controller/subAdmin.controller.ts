import { Request, Response } from 'express';
import SubAdminService from '../service/subAdmin.service';
import { registerSubAdminSchema, subAdminSchema } from '../schemas/subAdminSchema';


export class SubAdminController {
    private readonly subAdminAuthService: SubAdminService;

    constructor() {
        this.subAdminAuthService = new SubAdminService();
    }

    async register(req: Request, res: Response): Promise<any> {
        const parseresult = registerSubAdminSchema.parse(req.body);
        const userData = await this.subAdminAuthService.register(parseresult)
        return res.status(201).json({
            statusCode: 201,
            message: userData.message,
            id: userData.id,
            firstName: userData.firstName,
            lastName: userData.lastName

        });
    }

    async login(req: Request, res: Response): Promise<any> {
        const ip =
            (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
            req.socket.remoteAddress ||
            '';

        const parseResult = subAdminSchema.parse(req.body);
        const userData = await this.subAdminAuthService.login(parseResult, ip);
        return res.status(200).json({
            statusCode: 200,
            message: userData.message,
            tokens: userData.tokens,

        });

    }

}