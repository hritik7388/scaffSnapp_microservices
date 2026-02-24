import z from "zod";

export const superAdminSchema = z.object({
    email: z.string().email(),
    password: z.string(),

})
export type SuperAdminDTO = z.infer<typeof superAdminSchema>;