import { z } from "zod";

export const superAdminSchema = z.object({
  email: z
    .string()
    .trim()
    .toLowerCase()
    .email("Invalid email format"),

  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(100),

  deviceToken: z
    .string()
    .optional(),

  deviceType: z
    .enum(["ios", "android", "web"])
    .optional(),

  deviceName: z
    .string()
    .max(100)
    .optional(),

  rememberMe: z
    .boolean()
    .optional()
});

export const forgetPasswordSchema=z.object({
    email: z
    .string()
    .trim()
    .toLowerCase()
    .email("Invalid email format"),
})

export type SuperAdminDTO = z.infer<typeof superAdminSchema>;
export type ForegetpasswordDTO = z.infer<typeof forgetPasswordSchema>;