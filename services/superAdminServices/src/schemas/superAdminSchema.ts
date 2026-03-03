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
export const forgetPasswordSchema = z.object({
  email: z
    .string()
    .trim()
    .toLowerCase()
    .email("Invalid email format"),
})
export const resetPasswordSchema = z.object({
  email: z
    .string()
    .trim()
    .toLowerCase()
    .email("Invalid email format"),

  resetToken: z
    .string()
    .min(10, "Invalid or expired reset token"),

  newPassword: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[a-z]/, "Password must contain at least one lowercase letter")
    .regex(/[0-9]/, "Password must contain at least one number"),


});
export const refreshTokenSchema = z.object({
  refreshToken: z
    .string()
    .trim()
    .min(10, "Invalid refresh token"),

  deviceToken: z
    .string()
    .trim()
    .min(5, "Device token is required"),
});

export type SuperAdminDTO = z.infer<typeof superAdminSchema>;
export type ForgetPasswordDTO = z.infer<typeof forgetPasswordSchema>
export type ResetPasswordDTO = z.infer<typeof resetPasswordSchema>
export type RefreshTokenDTO = z.infer<typeof refreshTokenSchema>;