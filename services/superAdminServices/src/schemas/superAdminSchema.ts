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
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/,
      "Password must contain uppercase, lowercase, number and special character"
    )


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
export const createSubAdminSchema = z.object({
  firstName: z
    .string()
    .trim()
    .min(2, "First name must be at least 2 characters")
    .max(100),

  lastName: z
    .string()
    .trim()
    .min(2, "Last name must be at least 2 characters")
    .max(100),

  email: z
    .string()
    .trim()
    .toLowerCase()
    .email("Invalid email format"),

  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(100)
    .regex(
      /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])/,
      "Password must include uppercase, lowercase, number and special character"
    ),

  phoneNumber: z
    .string()
    .trim()
    .min(7)
    .max(20)
    .optional(),

  countryCode: z
    .string()
    .trim()
    .max(10)
    .optional(),

  profileImage: z
    .string()
    .url("Profile image must be a valid URL")
    .optional(),

  address: z
    .object({
      line1: z.string().trim().max(200).optional(),
      line2: z.string().trim().max(200).optional(),
      city: z.string().trim().max(100).optional(),
      state: z.string().trim().max(100).optional(),
      country: z.string().trim().max(100).optional(),
      postalCode: z.string().trim().max(20).optional(),
    })
    .optional(),

  coordinates: z
    .object({
      lat: z
        .number()
        .min(-90, "Latitude must be between -90 and 90")
        .max(90),
      lng: z
        .number()
        .min(-180, "Longitude must be between -180 and 180")
        .max(180),
    })
    .optional(),
});
export type SuperAdminDTO = z.infer<typeof superAdminSchema>;
export type RefreshTokenDTO = z.infer<typeof refreshTokenSchema>;
export type ResetPasswordDTO = z.infer<typeof resetPasswordSchema>
export type ForgetPasswordDTO = z.infer<typeof forgetPasswordSchema>
export type CreateSubAdminDTO = z.infer<typeof createSubAdminSchema>;