import { z } from "zod";


export const registerSubAdminSchema = z.object({
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

export const subAdminSchema = z.object({
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


export type RegisterSubAdminDTO = z.infer<typeof registerSubAdminSchema>;

export type SubAdminDTO = z.infer<typeof subAdminSchema>;
export type ForegetpasswordDTO = z.infer<typeof forgetPasswordSchema>;