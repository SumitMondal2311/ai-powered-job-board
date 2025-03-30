import z from "zod";

const signupSchema = z.object({
  fullName: z.string().trim().min(1, "Full name is required"),
  email: z
    .string()
    .trim()
    .email("Invalid email")
    .transform((str) => str.toLowerCase()),
  password: z
    .string()
    .trim()
    .min(8, "Password must contains atleast 8 characters")
    .max(20, "Password must contain atmost 20 characters")
    .regex(/[A-Z]/, "Password must contain at least 1 uppercase letter")
    .regex(/[0-9]/, "Password must contain at least 1 number")
    .regex(
      /[^A-Za-z0-9]/,
      "Password must contain at least 1 special character"
    ),
  role: z.enum(["CANDIDATE", "RECRUITER"]),
});

const loginSchema = z.object({
  email: z
    .string()
    .trim()
    .email("Invalid email")
    .transform((str) => str.toLowerCase()),
  password: z
    .string()
    .min(8, "Password must contains atleast 8 characters")
    .max(20, "Password must contain atmost 20 characters")
    .regex(/[A-Z]/, "Password must contain at least 1 uppercase letter")
    .regex(/[0-9]/, "Password must contain at least 1 number")
    .regex(
      /[^A-Za-z0-9]/,
      "Password must contain at least 1 special character"
    ),
});

export { signupSchema, loginSchema };
