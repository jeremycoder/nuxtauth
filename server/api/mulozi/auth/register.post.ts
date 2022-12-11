import {
  validateRegisterBody,
  validateEmail,
  emailExists,
  createUser,
  validatePassword,
} from "../../../../mulozi/utils";

export default defineEventHandler(async (event) => {
  const body = await readBody(event);

  // Check if body contains first_name, last_name, email, and password
  const bodyError = validateRegisterBody(body);
  if (bodyError) {
    throw createError({ statusCode: 400, statusMessage: bodyError });
  }

  // Check email is in a valid format
  if (!validateEmail(body.email)) {
    throw createError({ statusCode: 400, statusMessage: "Bad email format" });
  }

  // Check if email exists
  if (await emailExists(body.email)) {
    throw createError({
      statusCode: 403,
      statusMessage: "Email already exists",
    });
  }

  // Check password meets minimum strength requirements
  if (!validatePassword(body.password)) {
    throw createError({
      statusCode: 400,
      statusMessage:
        "Poor password strength. Password must contain at least 8 characters, an upper-case letter, and a lower-case letter, a number, and a non-alphanumeric character.",
    });
  }

  const user = await createUser(body);

  return { user };
});
