import {
  validateLoginBody,
  validateEmail,
  login,
} from "../../../../mulozi/utils";

export default defineEventHandler(async (event) => {
  const body = await readBody(event);

  // Check if body contains email, and password
  const bodyError = validateLoginBody(body);
  if (bodyError) {
    throw createError({ statusCode: 400, statusMessage: bodyError });
  }

  // Check email is in a valid format
  if (!validateEmail(body.email)) {
    throw createError({ statusCode: 400, statusMessage: "Bad email format" });
  }

  const tokens = await login(body);

  if (tokens === null) {
    throw createError({ statusCode: 401, statusMessage: "Invalid login" });
  }

  return { tokens };
});
