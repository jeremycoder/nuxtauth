import { createNewTokensFromRefresh } from "../../../../mulozi/utils";

export default defineEventHandler(async (event) => {
  // Check refresh signature (passed by MuloziRefreshGuard after authentication)
  if (event.context.refreshSignatureBy !== "MuloziRefreshGuard")
    throw createError({
      statusCode: 401,
      statusMessage: "Unauthorized",
    });

  // Get new access and refresh tokens
  const newTokens = createNewTokensFromRefresh(event.context.refreshToken);

  if (newTokens === null)
    throw createError({
      statusCode: 401,
      statusMessage: "Unauthorized",
    });

  return newTokens;
});
