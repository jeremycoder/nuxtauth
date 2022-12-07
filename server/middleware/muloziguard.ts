import { protectedRoutes } from "../../mulozi/protectedRoutes";
import { verifyUser, getUser } from "../../mulozi/utils";
const routes = protectedRoutes();

export default defineEventHandler(async (event) => {
  if (event.node.req.url)
    if (routes.includes(event.node.req.url)) {
      const authHeader = event.node.req.headers.authorization;

      // Check for authorization header
      if (!authHeader)
        throw createError({
          statusCode: 401,
          statusMessage: "Unauthorized",
        });

      // Get Bearer token
      const bearerToken = authHeader.split(" ");

      // Check for word "Bearer"
      if (bearerToken[0] !== "Bearer")
        throw createError({
          statusCode: 401,
          statusMessage: "Unauthorized",
        });

      // Check for token
      if (!bearerToken[1])
        throw createError({
          statusCode: 401,
          statusMessage: "Unauthorized",
        });

      // Get user from token
      const user = verifyUser(bearerToken[1]);

      // Check if user was retrieved from token
      if (user === null)
        throw createError({
          statusCode: 401,
          statusMessage: "Unauthorized",
        });

      // Check if user has email attribute
      if (!user.email)
        throw createError({
          statusCode: 401,
          statusMessage: "Unauthorized",
        });

      // Check if user exists in the database
      const userInDb = await getUser(user.email);

      if (userInDb === null)
        throw createError({
          statusCode: 401,
          statusMessage: "Unauthorized",
        });

      return user;
    }
});
