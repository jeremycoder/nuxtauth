import argon2 from "argon2";
import { PrismaClient } from "@prisma/client";
import { UnregisteredUser, RegisteredUser } from "./types";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";

const config = useRuntimeConfig();

const prisma = new PrismaClient();

/**
 * @desc Hashes a password or any string using Argon 2
 * @param password Unhashed password
 */
export async function hashPassword(password: string): Promise<string> {
  try {
    return await argon2.hash(password);
  } catch (err) {
    throw createError({ statusCode: 500, statusMessage: "Password error" });
  }
}

/**
 * @desc Checks whether the body in register post request is in correct format
 * @param body Body object passed in register post request
 */
export function validateRegisterBody(body: Object) {
  if ("first_name" in body === false) {
    return "'first_name' is required";
  }

  if ("last_name" in body === false) {
    return "'last_name' is required";
  }

  if ("email" in body === false) {
    return "'email' is required";
  }

  if ("password" in body === false) {
    return "'password' is required";
  }
}

/**
 * @desc Checks whether the body in login post request is in correct format
 * @param body Body object passed in login post request
 */
export function validateLoginBody(body: Object) {
  if ("email" in body === false) {
    return "'email' is required";
  }

  if ("password" in body === false) {
    return "'password' is required";
  }
}

/**
 * @desc Checks whether email is valid
 * @param email The email string
 */
export function validateEmail(email: string): boolean {
  if (/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(email)) {
    return true;
  }

  return false;
}

/**
 * @desc Checks whether email already exists in database
 * @param email The email string
 */
export async function emailExists(email: string): Promise<boolean> {
  let user = undefined;

  await prisma.user
    .findFirst({
      where: {
        email: email,
      },
    })
    .then(async (result) => {
      user = result;
      await prisma.$disconnect();
    })
    .catch(async (e) => {
      console.error(e);
      await prisma.$disconnect();
      process.exit(1);
    });

  if (user === null) return false;

  return true;
}

/**
 * @desc Creates a user
 * @param UnregUser Unregistered user with properties e.g first_name, email
 */
export async function createUser(
  UnregisteredUser: UnregisteredUser
): Promise<Object> {
  let registeredUser = {} as RegisteredUser;

  const hashedPassword = await hashPassword(UnregisteredUser.password);
  await prisma.user
    .create({
      data: {
        first_name: UnregisteredUser.first_name,
        last_name: UnregisteredUser.last_name,
        uuid: uuidv4(),
        email: UnregisteredUser.email,
        password: hashedPassword,
      },
    })
    .then(async (result) => {
      registeredUser = result;
      await prisma.$disconnect();
    })
    .catch(async (e) => {
      console.error(e);
      await prisma.$disconnect();
      process.exit(1);
    });

  return { email: registeredUser.email, uuid: registeredUser.uuid };
}

export function validatePassword(password: string): boolean {
  // Has at least 8 characters
  if (password.length <= 8) return false;

  // Has uppercase letters
  if (!/[A-Z]/.test(password)) return false;

  // Has lowercase letters
  if (!/[a-z]/.test(password)) return false;

  // Has numbers
  if (!/\d/.test(password)) return false;

  // Has non-alphanumeric characters
  if (!/\W/.test(password)) return false;

  return true;
}

/**
 * @desc Checks if a user exists
 * @param email User's email
 */
async function getUser(email: string): Promise<RegisteredUser | null> {
  let user = null;
  await prisma.user
    .findFirst({
      where: {
        email: email,
      },
    })
    .then(async (response) => {
      user = response;
      await prisma.$disconnect();
    })
    .catch(async (e) => {
      console.error(e);
      await prisma.$disconnect();
      process.exit(1);
    });

  return user;
}

/**
 * @desc Verifies password against a hash
 * @param hash Hashed password
 * @param password Unhashed password
 */
async function verifyPassword(
  hash: string,
  password: string
): Promise<boolean> {
  try {
    if (await argon2.verify(hash, password)) {
      return true;
    } else {
      return false;
    }
  } catch (err) {
    console.log(err);
    return false;
  }
}

/**
 * @desc Logs a user into database
 * @param registeredUser Registered user
 */
export async function login(
  registeredUser: RegisteredUser
): Promise<null | Object> {
  const user = await getUser(registeredUser.email);
  if (user === null) return null;

  console.log("User hashed email: ", user.email);

  if (await verifyPassword(user.password, registeredUser.password)) {
    // TODO: Create last login in table

    // Public user profile does not show password or internal user id
    const publicUser = {
      uuid: user.uuid,
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
      role: user.role,
      password_verified: user.password_verified,
      last_login: user.last_login,
      date_created: user.date_created,
    };

    // TODO: Very very well done. Contnue from here. Use access and refresh tokens.

    // Create access and refresh tokens
    const accessToken = jwt.sign(
      publicUser,
      config.public.muloziAccessTokenSecret
    );
    const refreshToken = jwt.sign(
      publicUser,
      config.public.muloziRefreshTokenSecret
    );

    return {
      accessToken: accessToken,
      refreshToken: refreshToken,
    };
  }

  return null;
}
