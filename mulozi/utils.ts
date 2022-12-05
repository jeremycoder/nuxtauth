import argon2 from "argon2";
import { PrismaClient } from "@prisma/client";
import { UnregisteredUser, RegisteredUser } from "./types";
import { v4 as uuidv4 } from "uuid";

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

/**
 * @desc Logs a user into database
 * @param user Registered user
 */
export async function login(user: RegisteredUser): Promise<boolean> {
  let authenticatedUser = null;
  const hashedPassword = await hashPassword(user.password);

  // Check if user exists
  await prisma.user
    .findFirst({
      where: {
        email: user.email,
      },
    })
    .then(async (result) => {
      authenticatedUser = result;
      await prisma.$disconnect();
    })
    .catch(async (e) => {
      console.error(e);
      await prisma.$disconnect();
      process.exit(1);
    });

  if (authenticatedUser === null) return false;

  // Check if password is correct !does not work, please fix
  if (!(await argon2.verify(hashedPassword, user.password))) return false;

  return true;
}
