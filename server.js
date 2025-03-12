import Hapi from "@hapi/hapi";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import HapiAuthJwt2 from "hapi-auth-jwt2";

dotenv.config();

const users = []; // Simpan user sementara (bisa diganti dengan database)

// Fungsi untuk membuat token JWT
const generateToken = (user) => {
    return jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, {
        expiresIn: "48h", // Token berlaku 1 jam
    });
};

const validate = async (decoded, request, h) => {
    const user = users.find((u) => u.id === decoded.id);
    if (!user) { 
        return { isValid: false };
    }

    const newObjek = {
        id: user.id,
        username: user.username
    }
    return { isValid: true, credentials: newObjek };
};

const init = async () => {
    const server = Hapi.server({
        port: 5000,
        host: "localhost",
    });

    await server.register(HapiAuthJwt2);

    server.auth.strategy("jwt", "jwt", {
        key: process.env.JWT_SECRET, // Secret Key
        validate,
        verifyOptions: { algorithms: ["HS256"] }, // Algoritma JWT
    });

    server.auth.default("jwt");

    // Endpoint Register User
    server.route({
        method: "POST",
        path: "/register",
        options: { auth: false }, // Tidak perlu login untuk register
        handler: async (request, h) => {
            const { username, password } = request.payload;
            const hashedPassword = await bcrypt.hash(password, 10);
            const newUser = { id: users.length + 1, username, password: hashedPassword };
            users.push(newUser);
            return h.response({ message: "User registered successfully" }).code(201);
        },
    });

    // Endpoint Login User
    server.route({
        method: "POST",
        path: "/login",
        options: { auth: false }, // Tidak perlu login untuk akses
        handler: async (request, h) => {
            const { username, password } = request.payload;
            const user = users.find((u) => u.username === username);
            if (!user || !(await bcrypt.compare(password, user.password))) {
                return h.response({ message: "Invalid credentials" }).code(401);
            }
            const token = generateToken(user);
            return h.response({ token }).code(200);
        },
    });

    // Endpoint Protected (Hanya Bisa Diakses Jika Sudah Login)
    server.route({
        method: "GET",
        path: "/protected",
        handler: (request, h) => {
            return h.response({ message: "Access granted", user: request.auth.credentials }).code(200);
        }, 
    });

    await server.start();
    console.log(`Server berjalan di ${server.info.uri}`);
};

init();
