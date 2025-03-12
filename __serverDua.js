import Hapi from "@hapi/hapi"
import dotenv from "dotenv";
import validate from "./service/validate.js";
import hapiAuthJwt2 from "hapi-auth-jwt2";
import { handlerRegister, handlerLogin } from "./service/handler.js";
import pool from "./config/database.js";

dotenv.config();

const init = async () => {
    const server = Hapi.server({
        port: 6000,
        host: 'localhost',
    })

    await server.register(hapiAuthJwt2)

    server.auth.strategy("jwt_strategy", "jwt", {
        key: process.env.JWT_SECRET,
        validate,
        verifyOptions: {algorithms: ["HS256"]}
    })

    server.auth.default("jwt_strategy")

    server.route({
       method: "POST",
       path: "/register",
       options: {
          auth: false  
       },
       handler: handlerRegister
    })

    server.route({
        method: "POST",
        path: "/login",
        options: {
            auth: false
        },
        handler: handlerLogin
    })

    server.route({
        method: "GET",
        path: "/protected",
        handler: (request, h) => {
            return h.response({ message: "Access granted", user: request.auth.credentials }).code(200);
        }, 
    });

    console.log(`server berjalan di ${server.info.uri}`)
    server.start()
}

init()