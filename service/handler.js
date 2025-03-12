import generateToken from "./generateToken.js"
import users from "./users.js"
import bcrypt from "bcryptjs"
import pool from "../config/database.js"

export const handlerRegister = async (request, h) => {
    // const hashedPassword = await bcrypt.hash(password, 10)
    // const newUser = {
        //     id: users.length + 1,
        //     username,
        //     password: hashedPassword
        // }
        
        // users.push(newUser)
        
    
    try {
        const {username, password} = request.payload

        const hashedPassword = await bcrypt.hash(password, 10)
        const [result] = await pool.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword])
        return h.response({
            pesan: "berhasil register",
            id: result.insertId,
            username: username
        }).code(201)
    } catch(err){
        console.log(err)
        return h.response({
            error: "database error",
            pesan: "gagal login"
        }).code(500)
    }
}

export const handlerLogin = async (request, h) => {
    const {username, password} = request.payload

    // const user = users.find((u) => u.username === username)

    // if(!user || !(await bcrypt.compare(password, user.password))){
    //     return h.response({
    //         pesan: "password atau username salah"
    //     }).code(501)
    // }

    try {
        const [rows] = await pool.query("SELECT * FROM users WHERE username = ? ", [username])
        if(rows === 0){
            return h.response("username atau password tidak di temukan").code(404)
        }

        const hashedPassword = rows[0].password

        const objekToken = {
            id: rows[0].id,
            username: rows[0].username
        }
        
        const isMatch = await bcrypt.compare(password, hashedPassword)
        const token = generateToken(objekToken)

        if(!isMatch) {
            return h.response("username atau password salah")
        } else {
            return h.response({
                token
            })
        }
    } catch(err){
        return h.response("gagal login").code(500)
    }

}