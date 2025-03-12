import users from "./users.js"
import pool from "../config/database.js"

const validate = async (decoded, request, h) => {

    // const user = users.find((u) => u.id === decoded.id)

    // const newObjek = {
    //     id: user.id,
    //     username: user.username
    // }

    // if(!user) {
    //     return {
    //         isValid: false
    //     }
    // }

    // return {
    //     isValid: true,
    //     credentials: newObjek
    // }


    try{
        const [rows] = await pool.query("SELECT * FROM users WHERE id = ?", [decoded.id])
        
        if(rows.length === 0) {
            return {
                isValid: false
            }
        }

        const user = rows[0]

        return {
            isValid: true,
            credentials: {
                id: user.id,
                username: user.username
            }
        } 
    } catch(err) {
        console.error(err);
        return { isValid: false };
    }
}

export default validate