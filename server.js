require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db.js');
const app = express();

app.use(express.json());
const secretkey = process.env.JWT_SECRET || "secret" ; 

app.post('/user' , async (req , res) =>{
    const { full_names , email , phone_number , password , role } = req.body;
    const hashpassword = await bcrypt.hash(password , 10);
     const sql = 'INSERT INTO user( full_name , email , phone_number , password , role ) VALUES ( ? , ? , ? ,? ,?)';
     db.query(sql , [full_names , email , phone_number , hashpassword , role ] , (err , result) =>{
        if(err){
            res.status(500).json('Failed to insert user' , err.stack);
        }
        res.status(200).json('User inserted successfully' , result);
     });
});

app.post('/user/login' , (req , res) =>{
    const {full_names , email , phone_number , password} = req.body;
    const sql = 'SELECT * FROM user where email=?';
    db.query(sql , [email] , async (err , result)=>{
        if(err){
            return res.status(400).json({message: 'User not found'});
        }
        const user = result[0];
        const valid = await bcrypt.compare(password , user.password);

        if(!valid){
            return res.status(400).json({message: 'Invalid Password'});
        }
 
        const token = jwt.sign(
            {id:user.user_id , email:user.email , phone_number:user.phone_number , role:user.role},secretkey,{exporesIn:"1h"}
        );

      res.json({token});

    } );
}); 

 
app.get('/user' , (req , res) =>{
    const sql = 'SELECT * FROM user';
    db.query(sql , (err , result) =>{
        if(err){
            res.status(500).json('Failed to fetch users' , err.stack);
        }
        res.json(result);
    })
});



app.listen(4300 , () =>{
    console.log('Server is running on port 4300');
});


