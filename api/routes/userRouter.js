const router = require("express").Router();
const User = require("../models/userModel");
const bcrypt = require("bcryptjs");


router.post('/register', async (req, res) => {

    try {

        const {email, password, passwordCheck, displayName} = req.body;

        //validate

        if (!email || !password || !passwordCheck || !displayName)
            return res.status(400).json({msg: "Please Fill all the fields!"})

        if (password.length < 5)
            return res.status(400).json({msg: "Password must be at least 5 letters!"})

        if (password !== passwordCheck)
            return res.status(400).json({msg: "Both password must be same!"})

        const existingUser = await User.findOne({email: email});

        if (existingUser)
            return res.status(400).json({msg: "User Already Exist!"})

        const salt = await bcrypt.genSalt();
        const passwordHash = await bcrypt.hash(password, salt);

        const newUser = new User({
            email,
            password: passwordHash,
            displayName
        });

        const savedUser = await newUser.save();
        return res.json({savedUser})


    } catch (err) {
        res.status(500).json({err});
    }

})


router.get("/test", (req, res) => {
    res.send("Hello");
})


module.exports = router;