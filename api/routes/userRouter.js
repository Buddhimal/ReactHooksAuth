const router = require("express").Router();
const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const auth = require("../middleware/auth")


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
        res.status(500).json({error: err.message});
    }

});

router.post("/login", async (req, res) => {
    try {

        const {email, password} = req.body;

        if (!email || !password)
            return res.status(400).json({msg: "Please Fill all the fields!"})

        const user = await User.findOne({email: email});

        if (!user)
            return res.status(400).json({msg: "No User Account found!"})

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch)
            return res.status(400).json({msg: "Invalied Password"});

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET);

        return res.json({
            token: token,
            user: {
                id: user.id,
                displayName: user.displayName,
                email: user.email
            }
        })


    } catch (err) {
        res.status(500).json({error: err.message});
    }
})


router.delete("/delete", auth, async (req, res) => {
    try {

        const deletedUser = await User.findByIdAndDelete(req.user);

        res.json(deletedUser);

    } catch (err) {
        res.status(500).json({error: err.message});
    }
})


router.post("/tokenIsValid", async (req, res) => {
    try {

        const token = req.header("x-auth-token");
        if (!token)
            return res.status(401).json(false);

        const verified = jwt.verify(token, process.env.JWT_SECRET);
        if (!verified)
            return res.status(401).json(false);

        const user = await User.findById(verified.id);
        if (!user)
            return res.status(401).json(false);

        return res.json(true);


    } catch (err) {
        res.status(500).json({error: err.message});
    }
})

module.exports = router;