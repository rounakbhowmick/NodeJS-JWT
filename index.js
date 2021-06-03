require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();
//middleware
app.use(express.json());
var refreshtokens = [];
//routes

//registration

//login
app.post("/login", (req, res) => {
	const username = req.body.username;
	const password = req.body.password;
	if (username === "rounak" && password === "1") {
		const access_token = jwt.sign(
			{ sub: username },
			process.env.JWT_ACCESS_SECRET,
			{ expiresIn: process.env.JWT_ACCESS_TIME }
		);
		const refreshtoken = GenerateRefreshToken(username);
		return res.json({
			status: true,
			message: "login success",
			data: { access_token, refreshtoken },
		});
	}
	return res.json({ status: true, message: "login failure" });
});

app.post("/token", verifyrefreshtoken, (req, res) => {
	console.log(req.userData);
	const username = req.userData.sub;
	const access_token = jwt.sign(
		{ sub: username },
		process.env.JWT_ACCESS_SECRET,
		{ expiresIn: process.env.JWT_ACCESS_TIME }
	);
	const refreshtoken = GenerateRefreshToken(username);
	return res.json({
		status: true,
		message: "success",
		data: { access_token, refreshtoken },
	});
});
//dashboard
app.get("/dashboard", verifytoken, (req, res) => {
	return res.json({ status: true, message: "Hello from dashboard" });
});
app.get("/logout", verifytoken, (req, res) => {
	const username = req.userData.sub;
	//remove refresh token;
	let index = refreshtokens.findIndex((i) => i.username == username);

	if (refreshtokens.findIndex((i) => i.username == username) !== -1) {
		refreshtokens = refreshtokens.filter((x) => x.username !== username);

		return res.json({ status: true, message: "Logout Successful" });
	}
	return res.json({ status: true, message: "Already logout" });
});
//Custom middleware

function verifytoken(req, res, next) {
	try {
		const token = req.headers.authorization.split(" ")[1];
		const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
		req.userData = decoded;
		next();
	} catch (err) {
		return res.status(401).json({
			status: true,
			message: "Your session is not valid",
			data: err,
		});
	}
}

function verifyrefreshtoken(req, res, next) {
	const token = req.body.token;
	if (token == null)
		return res.status(401).json({ status: false, message: "Invalid Request" });
	try {
		const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
		req.userData = decoded;
		//verify if refreshtoken already exits or not
		let storedRefreshtoken = refreshtokens.find(
			(t) => t.username == decoded.sub
		);
		if (storedRefreshtoken == undefined)
			return res
				.status(401)
				.json({ status: false, message: "Token is not in store" });
		if (storedRefreshtoken.token != token)
			return res
				.status(401)
				.json({ status: false, message: "Token is not same" });
		next();
	} catch (err) {
		return res.status(401).json({
			status: true,
			message: "Your session is not valid",
			data: err,
		});
	}
}
function GenerateRefreshToken(username) {
	const refreshtoken = jwt.sign(
		{ sub: username },
		process.env.JWT_REFRESH_SECRET,
		{ expiresIn: process.env.JWT_REFRESH_TIME }
	);
	let storedRefreshtoken = refreshtokens.find((t) => t.username == username);
	if (storedRefreshtoken == undefined) {
		refreshtokens.push({
			username: username,
			token: refreshtoken,
		});
	} else {
		refreshtoken[refreshtokens.findIndex((x) => x.username)].token =
			refreshtoken;
	}
	return refreshtoken;
}
app.listen(3000, () => console.log("Server is running"));
//1hour 4 min
