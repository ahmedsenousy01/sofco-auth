const express = require("express");
const cookieParser = require("cookie-parser");
const app = express();

app.use(cookieParser());
app.use(express.json());

let codeVerifier = "test-code-verifier";
const clientId = "testclientid";
const clientSecret = "testclientsecrettestclientsecret";

app.get("/login", async (req, res) => {
    const authorizationEndpoint = "http://localhost:5024/authorize";
    const queryParams = {
        response_type: "code",
        client_id: clientId,
        redirect_uri: "http://localhost:3000/callback",
        code_challenge: codeVerifier,
        code_challenge_method: "Plain",
        state: "some_random_state",
        scope: "openid profile email", // Adjust scope as needed
    };

    // Construct the authorization URL
    const authorizationUrl = new URL(authorizationEndpoint);
    authorizationUrl.search = new URLSearchParams(queryParams).toString();

    // Redirect the user to the authorization endpoint
    res.redirect(authorizationUrl.toString());
});

app.get("/callback", async (req, res) => {
    // Remove line breaks and spaces
    const urlEncodedString = req.url;
    const cleanedString = decodeURIComponent(
        urlEncodedString.replace(/\+/g, " ")
    );

    // Extract query parameters
    const queryString = cleanedString.split("?")[1]; // Get everything after the '?' in the URL
    const queryParams = new URLSearchParams(queryString);

    // Access query parameters
    const code = queryParams.get("code");
    const state = queryParams.get("state");
    const issuer = queryParams.get("iss");

    // Parameters for token exchange
    const tokenEndpoint = "http://localhost:5024/token";

    // Token exchange request
    try {
        let response = await fetch(tokenEndpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                grantType: "authorization_code",
                code: code,
                clientId: clientId,
                codeVerifier: codeVerifier,
            }),
        });
        console.log(response)
        let json = await response.json();
        console.log(json)
        // TODO: verify access_token using client secret
        res.cookie("access_token", json.access_token, {
            httpOnly: true,
            secure: true,
            sameSite: true,
            expires: new Date(Date.now() + 1000 * 60 * 60),
        });
        return res.redirect("/protected");
    } catch (error) {
        return res.status(500).send("Token exchange failed" + error);
    }
});

app.get("/protected", async (req, res) => {
    if (!req.cookies["access_token"]) {
        return res.redirect("/login");
    }
    return res.send("protected route");
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});
