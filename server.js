const express = require("express");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
const port = 8080;

// 가짜 사용자 정보
const fakeUser = {
    authorCode: "charlie-code",
    authorNm: "Charlie",
    email: "charlie@example.com",
    id: "charlie-123",
    ip: "127.0.0.1",
    name: "Charlie",
    orgnztId: "example-org",
    orgnztNm: "Example Org",
    picture: "https://picsum.photos/200",
    uniqId: "a-unique-id-for-charlie",
};

const loginInfo = {
    id: "jbs@gmail.com",
    password: "wavus12!",
};

// JWT 비밀 키
const JWT_SECRET = "access-key";
const JWT_SECRET_REFRESH = "refresh-key";

app.use(express.json());
app.use(cookieParser());

// 로그인 엔드포인트
app.post("/login", (req, res) => {
    const { id, password } = req.body;

    if (id === loginInfo.id && password === loginInfo.password) {
        //엑세스 토큰
        const accessToken = jwt.sign({ id, type: "access" }, JWT_SECRET, {
            expiresIn: "5m",
        });

        //리프레시 토큰
        const refreshToken = jwt.sign(
            { id, type: "refresh" },
            JWT_SECRET_REFRESH,
            {
                expiresIn: "1d",
            }
        );

        res.cookie("Authentication", accessToken, {
            httpOnly: true,
            path: "/",
            sameSite: "lax",
        });
        res.cookie("Refresh", refreshToken, {
            httpOnly: true,
            path: "/",
            maxAge: 1 * 24 * 60 * 60 * 1000,
            sameSite: "lax",
        });

        res.status(200).json(fakeUser);
    } else {
        res.status(401).send("Invalid credentials");
    }
});

// 로그아웃 엔드포인트
app.post("/logout", (req, res) => {
    res.clearCookie("Authentication", { path: "/" });
    res.clearCookie("Refresh", { path: "/" });
    res.status(200).send("Logout successful");
});

// 보호된 엔드포인트
app.get("/user/token-user", (req, res) => {
    const accessToken = req.cookies.Authentication;

    if (!accessToken) {
        return res.status(401).send("Access denied");
    }

    try {
        const decoded = jwt.verify(accessToken, JWT_SECRET);
        if (decoded.type !== "access") {
            return res.status(403).send("Forbidden: Invalid token type.");
        }
        res.status(200).json(fakeUser);
    } catch (error) {
        console.error("Access Token Verification Error:", error);

        if (error.name === "TokenExpiredError") {
            return res.status(401).send("Access denied: Access token expired.");
        }
        return res.status(400).send("Invalid access token.");
    }
});

app.get("/user/access-token", (req, res) => {
    const accessToken = req.cookies.Authentication;

    if (!accessToken) {
        console.error(`400 access ::: ${accessToken}`);
        return res.status(400).send("Access denied");
    }

    try {
        const decoded = jwt.verify(accessToken, JWT_SECRET);
        if (decoded.type !== "access") {
            console.error(`type access ::: ${decoded.type}`);
            return res.status(403).send("Forbidden: Invalid token type.");
        }
        console.log(`good access`);
        res.status(200).send("access token valid");
    } catch (error) {
        console.error("Access Token Verification Error:", error);

        if (error.name === "TokenExpiredError") {
            console.error(`TokenExpiredError access ::: ${error.name}`);
            return res.status(401).send("Access denied: Access token expired.");
        }

        console.error(`400 catch access ::: ${error.name}`);
        return res.status(400).send("Invalid access token.");
    }
});

app.post("/user/refresh-token", (req, res) => {
    const refreshToken = req.cookies.Refresh;

    if (!refreshToken) {
        res.clearCookie("Authentication", { path: "/" });
        res.clearCookie("Refresh", { path: "/" });
        console.error(`400 refresh ::: ${refreshToken}`);
        return res
            .status(400)
            .send("Access denied: No refresh token provided.");
    }

    try {
        const decoded = jwt.verify(refreshToken, JWT_SECRET_REFRESH);
        if (decoded.type !== "refresh") {
            res.clearCookie("Authentication", { path: "/" });
            res.clearCookie("Refresh", { path: "/" });
            console.error(`403 refresh ::: ${refreshToken}`);
            return res.status(403).send("Forbidden: Invalid token type.");
        }

        const newAccessToken = jwt.sign(
            { id: decoded.id, type: "access" },
            JWT_SECRET,
            { expiresIn: "5m" }
        );

        // 새로운 Access 토큰을 세션 쿠키로 설정
        res.cookie("Authentication", newAccessToken, {
            httpOnly: true,
            path: "/",
            sameSite: "lax",
        });
        console.log(`good refresh - new access token ::: ${newAccessToken}`);
        res.status(200).send("New access token issued.");
    } catch (error) {
        console.error("Refresh Token Verification Error:", error);

        res.clearCookie("Authentication", { path: "/" });
        res.clearCookie("Refresh", { path: "/" });

        if (error.name === "TokenExpiredError") {
            console.error("TokenExpiredError Refresh Token:", error);
            return res
                .status(401)
                .send(
                    "Access denied: Refresh token expired. Please log in again."
                );
        }
        console.error("400 catch refresh:", error);
        return res.status(400).send("Invalid refresh token.");
    }
});

app.listen(port, () => {
    console.log(`Mock auth server listening at http://localhost:${port}`);
});
