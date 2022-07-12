const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");

let connection = null;

mysql
    .createConnection({
        host: process.env.RDS_HOSTNAME,
        user: process.env.RDS_USERNAME,
        password: process.env.RDS_PASSWORD,
        database: process.env.RDS_DB_NAME,
    })
    .then((con) => (connection = con));

exports.handler = async (event) => {
    //se non siamo già connessi get connection
    if (!connection) {
        console.log("Nuova connessione");
        connection = await mysql.createConnection({
            host: process.env.RDS_HOSTNAME,
            user: process.env.RDS_USERNAME,
            password: process.env.RDS_PASSWORD,
            database: process.env.RDS_DB_NAME,
        });
    }

    // estrai il token dall'header
    const token = extractTokenFromHeader(event.authorizationToken);
    // se non lo trovi errore
    if (!token) return "Unauthorized";
    // verifica il token
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        if (!decoded.exp || !decoded.jti) return "Unauthorized";
        // se token scaduto dillo
        const expTime = +decoded.exp * 1000;
        const now = new Date().getTime();
        if (expTime < now) return "Error: Invalid token";
        // check a sistema se c'è quello user
        const id = decoded.jti;
        const queryExistingUser = `SELECT * FROM user WHERE id = '${id}'`;
        const resQuery = await connection.execute(queryExistingUser);
        const user = resQuery[0][0];
        return user
            ? generatePolicy(event.methodArn)
            : {
                  statusCode: 401,
                  body: "User non trovato, accesso negato.",
                  isBase64Encoded: false,
              };
    } catch (error) {
        return "Unauthorized";
    }
};

// Generate IAM policy
const generatePolicy = (resource) => {
    var authResponse = {};
    authResponse.principalId = "user";
    var policyDocument = {};
    policyDocument.Version = "2012-10-17";
    policyDocument.Statement = [];
    var statementOne = {};
    statementOne.Action = "execute-api:Invoke";
    statementOne.Effect = "Allow";
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
    return authResponse;
};

const extractTokenFromHeader = (authHeader) =>
    authHeader.split(" ")[0] !== "Bearer" ? null : authHeader.split(" ")[1];
