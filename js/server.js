const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();


const app = express();
const port = 8080;

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;

let db = new sqlite3.Database('./totally_not_my_privateKeys.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Connected to the SQlite database.');
});

db.run(`CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    exp INTEGER NOT NULL
)`);


async function generateKeyPairs() {
  // Generate a valid key pair
  let validKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  let serializedValidKey = validKeyPair.toJSON(true); // true for private key
  let validExpTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now

  // Generate an expired key pair
  let expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  let serializedExpiredKey = expiredKeyPair.toJSON(true);
  let expiredExpTime = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago

  // Insert valid key pair
  db.run(`INSERT INTO keys (key, exp) VALUES (?, ?)`, [JSON.stringify(serializedValidKey), validExpTime], function(err) {
    if (err) {
      return console.log(err.message);
    }
    console.log(`A valid row has been inserted with row-id ${this.lastID}`);
  });

  // Insert expired key pair
  db.run(`INSERT INTO keys (key, exp) VALUES (?, ?)`, [JSON.stringify(serializedExpiredKey), expiredExpTime], function(err) {
    if (err) {
      return console.log(err.message);
    }
    console.log(`An expired row has been inserted with row-id ${this.lastID}`);
  });
}// Repeat for expiredKeyPair with a past expiration tim


function generateToken() {
  db.get(`SELECT * FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1`, [Math.floor(Date.now() / 1000)], async (err, row) => {
    if (err) {
      return console.log(err.message);
    }
    try {
      const keyObj = JSON.parse(row.key);
      const joseKey = await jose.JWK.asKey(keyObj);
      const pemKey = joseKey.toPEM(true); // Convert to PEM format

      const payload = {
        user: 'sampleUser',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      };

      const options = {
        algorithm: 'RS256',
        header: {
          typ: 'JWT',
          alg: 'RS256',
          kid: joseKey.kid,
        },
      };

      // Now sign the token with the PEM-formatted key
      jwt.sign(payload, pemKey, options, (err, token) => {
        if (err) {
          console.log(err);
          return;
        }
        console.log("Token generated:", token);
        // Here you should handle the token, e.g., by sending it in a response
      });
    } catch (joseError) {
      console.error("Error handling JOSE key:", joseError);
    }
  });
}



function generateExpiredJWT() {
  // Query the database for an expired key
  db.get("SELECT key FROM keys WHERE exp <= ?", [Math.floor(Date.now() / 1000)], async (err, row) => {
    if (err) {
      console.error("Error fetching expired key:", err.message);
      return;
    }
    try {
      if (row) {
        const expiredKey = JSON.parse(row.key);
        const joseKey = await jose.JWK.asKey(expiredKey);
        const pemKey = joseKey.toPEM(true); // Convert to PEM format

        const payload = {
          user: 'sampleUser',
          iat: Math.floor(Date.now() / 1000) - 30000, // Issue time in the past
          exp: Math.floor(Date.now() / 1000) - 1800  // Expire time in the past
        };

        const options = {
          algorithm: 'RS256',
          header: {
            typ: 'JWT',
            alg: 'RS256',
            kid: joseKey.kid,
          },
        };

        // Generate JWT with the expired key
        jwt.sign(payload, pemKey, options, (err, expiredToken) => {
          if (err) {
            console.error("Error signing expired JWT:", err);
            return;
          }
          console.log("Expired JWT generated:", expiredToken);
          // Handle the expiredToken as needed
        });
      } else {
        console.log("No expired key found.");
      }
    } catch (joseError) {
      console.error("Error processing the key:", joseError);
    }
  });
}



app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});


// Middleware to ensure only GET requests are allowed for /jwks
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Corrected JWKS endpoint
app.get('/.well-known/jwks.json', (req, res) => {
  db.all(`SELECT * FROM keys WHERE exp > ?`, [Math.floor(Date.now() / 1000)], (err, rows) => {
    if (err) {
      console.error("Error querying the database for keys:", err.message);
      return res.status(500).send("Internal Server Error");
    }

    // Assuming rows are successfully fetched from the database
    const jwks = rows.map(row => {
      const key = JSON.parse(row.key);
      // Convert each key to JWK format suitable for JWKS
      // Note: This assumes the stored key JSON is already in JWK format
      return {
        kty: key.kty,
        use: key.use,
        kid: key.kid,
        alg: key.alg,
        n: key.n,
        e: key.e,
      };
    });

    res.setHeader('Content-Type', 'application/json');
    res.json({ keys: jwks });
  });
});


app.post('/auth', (req, res) => {
  // Determine if an expired key is requested
  const expired = req.query.expired === 'true';

  // SQL to fetch the correct key based on the `expired` parameter
  const sql = expired ?
      "SELECT * FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1" :
      "SELECT * FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1";

  // Fetch the key from the database
  db.get(sql, [Math.floor(Date.now() / 1000)], async (err, row) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send("Error fetching key from the database.");
    }
    if (!row) {
      return res.status(404).send("No appropriate key found.");
    }

    // Deserialize the key and convert to PEM for signing
    try {
      const joseKey = await jose.JWK.asKey(JSON.parse(row.key));
      const pemKey = joseKey.toPEM(true);

      // Define JWT payload
      const payload = {
        user: 'sampleUser',
        iat: Math.floor(Date.now() / 1000),
        exp: expired ? Math.floor(Date.now() / 1000) - 1800 : Math.floor(Date.now() / 1000) + 3600,
      };

      // Define JWT options
      const options = {
        algorithm: 'RS256',
        header: {
          typ: 'JWT',
          alg: 'RS256',
          kid: joseKey.kid,
        },
      };

      // Sign and send the JWT
      jwt.sign(payload, pemKey, options, (err, token) => {
        if (err) {
          console.log(err);
          return res.status(500).send("Error signing token.");
        }
        res.send(token);
      });
    } catch (error) {
      console.error("Error handling key for JWT signing:", error);
      res.status(500).send("Error processing key.");
    }
  });
});


generateKeyPairs().then(() => {
  generateToken()
  generateExpiredJWT()
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});
