declare var USER_POOL_ID: string;
 
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const fetch = require('node-fetch');
 
const pool_region = USER_POOL_ID.split('_')[0];
 
const verifyToken = async (token: any, pem: any): Promise<boolean> => {
 return new Promise((resolve) => {
   jwt.verify(token, pem, function(err: any, payload: any) {
     if (err) {
       resolve(false);
     } else {
       resolve(true);
     }
   });
 });
}
 
export const validateToken = async (token: any): Promise<boolean> => {
  const response = await fetch(`https://cognito-idp.${pool_region}.amazonaws.com/${USER_POOL_ID}/.well-known/jwks.json`);
  const { keys } = await response.json();

  let pems = {};
  for (let i = 0; i < keys.length; i++) {
    // Convert each key to PEM
    let key_id = keys[i].kid;
    let modulus = keys[i].n;
    let exponent = keys[i].e;
    let key_type = keys[i].kty;
    let jwk = { kty: key_type, n: modulus, e: exponent};
    let pem = jwkToPem(jwk);
    pems[key_id] = pem;
  }

  // validate the token
  let decodedJwt = jwt.decode(token, {complete: true});
  if (!decodedJwt) {
    console.log("Not a valid JWT token");
    return false;
  }

  let kid = decodedJwt.header.kid;
  let pem = pems[kid];
  if (!pem) {
    console.log('Invalid pem');
    return false;
  }

  return await verifyToken(token, pem);
}
