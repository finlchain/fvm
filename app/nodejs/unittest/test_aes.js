//
const fs = require('fs');

// const addon = require("./build/Release/ADDON");
const cryptoSsl = require("./build/Release/crypto-ssl");

//
const util = require("./test_util.js");

//
// cryptoSsl.aesTest();

//
const seedPath = "./test/seed";
const pw = "12345";
const pwLen = pw.length;
const pwPath = "./test/enc_pw";

// ** Encrypt Passwd
// *** return true : success, false : fail
let testEncPw = cryptoSsl.aesEncPw(seedPath, pw, pwLen, pwPath);
if(testEncPw === true) console.log("success");
else console.log("fail");


// ** Decrypt Passwd
// *** return passwd
let testDecPw = cryptoSsl.aesDecPw(seedPath, pwPath);
console.log(testDecPw);

//
const srcPath = "./test/ed_privkey.pem";
const seed = "mofas+pwd";
const seedLen = seed.length;
const dstPath = "./test/ed_privkey.fin";

let testEncFile = cryptoSsl.aesEncFile(srcPath, dstPath, seed, seedLen);
if(testEncFile === true) console.log("success");
else console.log("fail");

let testDecFile = cryptoSsl.aesDecFile(dstPath, seed, seedLen);
console.log(testDecFile);

let encBinaryStr = fs.readFileSync(dstPath, 'binary');
//
const encBinary = Buffer.from(encBinaryStr, 'ascii');
var encBinaryHexStr = encBinary.toString('hex');
// console.log(encBinaryHexStr);


const testDstPath = "./test/test_ed_privkey.fin";
fs.writeFileSync(testDstPath, encBinaryStr, 'binary');

let testDecBinary = cryptoSsl.aesDecBinary(encBinaryHexStr, seed, seedLen);
console.log(testDecBinary);