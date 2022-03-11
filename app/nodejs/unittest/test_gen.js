//
const cryptoSsl = require("./build/Release/crypto-ssl");

/////////////////////////////////////////////////////////////////////
// Shard
{
    console.log("========= Shard PW Enc =========");
    const seedPath = "./test/seed";
    const pw = "+purishard135@$";
    const pwLen = pw.length;
    const pwPath = "./test/pw_shard.fin";
    
    // ** Encrypt Passwd
    // *** return true : success, false : fail
    let testEncPw = cryptoSsl.aesEncPw(seedPath, pw, pwLen, pwPath);
    if(testEncPw === true) console.log("success");
    else console.log("fail");
    
    // ** Decrypt Passwd
    // *** return passwd
    let testDecPw = cryptoSsl.aesDecPw(seedPath, pwPath);
    console.log(testDecPw);
}

/////////////////////////////////////////////////////////////////////
// Replication
{
    console.log("========= Replication PW Enc =========");
    const seedPath = "./test/seed";
    const pw = "+purirepl@$135";
    const pwLen = pw.length;
    const pwPath = "./test/pw_repl.fin";
    
    // ** Encrypt Passwd
    // *** return true : success, false : fail
    let testEncPw = cryptoSsl.aesEncPw(seedPath, pw, pwLen, pwPath);
    if(testEncPw === true) console.log("success");
    else console.log("fail");
    
    // ** Decrypt Passwd
    // *** return passwd
    let testDecPw = cryptoSsl.aesDecPw(seedPath, pwPath);
    console.log(testDecPw);
}

{
    console.log("========= Replication NN PW Enc =========");
    const seedPath = "./test/seed";
    const pw = "+purirpnn@$135";
    const pwLen = pw.length;
    const pwPath = "./test/pw_nn.fin";
    
    // ** Encrypt Passwd
    // *** return true : success, false : fail
    let testEncPw = cryptoSsl.aesEncPw(seedPath, pw, pwLen, pwPath);
    if(testEncPw === true) console.log("success");
    else console.log("fail");
    
    // ** Decrypt Passwd
    // *** return passwd
    let testDecPw = cryptoSsl.aesDecPw(seedPath, pwPath);
    console.log(testDecPw);
}

{
    console.log("========= Replication ISAG PW Enc =========");
    const seedPath = "./test/seed";
    const pw = "+purirpisag@$135";
    const pwLen = pw.length;
    const pwPath = "./test/pw_isag.fin";
    
    // ** Encrypt Passwd
    // *** return true : success, false : fail
    let testEncPw = cryptoSsl.aesEncPw(seedPath, pw, pwLen, pwPath);
    if(testEncPw === true) console.log("success");
    else console.log("fail");
    
    // ** Decrypt Passwd
    // *** return passwd
    let testDecPw = cryptoSsl.aesDecPw(seedPath, pwPath);
    console.log(testDecPw);
}

/////////////////////////////////////////////////////////////////////
// Redis
{
    console.log("========= Redis PW Enc =========");
    const seedPath = "./test/seed";
    const pw = "pure+pwd";
    const pwLen = pw.length;
    const pwPath = "./test/pw_redis.fin";
    
    // ** Encrypt Passwd
    // *** return true : success, false : fail
    let testEncPw = cryptoSsl.aesEncPw(seedPath, pw, pwLen, pwPath);
    if(testEncPw === true) console.log("success");
    else console.log("fail");
    
    // ** Decrypt Passwd
    // *** return passwd
    let testDecPw = cryptoSsl.aesDecPw(seedPath, pwPath);
    console.log(testDecPw);
}

/////////////////////////////////////////////////////////////////////
// MariaDB
{
    console.log("========= IS Maria PW Enc =========");
    const seedPath = "./test/seed";
    const pw = "puriis+pwd";
    const pwLen = pw.length;
    const pwPath = "./test/is_pw_maria.fin";

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
    console.log("========= IS ED25519 Key Gen Pem =========");
    let retEdV1KeyGenPem = cryptoSsl.ed25519KeyGenPem("./test/is_");
    console.log("retEdV1KeyGenPem : " + retEdV1KeyGenPem);
    console.log(" ");
    console.log(" ");
    
    // Test
    const srcPath = "./test/is_ed_privkey.pem";
    const seed = pw;
    const seedLen = seed.length;
    const dstPath = "./test/is_ed_privkey.fin";

    console.log("seed : " + seed);
    console.log("seedLen : " + seedLen);
    
    let testEncFile = cryptoSsl.aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile === true) console.log("success");
    else console.log("fail");
    
    let testDecFile = cryptoSsl.aesDecFile(dstPath, seed, seedLen);
    console.log(testDecFile);
}

{
    console.log("========= NN Maria PW Enc =========");
    const seedPath = "./test/seed";
    const pw = "purinn+pwd";
    const pwLen = pw.length;
    const pwPath = "./test/nn_pw_maria.fin";

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
    console.log("========= NN ED25519 Key Gen Pem =========");
    let retEdV1KeyGenPem = cryptoSsl.ed25519KeyGenPem("./test/nn_");
    console.log("retEdV1KeyGenPem : " + retEdV1KeyGenPem);
    console.log(" ");
    console.log(" ");
    //
    const srcPath = "./test/nn_ed_privkey.pem";
    const seed = pw;
    const seedLen = seed.length;
    const dstPath = "./test/nn_ed_privkey.fin";

    console.log("seed : " + seed);
    console.log("seedLen : " + seedLen);
    
    let testEncFile = cryptoSsl.aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile === true) console.log("success");
    else console.log("fail");
    
    let testDecFile = cryptoSsl.aesDecFile(dstPath, seed, seedLen);
    console.log(testDecFile);
}

{
    console.log("========= ISAG Maria PW Enc =========");
    const seedPath = "./test/seed";
    const pw = "puriisag+pwd";
    const pwLen = pw.length;
    const pwPath = "./test/isag_pw_maria.fin";
    
    // ** Encrypt Passwd
    // *** return true : success, false : fail
    let testEncPw = cryptoSsl.aesEncPw(seedPath, pw, pwLen, pwPath);
    if(testEncPw === true) console.log("success");
    else console.log("fail");
    
    // ** Decrypt Passwd
    // *** return passwd
    let testDecPw = cryptoSsl.aesDecPw(seedPath, pwPath);
    console.log(testDecPw);
}

{
    console.log("========= FBN Maria PW Enc =========");
    const seedPath = "./test/seed";
    const pw = "purifbn+pwd";
    const pwLen = pw.length;
    const pwPath = "./test/fbn_pw_maria.fin";
    
    // ** Encrypt Passwd
    // *** return true : success, false : fail
    let testEncPw = cryptoSsl.aesEncPw(seedPath, pw, pwLen, pwPath);
    if(testEncPw === true) console.log("success");
    else console.log("fail");
    
    // ** Decrypt Passwd
    // *** return passwd
    let testDecPw = cryptoSsl.aesDecPw(seedPath, pwPath);
    console.log(testDecPw);
}
