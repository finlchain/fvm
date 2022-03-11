//
const cryptoSsl = require("./../linux/build/Release/crypto-ssl");

module.exports.REGEX = {
    'NEW_LINE_REGEX': /\n+/,
    'WHITE_SPACE_REGEX': /\s/,
    'IP_ADDR_REGEX': /^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$/,
    'HASH_REGEX': /^[a-z0-9+]{5,65}$/,
    'HEX_STR_REGEX' : /^[a-fA-F0-9]+$/,
    // 'PW_STRONG_REGEX' : /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})/,
    // 'PW_STRONG_REGEX' : /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?!.*[\s(|])(?=.*[!@#\$%\^&\*])(?=.{8,})/,
    'PW_STRONG_REGEX' : /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?!.*[])(?=.*[!@#\$%\^&\*])(?=.{8,})/,
    'PW_MEDIUM_REGEX' : /^(((?=.*[a-z])(?=.*[A-Z]))|((?=.*[a-z])(?=.*[0-9]))|((?=.*[A-Z])(?=.*[0-9])))(?=.{6,})/,
    'FINL_ADDR_REGEX' : /^(FINL){1}[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{1, }$/,
    'PURE_ADDR_REGEX' : /^(PURE){1}[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{1, }$/
}

//
console.log("length : " + process.argv.length);

if (process.argv.length === 3)
{
    //
    const seed = process.argv[2];
    const seedLen = seed.length;
    console.log("seed : " + seed);
    console.log("seedLen : " + seedLen);
    
    let regexResult = this.REGEX.PW_STRONG_REGEX.test(seed);
    if(regexResult) console.log("Password is VALID.");
    else console.log("Password is NOT VALID.");

    //
    let pemPath = "./";

    //
    let pw = "신의 축복이 있기를.";
    let mnemonic1 = "신의 축복이 있기를.";
    let mnemonic2 = "신의 축복이 있기를.";
    let rand_num = 0;
    
    {
        let ret = cryptoSsl.ecR1KeyGenPemWithMnemonic(pemPath, pw, mnemonic1, mnemonic2, rand_num);
        if(ret > 0) console.log("ecR1KeyGenPemWithMnemonic success");
        else console.log("ecR1KeyGenPemWithMnemonic fail");

        //
        const srcPath = "./privkey.pem";
        const dstPath = "./privkey.fin";
        
        let testEncFile = cryptoSsl.aesEncFile(srcPath, dstPath, seed, seedLen);
        if(testEncFile === true) console.log("aesEncFile success");
        else console.log("aesEncFile fail");

        let testDecFile = cryptoSsl.aesDecFile(dstPath, seed, seedLen);
        console.log(testDecFile);
    }

    {
        let ret = cryptoSsl.ecK1KeyGenPemWithMnemonic(pemPath, pw, mnemonic1, mnemonic2, rand_num);
        if(ret > 0) console.log("ecK1KeyGenPemWithMnemonic success");
        else console.log("ecK1KeyGenPemWithMnemonic fail");

        //
        const srcPath = "./privkey.pem";
        const dstPath = "./privkey.fin";
        
        let testEncFile = cryptoSsl.aesEncFile(srcPath, dstPath, seed, seedLen);
        if(testEncFile === true) console.log("aesEncFile success");
        else console.log("aesEncFile fail");

        let testDecFile = cryptoSsl.aesDecFile(dstPath, seed, seedLen);
        console.log(testDecFile);
    }

    // {
    //     let ret = cryptoSsl.ed25519KeyGenPemWithMnemonic(pemPath, pw, mnemonic1, mnemonic2, rand_num);
    //     if(ret === true) console.log("ed25519KeyGenPemWithMnemonic success");
    //     else console.log("ed25519KeyGenPemWithMnemonic fail");

    //     // let ret = cryptoSsl.ed25519KeyGenPem(pemPath);
    //     // let ret = cryptoSsl.ed25519KeyGenPemPubkey(pemPath);
    //     // let ret = cryptoSsl.ed25519KeyGenFin(pemPath, seed, seedLen);
    //     // if(ret === true) console.log("ed25519KeyGenPem success");
    //     // else console.log("ed25519KeyGenPem fail");

    //     //
    //     const srcPath = "./ed_privkey.pem";
    //     const dstPath = "./ed_privkey.fin";
        
    //     let testEncFile = cryptoSsl.aesEncFile(srcPath, dstPath, seed, seedLen);
    //     if(testEncFile === true) console.log("aesEncFile success");
    //     else console.log("aesEncFile fail");

    //     let testDecFile = cryptoSsl.aesDecFile(dstPath, seed, seedLen);
    //     console.log(testDecFile);
    // }

    {
        let ret = cryptoSsl.ed25519KeyGenFinWithMnemonic(pemPath, pw, mnemonic1, mnemonic2, rand_num, seed, seedLen);
        if(ret > 0) console.log("ed25519KeyGenFinWithMnemonic success");
        else console.log("ed25519KeyGenFinWithMnemonic fail");

        //
        const srcPath = "./ed_privkey.pem";
        const dstPath = "./ed_privkey.fin";
        
        // let testEncFile = cryptoSsl.aesEncFile(srcPath, dstPath, seed, seedLen);
        // if(testEncFile === true) console.log("aesEncFile success");
        // else console.log("aesEncFile fail");

        let testDecFile = cryptoSsl.aesDecFile(dstPath, seed, seedLen);
        console.log(testDecFile);
    }

    {
        let ret = cryptoSsl.x25519KeyGenPemWithMnemonic(pemPath, pw, mnemonic1, mnemonic2, rand_num);
        if(ret > 0) console.log("x25519KeyGenPemWithMnemonic success");
        else console.log("x25519KeyGenPemWithMnemonic fail");

        //
        const srcPath = "./x_privkey.pem";
        const dstPath = "./x_privkey.fin";
        
        let testEncFile = cryptoSsl.aesEncFile(srcPath, dstPath, seed, seedLen);
        if(testEncFile === true) console.log("aesEncFile success");
        else console.log("aesEncFile fail");

        let testDecFile = cryptoSsl.aesDecFile(dstPath, seed, seedLen);
        console.log(testDecFile);
    }

    // //////////////////////////////////////////////////////////////////////
    // //
    // {
    //     // cryptoSsl.utf8Test("한국이");
    //     let utf8Str;

    //     utf8Str = cryptoSsl.charToUtf8("한국이");
    //     console.log(utf8Str);

    //     utf8Str = cryptoSsl.charToUtf8("ABCDabcd");
    //     console.log(utf8Str);
    // }

    // //////////////////////////////////////////////////////////////////////
    //
    {
        let rand_num = cryptoSsl.keyCreateMasterChainCode(pw, mnemonic1, mnemonic2);
        console.log(rand_num);

        let masterChainCode = cryptoSsl.keyRestoreMasterChainCode(pw, mnemonic1, mnemonic2, rand_num);
        console.log(masterChainCode);
    }

    //
    {
        let masterChainCodeStrLen = cryptoSsl.keyCreateMasterChainCodeOri(mnemonic1, pw);
        console.log(masterChainCodeStrLen);

        let masterChainCode = cryptoSsl.keyRestoreMasterChainCode(mnemonic1, pw);
        console.log(masterChainCode);
    }

    //
    {
        let path = './';
        let mnemonic = "ice keep intact visual turn much soon essay setup arrive execute senior";
        let pw = 'abcdQWER1234!@';
        let seed = pw;

        console.log("path : " + path);
        console.log("mnemonic : " + mnemonic);
        console.log("pw : " + pw);
        console.log("seed : " + seed);
        console.log("seed.length : " + seed.length);

        ret1 = cryptoSsl.ed25519KeyGenFinWithMnemonicOri(path, mnemonic, pw, seed, seed.length);
        console.log("ret1 :" + ret1);
        ret2 = cryptoSsl.x25519KeyGenPemWithMnemonicOri(path, mnemonic, pw);
        console.log("ret2 :" + ret2);
    }
}



