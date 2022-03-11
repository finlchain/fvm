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

// if (process.argv.length === 3)
{
    //
    // const seed = process.argv[2];
    const seed = 'asdfQWER1234!@#$';
    const seedLen = seed.length;
    console.log("seed : " + seed);
    
    let regexResult = this.REGEX.PW_STRONG_REGEX.test(seed);
    if(regexResult) console.log("Password is VALID.");
    else console.log("Password is NOT VALID.");
    
    //
    // const dstPath = "./../../../test/key/crypto/out/ed_privkey.fin";
    // const dstPath = "./../../../../../conf/test/key/ed/key_06/ed_privkey.fin";
    const dstPath = "./../../../../../conf/test/key/ed/ed_privkey.fin";
    console.log("dstPath : " + dstPath);

    let testDecFile = cryptoSsl.aesDecFile(dstPath, seed, seedLen);
    console.log(testDecFile);
}



