//
const config = require("./../../config/config.js");
const define = require("./../../config/define.js");

//
const contractUtil = require("./../contract/contractUtil.js");

//
const cryptoSsl = require("./../../../linux/build/Release/crypto-ssl");
const verifier = require("./../../../linux/build/Release/crypto-ssl");

//
module.exports.genSign = (contractJson, prikeyHex) => {
    const mergedBuf = contractUtil.signBufferGenerator(contractJson);
    // console.log("mergedBuf : " + mergedBuf);

    let inputData = cryptoSsl.genSha256Str(mergedBuf);
    console.log("inputData : " + inputData);

    //
    let signature = cryptoSsl.eddsaSignHex(inputData, prikeyHex);

    return signature;
}

module.exports.verifySign = (pubkeyHex, contractJson) => {
    // Owner Public Key
    //
    if (pubkeyHex.length !== define.SEC_DEFINE.PUBLIC_KEY_LEN)
    {
        return false;
    }

    //
    const mergedBuffer = contractUtil.signBufferGenerator(contractJson);

    let inputData = cryptoSsl.genSha256Str(mergedBuffer);
    // console.log("verifySign - inputData : " + inputData);

    //
    var verifyRet;

    if (pubkeyHex.slice(define.SEC_DEFINE.KEY_DELIMITER.START_INDEX, define.SEC_DEFINE.KEY_DELIMITER.DELIMITER_LEN) 
                        === define.SEC_DEFINE.KEY_DELIMITER.ED25519_DELIMITER)
    {
        let realPubkeyHex = pubkeyHex.slice(define.SEC_DEFINE.KEY_DELIMITER.DELIMITER_LEN);
        // console.log("verifySign - realPubkeyHex : " + realPubkeyHex);
        // console.log("verifySign - signature : " + contractJson.sig);
        verifyRet = verifier.eddsaVerifyHex(inputData, contractJson.sig, realPubkeyHex);
    }
    else
    {
        var sigR = contractJson.sig.slice(define.SEC_DEFINE.SIG.R_START_INDEX, define.SEC_DEFINE.SIG.R_LEN);
        var sigS = contractJson.sig.slice(define.SEC_DEFINE.SIG.S_START_INDEX, define.SEC_DEFINE.SIG.S_LEN);

        verifyRet = verifier.ecdsaR1VerifyHex(inputData, sigR, sigS, pubkeyHex);
        if (verifyRet === false)
        {
            verifyRet = verifier.EcdsaK1Verify(inputData, sigR, sigS, pubkeyHex);
        }
    }

    return verifyRet;
}
