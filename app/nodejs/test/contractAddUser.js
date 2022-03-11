//
const fs = require('fs');

//
const cryptoSsl = require("./../linux/build/Release/crypto-ssl");

//
const define = require("../njsConn/config/define.js");
// const contractUtil = require("../njsConn/core/contract/contractUtil.js");
const cryptoUtil = require("../njsConn/core/utils/cryptoUtil.js");

//
let contractFilePath = './../../test/key/crypto/out/c_add_user.crd';

//
let ownerPrikeyFilePath = './../../../../conf/test/key/ed/key_09/ed_privkey.fin';
let ownerPubkeyFilePath = './../../../../conf/test/key/ed/key_09/ed_pubkey.pem';
let superPubkeyFilePath = './../../../../conf/test/key/ed/key_09/ed_pubkey.pem';

//
module.exports.makeContentsJson = async () => {
    ////////////////////////////////////////////////////////////////////
    // ownerPrikey
    // let ownerPrikey = fs.readFileSync(ownerPrikeyFilePath, 'binary');

    // ownerPrikeyPw
    let ownerPrikeyPw = "asdfQWER1234!@#$";

    // let stdin = process.openStdin();
    // console.log('password for *.fin : ');
    // stdin.addListener("data", function(d) {
    //     // note:  d is an object, and when converted to a string it will
    //     // end with a linefeed.  so we (rather crudely) account for that  
    //     // with toString() and then trim() 
    //     console.log("you entered: [" +  d.toString().trim() + "]");

    //     ownerPrikeyPw = d.toString().trim();
    // });

    //

    //
    let keySeed = ownerPrikeyPw;
    let dec = cryptoSsl.aesDecFile(ownerPrikeyFilePath, keySeed, keySeed.length);
    console.log('dec : ' + dec);

    let ownerPrikeyHex = cryptoSsl.ed25519GetPrikeyByPemStr(dec);
    console.log('ownerPrikeyHex : ' + ownerPrikeyHex);

    // ownerPubkey
    let ownerPubkey = cryptoSsl.ed25519GetPubkey(ownerPubkeyFilePath);
    console.log("ownerPubkey : " + ownerPubkey);

    // superPubkey
    let superPubkey = cryptoSsl.ed25519GetPubkey(superPubkeyFilePath);
    console.log("superPubkey : " + superPubkey);

    ////////////////////////////////////////////////////////////////////
    //
    let contractJson = {
        create_tm : cryptoSsl.utcCurrMS(), //util.getDateMS().toString(),
        fintech : define.CONTRACT_DEFINE.FINTECH.NON_FINANCIAL_TX,
        privacy : define.CONTRACT_DEFINE.PRIVACY.PUBLIC,
        fee : define.CONTRACT_DEFINE.FEE_DEFAULT,
        from_account : define.CONTRACT_DEFINE.FROM_DEFAULT,
        to_account : define.CONTRACT_DEFINE.TO_DEFAULT,
        action : define.CONTRACT_DEFINE.ACTIONS.DEFAULT.ADD_USER,
        contents : {
            owner_pk : define.CONTRACT_DEFINE.ED_PUB_IDX + ownerPubkey,
            super_pk : define.CONTRACT_DEFINE.ED_PUB_IDX + superPubkey,
            account_id : 'USER_09' // + util.getRandomNumBuf(6).toString('hex')
        },
        memo : ""
    };

    //
    let sig = cryptoUtil.genSign(contractJson, ownerPrikeyHex);
    contractJson.sig = sig;
    contractJson.signed_pubkey = define.CONTRACT_DEFINE.ED_PUB_IDX + ownerPubkey;

    //
    let plaintext = JSON.stringify(contractJson);
    // console.log("plaintext.length : " + plaintext.length);
    console.log("plaintext : " + plaintext);

    fs.writeFileSync(contractFilePath, plaintext, 'binary');
    // fs.writeFileSync(contractFilePath, plaintext);

    return plaintext;
}

module.exports.testCase = async () => {
    this.makeContentsJson();
}
