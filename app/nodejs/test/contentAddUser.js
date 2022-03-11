//
const fs = require('fs');

//
const cryptoSsl = require("./../linux/build/Release/crypto-ssl");

//
const config = require("./../njsConn/config/config.js");
const define = require("./../njsConn/config/define.js");

const contentsEnc = require("../njsConn/core/contents/contentsEnc.js");

//
let contentsFilePath = './../../test/key/crypto/out/xa_add_user.ctd'; // contents decrypted
let contentsEncFilePath = './../../test/key/crypto/out/xa_add_user_p1.cte'; // contents encrypted

//
let ownerPrikeyFilePath = './../../../../conf/test/key/ed/key_09/ed_privkey.fin';
let ownerPubkeyFilePath = './../../../../conf/test/key/ed/key_09/ed_pubkey.pem';
let superPubkeyFilePath = './../../../../conf/test/key/ed/key_09/ed_pubkey.pem';

//
let xaXPrikeyFilePath = './../../../../conf/test/key/x25519/09_x_privkey.pem';
let xaXPubkeyFilePath = './../../../../conf/test/key/x25519/09_x_pubkey.pem';
let xbXPrikeyFilePath = './../../../../conf/test/key/x25519/10_x_privkey.pem';
let xbXPubkeyFilePath = './../../../../conf/test/key/x25519/10_x_pubkey.pem';

//
let encJsonFilePath = './../../test/key/crypto/out/xa_add_user_p2.cej'; // contents encrypted json

//
module.exports.makeContentsJson = async () => {
    ////////////////////////////////////////////////////////////////////
    // ownerPrikey
    let ownerPrikey = fs.readFileSync(ownerPrikeyFilePath, 'binary');

    // let ownerPrikeyHexStr = Buffer.from(ownerPrikey,'binary').toString('hex');
    // console.log("ownerPrikeyHexStr : " + ownerPrikeyHexStr);

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

    // ownerPubkey
    let ownerPubkey = cryptoSsl.ed25519GetPubkey(ownerPubkeyFilePath);
    console.log("ownerPubkey : " + ownerPubkey);

    // superPubkey
    let superPubkey = cryptoSsl.ed25519GetPubkey(superPubkeyFilePath);
    console.log("superPubkey : " + superPubkey);

    // accountId
    let accountId = 'user_01';

    //
    let contentsJson = {
        addUser : {
            ownerPrikey : ownerPrikey,
            ownerPrikeyPw : ownerPrikeyPw,
            ownerPubkey : define.CONTRACT_DEFINE.ED_PUB_IDX + ownerPubkey,
            superPubkey : define.CONTRACT_DEFINE.ED_PUB_IDX + superPubkey,
            accountId : accountId
        }
    };

    let plaintext = JSON.stringify(contentsJson);
    // console.log("plaintext.length : " + plaintext.length);
    // console.log("plaintext : " + plaintext);

    fs.writeFileSync(contentsFilePath, plaintext, 'binary');
    // fs.writeFileSync(contentsFilePath, plaintext);

    return plaintext;
}

//
module.exports.makeContentsJsonEnc = async () => {
    ////////////////////////////////////////////////////////////////////
    // Phase 1
    // plaintext
    // let plaintext = fs.readFileSync(contentsFilePath, 'binary');
    let plaintext = fs.readFileSync(contentsFilePath);
    // console.log("plaintext : " + plaintext);

    //
    let plaintextHexStr = Buffer.from(plaintext, 'utf-8').toString('hex');

    // console.log("plaintextHexStr.length : " + plaintextHexStr.length);
    // console.log("plaintextHexStr : " + plaintextHexStr);

    ////////////////////////////////////////////////////////////////////
    // peerXPubkey
    let peerXPubkey;
    // peerXPubkey = cryptoSsl.ed25519GetPubkey(xbXPubkeyFilePath);
    // peerXPubkey = '308b942a2eae006d4adf46761cfa58b3c86c89d76bd0d05b3ee68b480552ab21'; // Pubkey of FBN1
    let retCurlMsg = cryptoSsl.curlHttpGet("http://purichain.com:4000/wallet/key/get/pubkey?x25519", "dummy");
    let culrMsg = JSON.parse(retCurlMsg);
    //
    peerXPubkey = culrMsg.contents.xPubkey;;

    console.log("peerXPubkey : " + peerXPubkey);
    
    // myPrikeyFile
    // let myXPrikeyFile = fs.readFileSync(xaXPrikeyFilePath, 'binary');
    let myXPrikeyFile = fs.readFileSync(xaXPrikeyFilePath);
    // console.log("myXPrikeyFile.length : " + myXPrikeyFile.length);
    // console.log("myXPrikeyFile : " + myXPrikeyFile);

    ////////////////////////////////////////////////////////////////////
    // encMsg
    let encMsg = cryptoSsl.x25519MixEnc(myXPrikeyFile, peerXPubkey, plaintextHexStr, plaintextHexStr.length);
    console.log("encMsg : " + encMsg);

    let encMsg_b = Buffer.from(encMsg, 'hex');
    fs.writeFileSync(contentsEncFilePath, encMsg_b, 'binary');

    ////////////////////////////////////////////////////////////////////
    // Phase 2
    // myXPubkey
    let myXPubkey = cryptoSsl.ed25519GetPubkey(xaXPubkeyFilePath);
    // console.log("myXPubkey : " + myXPubkey);

    //
    let encXPubkeyF = define.CONTRACT_DEFINE.ED_PUB_IDX + peerXPubkey;
    let myXPubkeyF = define.CONTRACT_DEFINE.ED_PUB_IDX + myXPubkey;
    let encJsonMsg = contentsEnc.makeEncJsonMsg(encMsg, encXPubkeyF, myXPubkeyF, encJsonFilePath);

    //
    return encJsonMsg;
}

//
module.exports.makeContentsJsonDec = async (phase) => {
    ////////////////////////////////////////////////////////////////////
    let encMsgHexStr;

    if (phase === 2)
    {
        let encJsonMsg = fs.readFileSync(encJsonFilePath);
        // console.log("encJsonMsg.length : " + encJsonMsg.length);
    
        //
        let encJson = JSON.parse(encJsonMsg);

        encMsgHexStr = encJson.jsonEnc.contentsEnc;
    }
    else // phase === 1
    {
        // encMsg
        let encMsg;

        // encMsg = fs.readFileSync(contentsFilePath, 'binary');
        encMsg = fs.readFileSync(contentsEncFilePath);

        // console.log("encMsg : " + encMsg);

        encMsgHexStr = Buffer.from(encMsg, 'utf-8').toString('hex');
    }

    // console.log("encMsgHexStr.length : " + encMsgHexStr.length);
    // console.log("encMsgHexStr : " + encMsgHexStr);

    ////////////////////////////////////////////////////////////////////
    // peerXPubkey
    let peerXPubkey = cryptoSsl.ed25519GetPubkey(xaXPubkeyFilePath);
    // console.log("peerXPubkey : " + peerXPubkey);

    // myXPrikey
    // let myXPrikeyFile = fs.readFileSync(xbXPrikeyFilePath, 'binary');
    let myXPrikeyFile = fs.readFileSync(xbXPrikeyFilePath);
    // console.log("myXPrikeyFile.length : " + myXPrikeyFile.length);
    // console.log("myXPrikeyFile : " + myXPrikeyFile);

    plaintext = cryptoSsl.x25519MixDec(myXPrikeyFile, peerXPubkey, encMsgHexStr, encMsgHexStr.length);
    // console.log("plaintext.length : " + plaintext.length);
    // console.log("plaintext : " + plaintext);

    return plaintext;
}

module.exports.sendContents = async (filePath) => {
    let plaintext = fs.readFileSync(filePath);
    console.log("plaintext : " + plaintext);

    //
    let plaintextHexStr = Buffer.from(plaintext, 'binary').toString('hex');
    console.log('plaintextHexStr : ' + plaintextHexStr);

    // // for test
    // let plaintext2 = Buffer.from(plaintextHexStr, 'hex');
    // let contractJson = JSON.parse(plaintext2.toString('binary'));
    // console.log('ownerPrikeyPw : ' + contractJson.addUser.ownerPrikeyPw);

    // fs.writeFileSync('./../../test/key/crypto/out/xa_add_user2.ctd', contractJson.addUser.ownerPrikey, 'binary');
    // // ///////////////////////////////////////////////////////////////////////

    let myContents = "contents=" + plaintextHexStr;

    cryptoSsl.curlHttpPost("http://purichain.com:4000/contract/tool/json", myContents);
}

module.exports.sendContentsEnc = async (filePath) => {
    let encJsonMsg = fs.readFileSync(filePath);
    console.log('encJsonMsg : ' + encJsonMsg);

    let myContentsEnc = "contentsEnc=" + encJsonMsg;

    cryptoSsl.curlHttpPost("http://purichain.com:4000/contract/tool/json", myContentsEnc);
}

module.exports.testCase = async () => {
    this.makeContentsJson();
    // this.sendContents(contentsFilePath);
    this.makeContentsJsonEnc();
    // this.makeContentsJsonDec(2);
    this.sendContentsEnc(encJsonFilePath);
}
