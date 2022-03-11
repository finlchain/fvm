//
const fs = require('fs');

//
const cryptoSsl = require("./build/Release/crypto-ssl");

let test = async () => {
    //////////////////////////////////////////////////////////////////
    
    console.log("========= x25519 Key Gen =========");
    // console.log("process.argv.length : " + process.argv.length);
    // console.log("process.argv : " + process.argv);
    // console.log("process.argv[0] : " + process.argv[0]);
    // console.log("process.argv[1] : " + process.argv[1]);
    // console.log("process.argv[2] : " + process.argv[2]);

    if (process.argv.length === 3)
    {
        // let pemPath = "./key/";
        let pemPath = process.argv[2];

        cryptoSsl.x25519KeyGenPem(pemPath);

        let xa_ed_pubkey = cryptoSsl.ed25519GetPubkey(pemPath + "x_pubkey.pem");
        console.log("xa_ed_pubkey : " + xa_ed_pubkey);
    }
    else
    {
        console.log("Error - Argument Length should be 3.");
    }
}

test();