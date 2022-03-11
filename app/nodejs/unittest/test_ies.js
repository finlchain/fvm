//
const fs = require('fs');

//
const cryptoSsl = require("./build/Release/crypto-ssl");

let test = async () => {
    ////////////////////////////////////////////////////////////////////
    //
    // console.log("========= x25519 Test =========");
    // cryptoSsl.x25519Test();

    ////////////////////////////////////////////////////////////////////
    //
    // console.log("========= x25519 Key Gen =========");
    // let pemPath = "./key/";
    // cryptoSsl.x25519KeyGenPem(pemPath);

    ////////////////////////////////////////////////////////////////////
    //
    let plaintext = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263';
    let enc_msg;

    //
    console.log("========= x25519 Hex Enc & Dec =========");
    //
    let xa_ed_privkey = cryptoSsl.ed25519GetPrikey("./key/xa_x_privkey.pem");
    console.log("xa_x_privkey : " + xa_ed_privkey);
    
    let xa_ed_pubkey = cryptoSsl.ed25519GetPubkey("./key/xa_x_pubkey.pem");
    console.log("xa_x_pubkey : " + xa_ed_pubkey);

    let xb_ed_privkey = cryptoSsl.ed25519GetPrikey("./key/xb_x_privkey.pem");
    console.log("xb_x_privkey : " + xb_ed_privkey);
    
    let xb_ed_pubkey = cryptoSsl.ed25519GetPubkey("./key/xb_x_pubkey.pem");
    console.log("xb_x_pubkey : " + xb_ed_pubkey);

    ////////////////////////////////////////////////////////////////////
    // 
    console.log("");
    console.log("");
    console.log("");
    console.log("========= x25519HexEnc =========");
    //
    enc_msg = cryptoSsl.x25519HexEnc(xa_ed_privkey, xb_ed_pubkey, plaintext, plaintext.length);
    console.log("enc_msg : " + enc_msg);

    console.log("");
    console.log("");
    console.log("");
    console.log("========= x25519HexDec =========");
    //
    plaintext = cryptoSsl.x25519HexDec(xb_ed_privkey, xa_ed_pubkey, enc_msg, enc_msg.length);
    console.log("plaintext : " + plaintext);

    ////////////////////////////////////////////////////////////////////
    //
    console.log("");
    console.log("");
    console.log("");
    
    console.log("========= AES Pem to Fin =========");
    //
    const seed = "mofas+pwd";
    const seedLen = seed.length;

    //
    const xaEdPrivkeyPemPath = "./key/xa_x_privkey.pem";
    const xaEdPrivkeyFinPath = "./key/xa_x_privkey.fin";
    const xaEdPubkeyPath = "./key/xa_x_pubkey.pem";

    //
    let xaEdPrivkeyEncFile = cryptoSsl.aesEncFile(xaEdPrivkeyPemPath, xaEdPrivkeyFinPath, seed, seedLen);
    if(xaEdPrivkeyEncFile === true) console.log("success");
    else console.log("fail");

    let xaEdPrivkeyDecFile = cryptoSsl.aesDecFile(xaEdPrivkeyFinPath, seed, seedLen);
    console.log("xaEdPrivkeyDecFile : " + xaEdPrivkeyDecFile);
    
    let xaEdPubkeyFile = fs.readFileSync(xaEdPubkeyPath, 'binary');
    console.log("xaEdPubkeyFile : " + xaEdPubkeyFile);

    //
    const xbEdPrivkeyPemPath = "./key/xb_x_privkey.pem";
    const xbEdPrivkeyFinPath = "./key/xb_x_privkey.fin";
    const xbEdPubkeyPath = "./key/xb_x_pubkey.pem";

    //
    let xbEdPrivkeyEncFile = cryptoSsl.aesEncFile(xbEdPrivkeyPemPath, xbEdPrivkeyFinPath, seed, seedLen);
    if(xbEdPrivkeyEncFile === true) console.log("success");
    else console.log("fail");

    let xbEdPrivkeyDecFile = cryptoSsl.aesDecFile(xbEdPrivkeyFinPath, seed, seedLen);
    console.log("xbEdPrivkeyDecFile : " + xbEdPrivkeyDecFile);

    let xbEdPubkeyFile = fs.readFileSync(xbEdPubkeyPath, 'binary');
    console.log("xbEdPubkeyFile : " + xbEdPubkeyFile);

    //
    console.log("");
    console.log("");
    console.log("");
    console.log("========= x25519PemEnc =========");
    //
    enc_msg = cryptoSsl.x25519PemEnc(xaEdPrivkeyDecFile, xbEdPubkeyFile, plaintext, plaintext.length);
    console.log("enc_msg : " + enc_msg);

    console.log("");
    console.log("");
    console.log("");
    console.log("========= x25519PemDec =========");
    plaintext = cryptoSsl.x25519PemDec(xbEdPrivkeyDecFile, xaEdPubkeyFile, enc_msg, enc_msg.length);
    console.log("plaintext : " + plaintext);


    ////////////////////////////////////////////////////////////////////
    // 
    console.log("");
    console.log("");
    console.log("");
    console.log("========= x25519MixEnc =========");
    //
    enc_msg = cryptoSsl.x25519MixEnc(xaEdPrivkeyDecFile, xb_ed_pubkey, plaintext, plaintext.length);
    console.log("enc_msg : " + enc_msg);

    console.log("");
    console.log("");
    console.log("");
    console.log("========= x25519MixDec =========");
    //
    plaintext = cryptoSsl.x25519MixDec(xbEdPrivkeyDecFile, xa_ed_pubkey, enc_msg, enc_msg.length);
    console.log("plaintext : " + plaintext);

    //
    console.log("");
    console.log("");
    console.log("");
    console.log("========= x25519Skey =========");
    let sharedkey;

    sharedkey = cryptoSsl.x25519HexSkey(xa_ed_privkey, xb_ed_pubkey);
    console.log("x25519HexSkey : " + sharedkey);
    
    sharedkey = cryptoSsl.x25519PemSkey(xaEdPrivkeyDecFile, xbEdPubkeyFile);
    console.log("x25519PemSkey : " + sharedkey);

    sharedkey = cryptoSsl.x25519MixSkey(xaEdPrivkeyDecFile, xb_ed_pubkey);
    console.log("x25519MixSkey : " + sharedkey);
}

test();