//
const fs = require('fs');

//
const cryptoSsl = require("./build/Release/crypto-ssl");

let test = async () => {
    ////////////////////////////////////////////////////////////////////
    //
    console.log("========= ARIA Test =========");
    cryptoSsl.ariaTest();
}

test();