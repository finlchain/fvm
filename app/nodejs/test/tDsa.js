//
const fs = require('fs');

//
const cryptoSsl = require("./../linux/build/Release/crypto-ssl");

// EDDSA
const edpubkey1 = "8d659aa97dc613b59a870a9bd4497d1d5b8cabc4b3d4d5cd967af205c72ac450";
const edprvkey1 = "1e3a01f19d240e8e585ca6a9e22952aec0f1671c0fae22fc9093a962be72d6de";
// const eddata1 = "fab3362e57027ad6d4d2447b479756254cb7781762c906a4cb69ea20c7939b8c";
const eddata1 = "fab3";

module.exports.testEddsa = async () => {
    const ret = await cryptoSsl.eddsaTestHex(edprvkey1, edpubkey1, eddata1);
    console.log("ret : " + ret);
}

//
module.exports.testCase = async () => {
    this.testEddsa();
}