//
const fs = require('fs');

//
const cryptoSsl = require("./../linux/build/Release/crypto-ssl");

module.exports.testGetKey = async () => {
    //
    let testKeyPath = './../keyStore.json';
    let testKey = fs.readFileSync(testKeyPath, 'binary');
    console.log('testKey : ' + testKey);

    //
    let testKeyJson = JSON.parse(testKey);


    //
    console.log('edPubkeyPem : ' + testKeyJson.edPubkeyPem);
    //
    let ed_pubkey = cryptoSsl.ed25519GetPubkeyNoFile(testKeyJson.edPubkeyPem);
    console.log('ed_pubkey : ' + ed_pubkey);
}

//
module.exports.testCase = async () => {
    this.testGetKey();
}