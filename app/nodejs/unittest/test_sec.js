//
const cryptoSsl = require("./../linux/build/Release/crypto-ssl");

{
    //
    let seed = 'abcdef';
    let seedLen = seed.length;

    //
    let plaintextStr = 'finl test ok?=Zfewoscfsaqodfsf adf2qqer';
    console.log('plaintextStr : ' + plaintextStr);

    const plaintextStrBuf = Buffer.from(plaintextStr, 'utf8');
    let plaintextHexStr = plaintextStrBuf.toString('hex');
    console.log('plaintextHexStr : ' + plaintextHexStr);

    //
    let ciphertextHexStr = cryptoSsl.aes256CbcEnc(plaintextHexStr, seed);
    console.log('ciphertextHexStr : ' + ciphertextHexStr);

    //
    let retPlaintextHexStr = cryptoSsl.aes256CbcDec(ciphertextHexStr, seed);
    console.log('retPlaintextHexStr : ' + retPlaintextHexStr);

    let retPlaintextStr = Buffer.from(retPlaintextHexStr, 'hex');
    console.log('retPlaintextStr : ' + retPlaintextStr);
}
