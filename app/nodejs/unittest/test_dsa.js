const cryptoSsl = require("./build/Release/crypto-ssl");

////////////////////////////////////////////////////
// ECDSA - R1
// Test 1
const ecrprikey1 = "a69e75d5727c07942eb359fe62afd97c447130ca5b8496048c5c7b94e513da78";
const ecrpubkey1 = "04354d54bdc0b9d94a841cfdd0bd25b9c61b603fbe47d95ecbf8b445614aac559d494b0ab32310c2ac3546fecdec4717d9d3f5c46d1042560f5aeaff95acec7496";
const ecrdata1 = "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd";
// const ecrr1 = "640CFDF9C7E2AB303834DDE4B3E24C9950D846299BB3165648674E600A36F704";
// const ecrs1 = "879C4F4A89E815BF54203537D10D654CFD3DAA6D0E49F73278410F863BFFFE6B";

// Test 2
const ecrpubkey2 = "037A7ED2B23B16B3DFA5351DE64FDB96E339807278A032D700E3D88734BF6E67EC";
const ecrdata2 = "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd";
const ecrr2 = "A7C97CEF667F2D687BFF9457407244E199FCBB9E7C8895BF7C1FC53C79F1AD78";
const ecrs2 = "864AF578EFE3A5866457B57E98ADDDBEF3791C0EF74122F7AB7A849FF03CC960";

////////////////////////////////////////////////////
// EDDSA
// Test 1
const edpubkey1 = "8d659aa97dc613b59a870a9bd4497d1d5b8cabc4b3d4d5cd967af205c72ac450";
const edprvkey1 = "1e3a01f19d240e8e585ca6a9e22952aec0f1671c0fae22fc9093a962be72d6de";
const eddata1 = "fab3362e57027ad6d4d2447b479756254cb7781762c906a4cb69ea20c7939b8c";
// const edsignature1 = "607b8a43fc7bbbff898083bd0bdfe57dbf34212f34adfefe2bfe807a7076337888e04c86bbae4f56d9834d503e5c76b065efad98942bfe04b906796ac3333e09";

// Test 2
const edpubkey2 = "3D32A0648C360D7CB4CFC7BA8579AACD2B5298A5BB324DB6C32134F7AC11AE1E";
const edprvkey2 = "ac8b1e03cb8ef427b896f6e3db96d1db078c67c3f0b8a6f144789fff29546067";
const eddata2 = "fab3362e57027ad6d4d2447b479756254cb7781762c906a4cb69ea20c7939b8c";
// const edsignature2 = "607b8a43fc7bbbff898083bd0bdfe57dbf34212f34adfefe2bfe807a7076337888e04c86bbae4f56d9834d503e5c76b065efad98942bfe04b906796ac3333e09";


let test = async () => {
    cryptoSsl.eddsaTest();

    // ECDSA K1 Test 1
    console.log("======================= ECDSA K1 Test 1 Start ==========================");
    console.log("========= EC K1 Key Gen Test 1-1) Pem =========");
    let retEcK1V1KeyGen = cryptoSsl.ecK1KeyGenPem("./test/k1_");
    console.log("retEcK1V1KeyGen : " + retEcK1V1KeyGen);
    console.log(" ");
    console.log(" ");

    console.log("========= EC K1 Key Gen Test 1-2) Key =========");
    let retEcK1V1Prikey = cryptoSsl.ecK1GetPrikey("./test/k1_privkey.pem");
    console.log("retEcK1V1Prikey : " + retEcK1V1Prikey);
    console.log(" ");
    console.log(" ");
    
    let retEcK1V1Pubkey = cryptoSsl.ecK1GetPubkey("./test/k1_pubkey.pem");
    console.log("retEcK1V1Pubkey : " + retEcK1V1Pubkey);
    console.log(" ");
    console.log(" ");

    // const retEcK1V = await cryptoSsl.ecdsaK1Verify(eckdata, eckr, ecks, eckpubkey);
    // console.log("retEcK1V : " + retEcK1V);
    console.log("======================= ECDSA K1 Test 1 End ============================");
    console.log(" ");
    
    // ECDSA R1 Test 1
    console.log("======================= ECDSA R1 Test 1 Start ==========================");
    console.log("========= EC R1 Key Gen Test 1-1) Pem =========");
    let retEcR1V1KeyGen = cryptoSsl.ecR1KeyGenPem("./test/r1_");
    console.log("retEcR1V1KeyGen : " + retEcR1V1KeyGen);
    console.log(" ");
    console.log(" ");

    console.log("========= EC R1 Key Gen Test 1-2) Key =========");
    let retEcR1V1Prikey = cryptoSsl.ecR1GetPrikey("./test/r1_privkey.pem");
    console.log("retEcR1V1Prikey : " + retEcR1V1Prikey);
    console.log(" ");
    console.log(" ");
    
    let retEcR1V1Pubkey = cryptoSsl.ecR1GetPubkey("./test/r1_pubkey.pem");
    console.log("retEcR1V1Pubkey : " + retEcR1V1Pubkey);
    console.log(" ");
    console.log(" ");
    
    console.log("========= ECDSA R1 Test 1-1) Pem =========");
    // Sig From Pem
    let retEcR1V1SigPem = cryptoSsl.ecdsaR1SignPem(ecrdata1, "./test/privkey.pem");
    console.log("retEcR1V1SigPem : " + retEcR1V1SigPem);
    console.log(" ");
    console.log(" ");

    // Verify From Pem
    let retEcR1V1PemSigR = retEcR1V1SigPem.slice(0,64);
    let retEcR1V1PemSigS = retEcR1V1SigPem.slice(64);

    console.log("retEcR1V1PemSigR : " + retEcR1V1PemSigR);
    console.log("retEcR1V1PemSigS : " + retEcR1V1PemSigS);
    console.log(" ");

    const retEcR1V1Pem = await cryptoSsl.ecdsaR1VerifyHex(ecrdata1, retEcR1V1PemSigR, retEcR1V1PemSigS, ecrpubkey1);
    console.log("retEcR1V1Pem : " + retEcR1V1Pem);
    console.log(" ");
    console.log(" ");

    console.log("========= ECDSA R1 Test 1-2) Hex =========");
    // Sig From Hex
    let retEcR1V1SigHex = cryptoSsl.ecdsaR1SignHex(ecrdata1, ecrprikey1);
    console.log("retEcR1V1SigHex : " + retEcR1V1SigHex);
    console.log(" ");
    console.log(" ");

    // Verify From Hex
    let retEcR1V1HexSigR = retEcR1V1SigHex.slice(0,64);
    let retEcR1V1HexSigS = retEcR1V1SigHex.slice(64);

    console.log("retEcR1V1HexSigR : " + retEcR1V1HexSigR);
    console.log("retEcR1V1HexSigS : " + retEcR1V1HexSigS);
    console.log(" ");

    const retEcR1V1Hex = await cryptoSsl.ecdsaR1VerifyHex(ecrdata1, retEcR1V1HexSigR, retEcR1V1HexSigS, ecrpubkey1);
    console.log("retEcR1V1Hex : " + retEcR1V1Hex);
    console.log(" ");
    console.log(" ");
    console.log("======================= ECDSA R1 Test 1 End ============================");
    console.log(" ");

    // ECDSA R1 Test 2
    console.log("======================= ECDSA R1 Test 2 Start ==========================");
    const retEcR1V2 = await cryptoSsl.ecdsaR1VerifyHex(ecrdata2, ecrr2, ecrs2, ecrpubkey2);
    console.log("retEcR1V2 : " + retEcR1V2);
    console.log(" ");
    console.log(" ");
    console.log("======================= ECDSA R1 Test 2 End ============================");
    console.log(" ");

    // EDDSA Test 1
    console.log("======================= EDDSA Test 1 Start ============================");
    console.log("========= ED25519 Key Gen Test 1-1) Pem =========");
    let retEdV1KeyGenPem = cryptoSsl.ed25519KeyGenPem("./test/2_");
    console.log("retEdV1KeyGenPem : " + retEdV1KeyGenPem);
    console.log(" ");
    console.log(" ");

    console.log("========= ED25519 Key Gen 1-2) Key =========");
    let retEdV1Prikey = cryptoSsl.ed25519GetPrikey("./test/2_ed_privkey.pem");
    console.log("retEdV1Prikey : " + retEdV1Prikey);
    console.log(" ");
    console.log(" ");
    
    let retEdV1Pubkey = cryptoSsl.ed25519GetPubkey("./test/2_ed_pubkey.pem");
    console.log("retEdV1Pubkey : " + retEdV1Pubkey);
    console.log(" ");
    console.log(" ");
    console.log("======================= EDDSA Test 1 End ==============================");
    console.log(" ");

    console.log("========= EDDSA Test 1-1) Pem =========");
    let retEdV1SigPem = cryptoSsl.eddsaSignPem(eddata1, "./test/1_ed_privkey.pem");
    console.log("retEdV1SigPem : " + retEdV1SigPem);
    console.log(" ");
    console.log(" ");

    const retEdV1Pem = await cryptoSsl.eddsaVerifyHex(eddata1, retEdV1SigPem, edpubkey1);
    console.log("retEdV1Pem : " + retEdV1Pem);
    console.log(" ");
    console.log(" ");

    console.log("========= EDDSA Test 1-2) Hex =========");
    let retEdV1SigHex = cryptoSsl.eddsaSignHex(eddata1, edprvkey1);
    console.log("retEdV1SigHex : " + retEdV1SigHex);
    console.log(" ");
    console.log(" ");

    const retEdV1Hex = await cryptoSsl.eddsaVerifyHex(eddata1, retEdV1SigHex, edpubkey1);
    console.log("retEdV1Hex : " + retEdV1Hex);
    console.log(" ");
    console.log(" ");

    // EDDSA Test 2
    console.log("======================= EDDSA Test 2 Start ============================");
    let retEdV2SigPem = cryptoSsl.eddsaSignPem(eddata2, "./test/ed_privkey.pem");
    console.log("retEdV2SigPem : " + retEdV2SigPem);
    console.log(" ");
    console.log(" ");

    const retEdV2Pem = await cryptoSsl.eddsaVerifyHex(eddata2, retEdV2SigPem, edpubkey2);
    console.log("retEdV2Hex : " + retEdV2Pem);
    console.log(" ");
    console.log(" ");

    console.log("========= EDDSA Test 2-2) Hex =========");
    let retEdV2SigHex = cryptoSsl.eddsaSignHex(eddata2, edprvkey2);
    console.log("retEdV2SigHex : " + retEdV2SigHex);
    console.log(" ");
    console.log(" ");

    const retEdV2Hex = await cryptoSsl.eddsaVerifyHex(eddata2, retEdV2SigHex, edpubkey2);
    console.log("retEdV2Hex : " + retEdV2Hex);
    console.log(" ");
    console.log(" ");

    console.log("========= EDDSA Test 2-3) Key =========");
    let retEdV2Prikey = cryptoSsl.ed25519GetPrikey("./test/ed_privkey.pem");
    console.log("retEdV2Prikey : " + retEdV2Prikey);
    console.log(" ");
    console.log(" ");
    
    let retEdV2Pubkey = cryptoSsl.ed25519GetPubkey("./test/ed_pubkey.pem");
    console.log("retEdV2Pubkey : " + retEdV2Pubkey);
    console.log(" ");
    console.log(" ");
    console.log("======================= EDDSA Test 2 End ==============================");
}

test();
