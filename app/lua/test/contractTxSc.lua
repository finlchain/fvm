
print('test.contractTxSc')

contractTxSc = {
    --
};

--
local contractFilePath = './../../test/key/crypto/out/c_create_sc.crd'; -- contract decrypted

--
local ownerPrikeyFilePath = './../../../../conf/test/key/ed/key_09/ed_privkey.fin';
local ownerPubkeyFilePath = './../../../../conf/test/key/ed/key_09/ed_pubkey.pem';
local superPubkeyFilePath = './../../../../conf/test/key/ed/key_09/ed_pubkey.pem';

--
function contractTxSc.makeContractJson()
    --
    ctxSc = cTxSc;

    --
    ctxSc:init();

    --------------------------------------------------------
    -- ownerPrikey
    -- io.write('Owner Private key file path to sign (*.fin) : ');
    -- local ownerPrikeyFilePath = io.read();

    -- local ownerPrikey = _commonUtil.readBinaryFile(ownerPrikeyFilePath);
    -- local ownerPrikeyHexStr = _commonUtil.bytesToHexStr(ownerPrikeyHexStr);
    -- print('ownerPrikeyHexStr : ', ownerPrikeyHexStr);

    -- ownerPrikeyPw
    -- io.write('password for *.fin : ');
    -- local ownerPrikeyPw = io.read();
    local ownerPrikeyPw = "asdfQWER1234!@#$";

    --
    local keySeed = ownerPrikeyPw;
    local dec = aesDecFile(ownerPrikeyFilePath, keySeed, string.len(keySeed));
    -- print('dec : ', dec);

    local ownerPrikeyHex = ed25519GetPrikeyByPemStr(dec);
    print('ownerPrikeyHex : ', ownerPrikeyHex);

    -- ownerPubkey
    local ownerPubkey = ed25519GetPubkey(ownerPubkeyFilePath);
    print("ownerPubkey : ", ownerPubkey);
    -- print("ownerPubkey05 : ", _commonUtil.insertStr(ownerPubkey, '05', 0));

    -- superPubkey
    local superPubkey = ed25519GetPubkey(superPubkeyFilePath);
    -- print("superPubkey05 : ", _commonUtil.insertStr(superPubkey, '05', 0));

    --
    local contractActionsJson = _config.contractActions();
    -- print(contractActionsJson['CONTRACT']['DEFAULT']['ADD_USER']);
    -- _commonUtil.prtTable(contractActionsJson['CONTRACT']['DEFAULT']);
    
    --------------------------------------------------------
    --
    local create_tm = utcCurrMS();
    local fintech = '0';
    local privacy = '0';
    local fee = '0';
    local from_account = '0000000000000000';
    local to_account = '0000000000000000';
    local sc_action = contractActionsJson['CONTRACT']['SC']['STT'];
    -- contents
    local memo = '';

    --
    ctxSc:setContractObj('create_tm', create_tm);
    ctxSc:setContractObj('fintech', fintech);
    ctxSc:setContractObj('privacy', privacy);
    ctxSc:setContractObj('fee', fee);
    ctxSc:setContractObj('from_account', from_account);
    ctxSc:setContractObj('to_account', to_account);
    ctxSc:setContractObj('action', sc_action);
    ctxSc:setContractObj('memo', memo);
    
    --------------------------------------------------------
    --
    local sc = '{}';

    ctxSc:setMyContentObj('sc', sc);

    --
    local mergedBuf = ctxSc:signBufferGenerator(true);
    -- print('mergedBuf : ', mergedBuf);

    --
    local inputData = genSha256Str(mergedBuf);
    print('inputData : ', inputData);

    --
    local signature = eddsaSignHex(inputData, ownerPrikeyHex);
    -- print('signature : ', signature);

    --
    ctxSc:setContractObj('signed_pubkey', _commonUtil.insertStr(ownerPubkey, '05', 0));
    ctxSc:setContractObj('sig', signature);

    -- --
    -- ctxSc:prtMyContractObj();
    -- ctxSc:prtMyContentObj();
    
    --
    local plaintext = '';
    plaintext = ctxSc:jsonStringifyContract(ctxSc._contractName, true);
    -- print('plaintext.len : ', string.len(plaintext));
    print('plaintext : ', plaintext);

    _commonUtil.writeBinaryFile(contractFilePath, plaintext);

    --
    ctxSc:remove();

    return plaintext;
end

function contractTxSc.testCase()
    --
    local rtnJsonStr = contractTxSc.makeContractJson();
end
