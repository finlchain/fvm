
print('test.contractTxUtilToken')

contractTxUtilToken = {
    --
};

--
local contractFilePath = './../../test/key/crypto/out/c_tx_sec_token.crd'; -- contract decrypted

--
local ownerPrikeyFilePath = './../../../../conf/test/key/ed/key_09/ed_privkey.fin';
local ownerPubkeyFilePath = './../../../../conf/test/key/ed/key_09/ed_pubkey.pem';
local superPubkeyFilePath = './../../../../conf/test/key/ed/key_09/ed_pubkey.pem';

--
function contractTxUtilToken.makeContractJson()
    --
    ctxToken = cTxUtilToken;

    --
    ctxToken:init();

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
    local fintech = '1';
    local privacy = '0';
    local fee = '0';
    local from_account = 'USER_01';
    local to_account = 'USER_02';
    local token_account = 'IS00';
    local token_num = contractActionsJson['TOKEN']['UTILITY']['STT'];
    -- contents
    local memo = '';

    --
    ctxToken:setContractObj('create_tm', create_tm);
    ctxToken:setContractObj('fintech', fintech);
    ctxToken:setContractObj('privacy', privacy);
    ctxToken:setContractObj('fee', fee);
    ctxToken:setContractObj('from_account', from_account);
    ctxToken:setContractObj('to_account', token_account);
    ctxToken:setContractObj('action', token_num);
    ctxToken:setContractObj('memo', memo);
    
    --------------------------------------------------------
    --
    local amount = '10000.000000000';

    ctxToken:setMyContentObj('dst_account', to_account);
    ctxToken:setMyContentObj('amount', amount);

    --
    local mergedBuf = ctxToken:signBufferGenerator(true);
    -- print('mergedBuf : ', mergedBuf);

    --
    local inputData = genSha256Str(mergedBuf);
    print('inputData : ', inputData);

    --
    local signature = eddsaSignHex(inputData, ownerPrikeyHex);
    -- print('signature : ', signature);

    --
    ctxToken:setContractObj('signed_pubkey', _commonUtil.insertStr(ownerPubkey, '05', 0));
    ctxToken:setContractObj('sig', signature);

    -- --
    -- ctxToken:prtMyContractObj();
    -- ctxToken:prtMyContentObj();
    
    --
    local plaintext = '';
    plaintext = ctxToken:jsonStringifyContract(ctxToken._contractName, true);
    -- print('plaintext.len : ', string.len(plaintext));
    print('plaintext : ', plaintext);

    _commonUtil.writeBinaryFile(contractFilePath, plaintext);

    --
    ctxToken:remove();

    return plaintext;
end

function contractTxUtilToken.testCase()
    --
    local rtnJsonStr = contractTxUtilToken.makeContractJson();
end
