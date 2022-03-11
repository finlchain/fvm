
print('test.contractCreateSc')

contractCreateSc = {
    --
};

--
local contractFilePath = './../../test/key/crypto/out/c_create_sc.crd'; -- contract decrypted

--
local ownerPrikeyFilePath = './../../../../conf/test/key/ed/key_09/ed_privkey.fin';
local ownerPubkeyFilePath = './../../../../conf/test/key/ed/key_09/ed_pubkey.pem';
local superPubkeyFilePath = './../../../../conf/test/key/ed/key_09/ed_pubkey.pem';

--
function contractCreateSc.makeContractJson()
    --
    ccreateSc = cCreateSc;

    --
    ccreateSc:init();

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
    local action = contractActionsJson['CONTRACT']['DEFAULT']['CREATE_SC'];
    -- contents
    local memo = '';

    --
    ccreateSc:setContractObj('create_tm', create_tm);
    ccreateSc:setContractObj('fintech', fintech);
    ccreateSc:setContractObj('privacy', privacy);
    ccreateSc:setContractObj('fee', fee);
    ccreateSc:setContractObj('from_account', from_account);
    ccreateSc:setContractObj('to_account', to_account);
    ccreateSc:setContractObj('action', action);
    ccreateSc:setContractObj('memo', memo);
    
    --------------------------------------------------------
    --
    local sc_action = contractActionsJson['CONTRACT']['SC']['STT'];
    local action_target = contractActionsJson['TOKEN']['SECURITY'];
    local sc = '{}';

    ccreateSc:setMyContentObj('sc_action', sc_action);
    ccreateSc:setMyContentObj('action_target', action_target);
    ccreateSc:setMyContentObj('sc', sc);

    --
    local mergedBuf = ccreateSc:signBufferGenerator(true);
    -- print('mergedBuf : ', mergedBuf);

    --
    local inputData = genSha256Str(mergedBuf);
    print('inputData : ', inputData);

    --
    local signature = eddsaSignHex(inputData, ownerPrikeyHex);
    -- print('signature : ', signature);

    --
    ccreateSc:setContractObj('signed_pubkey', _commonUtil.insertStr(ownerPubkey, '05', 0));
    ccreateSc:setContractObj('sig', signature);

    -- --
    -- ccreateSc:prtMyContractObj();
    -- ccreateSc:prtMyContentObj();
    
    --
    local plaintext = '';
    plaintext = ccreateSc:jsonStringifyContract(ccreateSc._contractName, true);
    -- print('plaintext.len : ', string.len(plaintext));
    print('plaintext : ', plaintext);

    _commonUtil.writeBinaryFile(contractFilePath, plaintext);

    --
    ccreateSc:remove();

    return plaintext;
end

function contractCreateSc.testCase()
    --
    local rtnJsonStr = contractCreateSc.makeContractJson();
end
