
print('test.contractAddUser')

contractAddUser = {
    --
};

--
local contractFilePath = './../../test/key/crypto/out/c_add_user.crd'; -- contract decrypted

--
local ownerPrikeyFilePath = './../../../../conf/test/key/ed/key_09/ed_privkey.fin';
local ownerPubkeyFilePath = './../../../../conf/test/key/ed/key_09/ed_pubkey.pem';
local superPubkeyFilePath = './../../../../conf/test/key/ed/key_09/ed_pubkey.pem';

--
function contractAddUser.makeContractJson()
    --
    caddUser = cAddUser;

    --
    caddUser:init();

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
    local action = contractActionsJson['CONTRACT']['DEFAULT']['ADD_USER'];
    -- contents
    local memo = '';

    --
    caddUser:setContractObj('create_tm', create_tm);
    caddUser:setContractObj('fintech', fintech);
    caddUser:setContractObj('privacy', privacy);
    caddUser:setContractObj('fee', fee);
    caddUser:setContractObj('from_account', from_account);
    caddUser:setContractObj('to_account', to_account);
    caddUser:setContractObj('action', action);
    caddUser:setContractObj('memo', memo);
    
    --------------------------------------------------------
    -- accountId
    local accountId = 'USER_09';

    --
    caddUser:setMyContentObj('owner_pk', _commonUtil.insertStr(ownerPubkey, '05', 0));
    caddUser:setMyContentObj('super_pk', _commonUtil.insertStr(superPubkey, '05', 0));
    caddUser:setMyContentObj('account_id', accountId);

    --
    local mergedBuf = caddUser:signBufferGenerator(true);
    -- print('mergedBuf : ', mergedBuf);

    --
    local inputData = genSha256Str(mergedBuf);
    print('inputData : ', inputData);

    --
    local signature = eddsaSignHex(inputData, ownerPrikeyHex);
    -- print('signature : ', signature);

    --
    caddUser:setContractObj('signed_pubkey', _commonUtil.insertStr(ownerPubkey, '05', 0));
    caddUser:setContractObj('sig', signature);

    -- --
    -- caddUser:prtMyContractObj();
    -- caddUser:prtMyContentObj();
    
    --
    local plaintext = '';
    plaintext = caddUser:jsonStringifyContract(caddUser._contractName, true);
    -- print('plaintext.len : ', string.len(plaintext));
    print('plaintext : ', plaintext);

    _commonUtil.writeBinaryFile(contractFilePath, plaintext);

    --
    caddUser:remove();

    return plaintext;
end

function contractAddUser.testCase()
    --
    local rtnJsonStr = contractAddUser.makeContractJson();
end
