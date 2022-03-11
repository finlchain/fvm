
print('test.contractCreateToken')

contractCreateToken = {
    --
};

--
local contractFilePath = './../../test/key/crypto/out/c_create_token.crd'; -- contract decrypted

--
local ownerPrikeyFilePath = './../../../../conf/test/key/ed/key_09/ed_privkey.fin';
local ownerPubkeyFilePath = './../../../../conf/test/key/ed/key_09/ed_pubkey.pem';
local superPubkeyFilePath = './../../../../conf/test/key/ed/key_09/ed_pubkey.pem';

--
function contractCreateToken.makeContractJson()
    --
    ccreateToken = cCreateToken;

    --
    ccreateToken:init();

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
    local action = contractActionsJson['CONTRACT']['DEFAULT']['TOKEN_CREATION'];
    -- contents
    local memo = '';

    --
    ccreateToken:setContractObj('create_tm', create_tm);
    ccreateToken:setContractObj('fintech', fintech);
    ccreateToken:setContractObj('privacy', privacy);
    ccreateToken:setContractObj('fee', fee);
    ccreateToken:setContractObj('from_account', from_account);
    ccreateToken:setContractObj('to_account', to_account);
    ccreateToken:setContractObj('action', action);
    ccreateToken:setContractObj('memo', memo);
    
    --------------------------------------------------------
    --
    local token_num = 11;
    local token_name = 'UTIL_' .. tostring(token_num);
    local token_symbol = 'f' .. tostring(token_num);

    --
    ccreateToken:setMyContentObj('owner_pk', _commonUtil.insertStr(ownerPubkey, '05', 0));
    ccreateToken:setMyContentObj('super_pk', _commonUtil.insertStr(superPubkey, '05', 0));
    ccreateToken:setMyContentObj('action', token_num);
    ccreateToken:setMyContentObj('name', token_name);
    ccreateToken:setMyContentObj('symbol', token_symbol);
    ccreateToken:setMyContentObj('total_supply', '1000000000.000000000');
    ccreateToken:setMyContentObj('decimal_point', 9);
    ccreateToken:setMyContentObj('lock_time_from', '0');
    ccreateToken:setMyContentObj('lock_time_to', '0');
    ccreateToken:setMyContentObj('lock_transfer', 0);
    ccreateToken:setMyContentObj('black_list', '');
    ccreateToken:setMyContentObj('functions', '');

    --
    local mergedBuf = ccreateToken:signBufferGenerator(true);
    -- print('mergedBuf : ', mergedBuf);

    --
    local inputData = genSha256Str(mergedBuf);
    print('inputData : ', inputData);

    --
    local signature = eddsaSignHex(inputData, ownerPrikeyHex);
    -- print('signature : ', signature);

    --
    ccreateToken:setContractObj('signed_pubkey', _commonUtil.insertStr(ownerPubkey, '05', 0));
    ccreateToken:setContractObj('sig', signature);

    -- --
    -- ccreateToken:prtMyContractObj();
    -- ccreateToken:prtMyContentObj();
    
    --
    local plaintext = '';
    plaintext = ccreateToken:jsonStringifyContract(ccreateToken._contractName, true);
    -- print('plaintext.len : ', string.len(plaintext));
    print('plaintext : ', plaintext);

    _commonUtil.writeBinaryFile(contractFilePath, plaintext);

    --
    ccreateToken:remove();

    return plaintext;
end

function contractCreateToken.testCase()
    --
    local rtnJsonStr = contractCreateToken.makeContractJson();
end
