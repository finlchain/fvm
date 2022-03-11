
print('test.contentChangeUserPubkey')

contentChangeUserPubkey = {
    --
};

--
local contentsFilePath = './../../test/key/crypto/out/xa_change_user_pubkey.ctd'; -- contents decrypted
local contentsEncFilePath = './../../test/key/crypto/out/xa_change_user_pubkey_p1.cte'; -- contents encrypted

--
local ownerPubkeyFilePath = './../../test/key/crypto/xc_ed_pubkey.pem';
local superPubkeyFilePath = './../../test/key/crypto/xc_ed_pubkey.pem';

local regSuperPrikeyFilePath = './../../test/key/crypto/xa_ed_privkey.fin';
local regSuperPubkeyFilePath = './../../test/key/crypto/xa_ed_pubkey.pem';

--
local xaXPrikeyFilePath = './../../test/key/crypto/xa_x_privkey.pem';
local xaXPubkeyFilePath = './../../test/key/crypto/xa_x_pubkey.pem';

local xbXPrikeyFilePath = './../../test/key/crypto/xb_x_privkey.pem';
local xbXPubkeyFilePath = './../../test/key/crypto/xb_x_pubkey.pem';

--
local encJsonFilePath = './../../test/key/crypto/out/xa_change_user_pubkey_p2.cej'; -- contents encrypted json

--
function contentChangeUserPubkey.makeContentsJson()
    --
    changeUserPubkey = ChangeUserPubkey;

    --
    changeUserPubkey:init();

    -- ownerPubkey
    local ownerPubkey = ed25519GetPubkey(ownerPubkeyFilePath);
    print("ownerPubkey : ", ownerPubkey);
    print("ownerPubkey05 : ", _commonUtil.insertStr(ownerPubkey, '05', 0));
    -- print("str1:sub(1,1) : ", str1:sub(1,1));
    -- print("str1:sub(1+1): ", str1:sub(1+1));

    -- superPubkey
    local superPubkey = ed25519GetPubkey(superPubkeyFilePath);
    print("superPubkey : ", superPubkey);

    -- accountId
    local accountId = 'user_01';

    -- regSuperPrikey
    -- io.write('Registered Super Private key file path to sign (*.fin) : ');
    -- local regSuperPrikeyFilePath = io.read();

    local regSuperPrikey = _commonUtil.readBinaryFile(regSuperPrikeyFilePath);
    -- local regSuperPrikeyHexStr = _commonUtil.bytesToHexStr(regSuperPrikey);

    -- regSuperPrikeyPw
    -- io.write('password for *.fin : ');
    -- local regSuperPrikeyPw = io.read();
    local regSuperPrikeyPw = "asdfQWER1234!@#$";

    -- regSuperPubkey
    local regSuperPubkey = ed25519GetPubkey(regSuperPubkeyFilePath);
    print("regSuperPubkey : ", regSuperPubkey);

    --
    changeUserPubkey:setMyContentObj('ownerPubkey', _commonUtil.insertStr(ownerPubkey, '05', 0));
    changeUserPubkey:setMyContentObj('superPubkey', _commonUtil.insertStr(superPubkey, '05', 0));
    changeUserPubkey:setMyContentObj('accountId', accountId);
    changeUserPubkey:setMyContentObj('regSuperPrikey', regSuperPrikey);
    changeUserPubkey:setMyContentObj('regSuperPrikeyPw', regSuperPrikeyPw);
    changeUserPubkey:setMyContentObj('regSuperPubkey', _commonUtil.insertStr(regSuperPubkey, '05', 0));
    
    local plaintext = changeUserPubkey:jsonStringifyContent(changeUserPubkey._myContentsName, true);
    -- print('plaintext.len : ', string.len(plaintext));

    -- // for test
    -- local contractJson = json.parse(plaintext);
    -- _commonUtil.prtTable(contractJson['changeUserPubkey']);
    -- print('ownerPrikeyPw : ', contractJson['changeUserPubkey']['ownerPrikeyPw']);
    -- ///////////////////////////////////////////////////////////////////////

    _commonUtil.writeBinaryFile(contentsFilePath, plaintext);

    --
    changeUserPubkey:remove();

    return plaintext;
end

function contentChangeUserPubkey.makeContentsJsonEnc()
    -- peerXPubkey
    local peerXPubkeyFilePath = xbXPubkeyFilePath;
    local peerXPubkey = ed25519GetPubkey(peerXPubkeyFilePath);
    peerXPubkey = '308b942a2eae006d4adf46761cfa58b3c86c89d76bd0d05b3ee68b480552ab21'; -- Pubkey of FBN1
    print("peerXPubkey : ", peerXPubkey);

    --
    contentsEnc = ContentsEnc;

    --
    contentsEnc:init();

    --
    local myXPrikeyFilePath = xaXPrikeyFilePath;
    local encMsg = contentsEnc:makeContentsJsonEncP1(contentsFilePath, peerXPubkey, myXPrikeyFilePath, contentsEncFilePath);

    --
    local myXPubkeyFilePath = xaXPubkeyFilePath;
    local encJsonMsg = contentsEnc:makeContentsJsonEncP2(encMsg, peerXPubkey, myXPubkeyFilePath, encJsonFilePath)

    --
    contentsEnc:remove();
end

function contentChangeUserPubkey.makeContentsJsonDec(phase)
    -- peerXPubkey
    local peerXPubkeyFilePath = xaXPubkeyFilePath;
    local peerXPubkey = ed25519GetPubkey(peerXPubkeyFilePath);
    -- print("peerXPubkey : ", peerXPubkey);

    --
    contentsEnc = ContentsEnc;

    --
    contentsEnc:init();

    --
    local myXPrikeyFilePath = xbXPrikeyFilePath;
    
    if (phase == 1) then
        -- Phase 1
        local plaintext = contentsEnc:makeContentsJsonDec(nil, contentsEncFilePath, peerXPubkey, myXPrikeyFilePath);
    else
        -- Phase 2
        local plaintext = contentsEnc:makeContentsJsonDec(encJsonFilePath, nil, peerXPubkey, myXPrikeyFilePath);
    end

    --
    contentsEnc:remove();

    return plaintext;
end

function contentChangeUserPubkey.testCase()
    --
    local rtnJsonStr = contentChangeUserPubkey.makeContentsJson();

    --
    local encMsg = contentChangeUserPubkey.makeContentsJsonEnc();

    --
    contentChangeUserPubkey.makeContentsJsonDec(2);
end
