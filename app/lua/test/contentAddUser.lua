
print('test.contentAddUser')

contentAddUser = {
    --
};

--
local contentsFilePath = './../../test/key/crypto/out/xa_add_user.ctd'; -- contents decrypted
local contentsEncFilePath = './../../test/key/crypto/out/xa_add_user_p1.cte'; -- contents encrypted

-- --
-- local ownerPrikeyFilePath = './../../test/key/crypto/xa_ed_privkey.fin';
-- local ownerPubkeyFilePath = './../../test/key/crypto/xa_ed_pubkey.pem';
-- local superPubkeyFilePath = './../../test/key/crypto/xa_ed_pubkey.pem';

-- --
-- local xaXPrikeyFilePath = './../../test/key/crypto/xa_x_privkey.pem';
-- local xaXPubkeyFilePath = './../../test/key/crypto/xa_x_pubkey.pem';

-- local xbXPrikeyFilePath = './../../test/key/crypto/xb_x_privkey.pem';
-- local xbXPubkeyFilePath = './../../test/key/crypto/xb_x_pubkey.pem';

--
local ownerPrikeyFilePath = './../../../../conf/test/key/ed/key_09/ed_privkey.fin';
local ownerPubkeyFilePath = './../../../../conf/test/key/ed/key_09/ed_pubkey.pem';
local superPubkeyFilePath = './../../../../conf/test/key/ed/key_09/ed_pubkey.pem';

--
local xaXPrikeyFilePath = './../../../../conf/test/key/x25519/09_x_privkey.pem';
local xaXPubkeyFilePath = './../../../../conf/test/key/x25519/09_x_pubkey.pem';

local xbXPrikeyFilePath = './../../../../conf/test/key/x25519/10_x_privkey.pem';
local xbXPubkeyFilePath = './../../../../conf/test/key/x25519/10_x_pubkey.pem';

--
local encJsonFilePath = './../../test/key/crypto/out/xa_add_user_p2.cej'; -- contents encrypted json

--
function contentAddUser.makeContentsJson()
    --
    addUser = AddUser;

    --
    addUser:init();

    -- ownerPrikey
    -- io.write('Owner Private key file path to sign (*.fin) : ');
    -- local ownerPrikeyFilePath = io.read();

    local ownerPrikey = _commonUtil.readBinaryFile(ownerPrikeyFilePath);
    -- local ownerPrikeyHexStr = _commonUtil.bytesToHexStr(ownerPrikey);
    -- print('ownerPrikeyHexStr : ', ownerPrikeyHexStr);

    -- ownerPrikeyPw
    -- io.write('password for *.fin : ');
    -- local ownerPrikeyPw = io.read();
    local ownerPrikeyPw = "asdfQWER1234!@#$";

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
    local accountId = 'user_09';

    --
    -- addUser:setMyContentObj('owner_pk', _commonUtil.insertStr(ownerPubkey, '05', 0));
    -- addUser:setMyContentObj('super_pk', _commonUtil.insertStr(superPubkey, '05', 0));
    -- addUser:setMyContentObj('account_id', accountId);
    addUser:setMyContentObj('ownerPubkey', _commonUtil.insertStr(ownerPubkey, '05', 0));
    addUser:setMyContentObj('superPubkey', _commonUtil.insertStr(superPubkey, '05', 0));
    addUser:setMyContentObj('accountId', accountId);
    addUser:setMyContentObj('ownerPrikey', ownerPrikey);
    addUser:setMyContentObj('ownerPrikeyPw', ownerPrikeyPw);

    local plaintext = addUser:jsonStringifyContent(addUser._myContentsName, true);
    -- print('plaintext.len : ', string.len(plaintext));

    -- // for test
    -- local contractJson = json.parse(plaintext);
    -- _commonUtil.prtTable(contractJson['addUser']);
    -- print('ownerPrikeyPw : ', contractJson['addUser']['ownerPrikeyPw']);
    -- ///////////////////////////////////////////////////////////////////////

    _commonUtil.writeBinaryFile(contentsFilePath, plaintext);

    --
    addUser:remove();

    return plaintext;
end

function contentAddUser.makeContentsJsonEnc()
    -- peerXPubkey
    local peerXPubkey;
    -- local peerXPubkeyFilePath = xbXPubkeyFilePath;
    -- peerXPubkey = ed25519GetPubkey(peerXPubkeyFilePath);
    -- peerXPubkey = '308b942a2eae006d4adf46761cfa58b3c86c89d76bd0d05b3ee68b480552ab21'; -- Pubkey of FBN1
    local retCurlMsg = curlHttpGet("http://purichain.com:4000/wallet/key/get/pubkey?x25519", "dummy");
    local culrMsg = json.parse(retCurlMsg);
    -- _commonUtil.prtTable(culrMsg['contents']);
    -- _commonUtil.prtTable(culrMsg);
    --
    peerXPubkey = culrMsg['contents']['xPubkey'];
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

function contentAddUser.makeContentsJsonDec(phase)
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

function contentAddUser.sendContents(filePath)
    local plaintext = _commonUtil.readBinaryFile(filePath);
    -- print('plaintext.len : ', string.len(plaintext));
    print('plaintext.len : ', string.len(plaintext));
    print('plaintext : ', plaintext);

    -- // for test
    -- local contractJson = json.parse(plaintext);
    -- _commonUtil.prtTable(contractJson['addUser']);
    -- print('ownerPrikey4 : ', contractJson['addUser']['ownerPrikey']);
    -- print('ownerPrikeyPw : ', contractJson['addUser']['ownerPrikeyPw']);

    -- local ownerPrikeyHexStr = _commonUtil.bytesToHexStr(contractJson['addUser']['ownerPrikey']);
    -- print('ownerPrikeyHexStr : ', ownerPrikeyHexStr);
    -- ///////////////////////////////////////////////////////////////////////

    local plaintextHexStr = _commonUtil.bytesToHexStr(plaintext);
    print('plaintextHexStr.len : ', string.len(plaintextHexStr));
    print('plaintextHexStr : ', plaintextHexStr);

    -- local myContents = "contents=" .. plaintext;
    local myContents = "contents=" .. plaintextHexStr;

    curlHttpPost("http://purichain.com:4000/contract/tool/json", myContents);
end

function contentAddUser.sendContentsEnc(filePath)
    local encJsonMsg = _commonUtil.readBinaryFile(filePath);
    print('encJsonMsg : ', encJsonMsg);

    local myContentsEnc = "contentsEnc=" .. encJsonMsg;

    curlHttpPost("http://purichain.com:4000/contract/tool/json", myContentsEnc);
end

function contentAddUser.testCase()
    --
    local rtnJsonStr = contentAddUser.makeContentsJson();
    -- contentAddUser.sendContents(contentsFilePath);

    --
    local encMsg = contentAddUser.makeContentsJsonEnc();

    --
    contentAddUser.makeContentsJsonDec(2);

    contentAddUser.sendContentsEnc(encJsonFilePath);
end
