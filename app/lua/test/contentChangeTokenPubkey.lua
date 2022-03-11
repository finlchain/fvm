
print('test.contentChangeTokenPubkey')

contentChangeTokenPubkey = {
    --
};

--
local contentsFilePath = './../../test/key/crypto/out/xa_change_token_pubkey.ctd'; -- contents decrypted
local contentsEncFilePath = './../../test/key/crypto/out/xa_change_token_pubkey_p1.cte'; -- contents encrypted

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
local encJsonFilePath = './../../test/key/crypto/out/xa_change_token_pubkey_p2.cej'; -- contents encrypted json

--
function contentChangeTokenPubkey.makeContentsJson()
    --
    changeTokenPubkey = ChangeTokenPubkey;

    --
    changeTokenPubkey:init();

    -- ownerPubkey
    local ownerPubkey = ed25519GetPubkey(ownerPubkeyFilePath);
    print("ownerPubkey : ", ownerPubkey);
    print("ownerPubkey05 : ", _commonUtil.insertStr(ownerPubkey, '05', 0));
    -- print("str1:sub(1,1) : ", str1:sub(1,1));
    -- print("str1:sub(1+1): ", str1:sub(1+1));

    -- superPubkey
    local superPubkey = ed25519GetPubkey(superPubkeyFilePath);
    print("superPubkey : ", superPubkey);

    -- tokenAction
    local tokenAction = 11;

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
    changeTokenPubkey:setMyContentObj('ownerPubkey', _commonUtil.insertStr(ownerPubkey, '05', 0));
    changeTokenPubkey:setMyContentObj('superPubkey', _commonUtil.insertStr(superPubkey, '05', 0));
    changeTokenPubkey:setMyContentObj('tokenAction', tokenAction);
    changeTokenPubkey:setMyContentObj('regSuperPrikey', regSuperPrikey);
    changeTokenPubkey:setMyContentObj('regSuperPrikeyPw', regSuperPrikeyPw);
    changeTokenPubkey:setMyContentObj('regSuperPubkey', _commonUtil.insertStr(regSuperPubkey, '05', 0));
    
    local plaintext = changeTokenPubkey:jsonStringifyContent(changeTokenPubkey._myContentsName, true);
    -- print('plaintext.len : ', string.len(plaintext));

    -- // for test
    -- local contractJson = json.parse(plaintext);
    -- _commonUtil.prtTable(contractJson['changeTokenPubkey']);
    -- ///////////////////////////////////////////////////////////////////////

    _commonUtil.writeBinaryFile(contentsFilePath, plaintext);

    --
    changeTokenPubkey:remove();

    return plaintext;
end

function contentChangeTokenPubkey.makeContentsJsonEnc()
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

function contentChangeTokenPubkey.makeContentsJsonDec(phase)
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

-- function contentChangeTokenPubkey.makeContentsJsonEnc()
--     -------------------------------------------------------
--     -- Phase 1
--     --
--     local plaintext = _commonUtil.readBinaryFile(contentsFilePath);
--     -- print('plaintext.len : ', string.len(plaintext));

--     local plaintextHexStr = _commonUtil.bytesToHexStr(plaintext);
--     print('plaintextHexStr.len : ', string.len(plaintextHexStr));
--     print('plaintextHexStr : ', plaintextHexStr);

--     -- peerXPubkey
--     local peerXPubkey = ed25519GetPubkey(xbXPubkeyFilePath);
--     -- local peerXPubkey = '308b942a2eae006d4adf46761cfa58b3c86c89d76bd0d05b3ee68b480552ab21'; -- Pubkey of FBN1
--     print("peerXPubkey : ", peerXPubkey);

--     -- myPrikeyFilePath
--     local myXPrikeyFile = _commonUtil.readBinaryFile(xaXPrikeyFilePath);
--     -- print('myXPrikeyFile.len : ', string.len(myXPrikeyFile));
--     -- print("myXPrikeyFile : ", myXPrikeyFile);

--     -- encMsg
--     local encMsg = x25519MixEnc(myXPrikeyFile, peerXPubkey, plaintextHexStr, string.len(plaintextHexStr));
--     -- print("encMsg : ", encMsg);

--     local encMsg_b = _commonUtil.hexStrToBytes(encMsg);
--     _commonUtil.writeBinaryFile(contentsEncFilePath, encMsg_b);
--     -------------------------------------------------------

--     -------------------------------------------------------
--     -- Phase 2
--     -- myXPubkey
--     local myXPubkey = ed25519GetPubkey(xaXPubkeyFilePath);
--     -- print("myXPubkey : ", myXPubkey);

--     --
--     contentsEnc = ContentsEnc;

--     --
--     contentsEnc:init();

--     --
--     local encXPubkeyF = _commonUtil.insertStr(peerXPubkey, '05', 0);
--     local myXPubkeyF = _commonUtil.insertStr(myXPubkey, '05', 0);
--     local encJsonMsg = contentsEnc:makeEncJsonMsg(encMsg, encXPubkeyF, myXPubkeyF, encJsonFilePath);

--     --
--     contentsEnc:remove();
--     -------------------------------------------------------

--     return encMsg;
-- end

-- function contentChangeTokenPubkey.makeContentsJsonDec(phase)
--     -- Phase 1
--     --
--     local encMsg;
--     local encMsgHexStr;

--     if (phase == 2) then
--         local encJsonMsg = _commonUtil.readBinaryFile(encJsonFilePath);
--         -- print('encJsonMsg.length : ', string.len(encJsonMsg));
    
--         --
--         local encJson = json.parse(encJsonMsg);
--         -- _commonUtil.prtTable(encJson['jsonEnc']);

--         --
--         -- encMsg = encJson['jsonEnc']['contentsEnc'];
--         encMsgHexStr = encJson['jsonEnc']['contentsEnc'];
--     else
--         encMsg = _commonUtil.readBinaryFile(contentsEncFilePath);
--         encMsgHexStr = _commonUtil.bytesToHexStr(encMsg);
--     end
--     -- print('encMsg.len : ', string.len(encMsg));
--     -- print('encMsg : ', encMsg);

--     -- local encMsgHexStr = _commonUtil.bytesToHexStr(encMsg);
--     -- print('encMsgHexStr.len : ', string.len(encMsgHexStr));
--     -- print('encMsgHexStr : ', encMsgHexStr);

--     --
--     local peerXPubkey = ed25519GetPubkey(xaXPubkeyFilePath);
--     -- print("peerXPubkey : ", peerXPubkey);

--     --
--     local myXPrikeyFile = _commonUtil.readBinaryFile(xbXPrikeyFilePath);
--     -- print('myXPrikeyFile.len : ', string.len(myXPrikeyFile));
--     -- print("myXPrikeyFile : ", myXPrikeyFile);

--     plaintext = x25519MixDec(myXPrikeyFile, peerXPubkey, encMsgHexStr, string.len(encMsgHexStr));
--     -- print('plaintext.len : ', string.len(plaintext));
--     -- print("plaintext : ", plaintext);

--     return plaintext;
-- end

function contentChangeTokenPubkey.testCase()
    --
    local rtnJsonStr = contentChangeTokenPubkey.makeContentsJson();

    --
    local encMsg = contentChangeTokenPubkey.makeContentsJsonEnc();

    --
    contentChangeTokenPubkey.makeContentsJsonDec(2);
end
