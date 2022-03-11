
print('test.contentCreateToken')

contentCreateToken = {
    --
};

--
local contentsFilePath = './../../test/key/crypto/out/xa_create_token.ctd'; -- contents decrypted
local contentsEncFilePath = './../../test/key/crypto/out/xa_create_token_p1.cte'; -- contents encrypted

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
local encJsonFilePath = './../../test/key/crypto/out/xa_create_token_p2.cej'; -- contents encrypted json

--
function contentCreateToken.makeContentsJson()
    --
    createToken = CreateToken;

    --
    createToken:init();

    -- ownerPrikey
    -- io.write('Owner Private key file path to sign (*.fin) : ');
    -- local ownerPrikeyFilePath = io.read();

    local ownerPrikey = _commonUtil.readBinaryFile(ownerPrikeyFilePath);
    -- local ownerPrikeyHexStr = _commonUtil.bytesToHexStr(ownerPrikey);

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

    -- tokenAction
    local tokenAction = 11;

    -- tokenName
    local tokenName = 'TestToken';

    -- tokenSymbol
    local tokenSymbol = 'TTKN';

    -- totalSupply
    local totalSupply = '1200000000.000000000';

    -- decimalPoint
    local decimalPoint = 9;

    --
    createToken:setMyContentObj('ownerPrikey', ownerPrikey);
    createToken:setMyContentObj('ownerPrikeyPw', ownerPrikeyPw);
    createToken:setMyContentObj('ownerPubkey', _commonUtil.insertStr(ownerPubkey, '05', 0));
    createToken:setMyContentObj('superPubkey', _commonUtil.insertStr(superPubkey, '05', 0));
    createToken:setMyContentObj('tokenAction', tokenAction);
    createToken:setMyContentObj('tokenName', tokenName);
    createToken:setMyContentObj('tokenSymbol', tokenSymbol);
    createToken:setMyContentObj('totalSupply', totalSupply);
    createToken:setMyContentObj('decimalPoint', decimalPoint);
    
    local plaintext = createToken:jsonStringifyContent(createToken._myContentsName, true);
    -- print('plaintext.len : ', string.len(plaintext));

    -- // for test
    -- local contractJson = json.parse(plaintext);
    -- _commonUtil.prtTable(contractJson['createToken']);
    -- ///////////////////////////////////////////////////////////////////////

    _commonUtil.writeBinaryFile(contentsFilePath, plaintext);

    --
    createToken:remove();

    return plaintext;
end

function contentCreateToken.makeContentsJsonEnc()
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

function contentCreateToken.makeContentsJsonDec(phase)
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

function contentCreateToken.testCase()
    --
    local rtnJsonStr = contentCreateToken.makeContentsJson();

    --
    local encMsg = contentCreateToken.makeContentsJsonEnc();

    --
    contentCreateToken.makeContentsJsonDec(2);
end
