
print('test.contentChangeTokenLockTime')

contentChangeTokenLockTime = {
    --
};

--
local contentsFilePath = './../../test/key/crypto/out/xa_change_token_lock_time.ctd'; -- contents decrypted
local contentsEncFilePath = './../../test/key/crypto/out/xa_change_token_lock_time_p1.cte'; -- contents encrypted

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
local encJsonFilePath = './../../test/key/crypto/out/xa_change_token_lock_time_p2.cej'; -- contents encrypted json

--
local tokenLockTime = {UNLOCK = '0'};

--
function contentChangeTokenLockTime.makeContentsJson()
    --
    changeTokenLockTime = ChangeTokenLockTime;

    --
    changeTokenLockTime:init();

    -- tokenAction
    local tokenAction = 11;

    -- lockTimeFrom
    local lockTimeFrom = tokenLockTime['UNLOCK'];
    print("lockTimeFrom : ", lockTimeFrom);

    -- lockTimeTo
    -- local lockTimeTo = tokenLockTime['UNLOCK'];
    local lockTimeTo = utcCurrMS()+60000;
    print("lockTimeTo : ", lockTimeTo);

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
    changeTokenLockTime:setMyContentObj('tokenAction', tokenAction);
    changeTokenLockTime:setMyContentObj('lockTimeFrom', lockTimeFrom);
    changeTokenLockTime:setMyContentObj('lockTimeTo', lockTimeTo);
    changeTokenLockTime:setMyContentObj('regSuperPrikey', regSuperPrikey);
    changeTokenLockTime:setMyContentObj('regSuperPrikeyPw', regSuperPrikeyPw);
    changeTokenLockTime:setMyContentObj('regSuperPubkey', _commonUtil.insertStr(regSuperPubkey, '05', 0));
    
    local plaintext = changeTokenLockTime:jsonStringifyContent(changeTokenLockTime._myContentsName, true);
    -- print('plaintext.len : ', string.len(plaintext));

    -- // for test
    -- local contractJson = json.parse(plaintext);
    -- _commonUtil.prtTable(contractJson['changeTokenLockTime']);
    -- ///////////////////////////////////////////////////////////////////////

    _commonUtil.writeBinaryFile(contentsFilePath, plaintext);

    --
    changeTokenLockTime:remove();

    return plaintext;
end

function contentChangeTokenLockTime.makeContentsJsonEnc()
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

function contentChangeTokenLockTime.makeContentsJsonDec(phase)
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

function contentChangeTokenLockTime.testCase()
    --
    local rtnJsonStr = contentChangeTokenLockTime.makeContentsJson();

    --
    local encMsg = contentChangeTokenLockTime.makeContentsJsonEnc();

    --
    contentChangeTokenLockTime.makeContentsJsonDec(2);
end
