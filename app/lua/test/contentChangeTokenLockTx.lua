
print('test.contentChangeTokenLockTx')

contentChangeTokenLockTx = {
    --
};

--
local contentsFilePath = './../../test/key/crypto/out/xa_change_token_lock_tx.ctd'; -- contents decrypted
local contentsEncFilePath = './../../test/key/crypto/out/xa_change_token_lock_tx_p1.cte'; -- contents encrypted

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
local encJsonFilePath = './../../test/key/crypto/out/xa_change_token_lock_tx_p2.cej'; -- contents encrypted json

--
local tokenLockTx = {UNLOCK = '0', LOCK_ALL = '1', LOCK_EXC_OWNER = '2'};

--
function contentChangeTokenLockTx.makeContentsJson()
    --
    changeTokenLockTx = ChangeTokenLockTx;

    --
    changeTokenLockTx:init();

    -- tokenAction
    local tokenAction = 11;

    -- lockTx
    local lockTx = tokenLockTx['UNLOCK'];
    print("lockTx : ", lockTx);

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
    changeTokenLockTx:setMyContentObj('tokenAction', tokenAction);
    changeTokenLockTx:setMyContentObj('lockTx', lockTx);
    changeTokenLockTx:setMyContentObj('regSuperPrikey', regSuperPrikey);
    changeTokenLockTx:setMyContentObj('regSuperPrikeyPw', regSuperPrikeyPw);
    changeTokenLockTx:setMyContentObj('regSuperPubkey', _commonUtil.insertStr(regSuperPubkey, '05', 0));
    
    local plaintext = changeTokenLockTx:jsonStringifyContent(changeTokenLockTx._myContentsName, true);
    -- print('plaintext.len : ', string.len(plaintext));

    -- // for test
    -- local contractJson = json.parse(plaintext);
    -- _commonUtil.prtTable(contractJson['changeTokenLockTx']);
    -- ///////////////////////////////////////////////////////////////////////

    _commonUtil.writeBinaryFile(contentsFilePath, plaintext);

    --
    changeTokenLockTx:remove();

    return plaintext;
end

function contentChangeTokenLockTx.makeContentsJsonEnc()
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

function contentChangeTokenLockTx.makeContentsJsonDec(phase)
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

function contentChangeTokenLockTx.testCase()
    --
    local rtnJsonStr = contentChangeTokenLockTx.makeContentsJson();

    --
    local encMsg = contentChangeTokenLockTx.makeContentsJsonEnc();

    --
    contentChangeTokenLockTx.makeContentsJsonDec(2);
end
