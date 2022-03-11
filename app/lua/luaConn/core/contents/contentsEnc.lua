
print('core.contents.contentsEnc');

ContentsEnc = class();

--
local cObjs = {}; -- Contents Objects

--------------------------------------------------------
--
ContentsEnc._contentEncObj = {};
local _contentEncObj = ContentsEnc._contentEncObj;

ContentsEnc._contentEncObjName = {
    'contentsEnc', 
    'encXPubkey', 
    'myXPubkey'
};

ContentsEnc._contentEncName = 'jsonEnc';
local contractEncName = ContentsEnc._contentEncName;

--------------------------------------------------------

--
function ContentsEnc:init()
    cObjs[self] = self;

    for _, val in pairs(self._contentEncObjName) do
        self:setContentEncObj(val, '');
    end

    -- self:clrContentEncObj();
end

function ContentsEnc:remove()
    cObjs[self] = nil;
end

--------------------------------------------------------
--
function ContentsEnc:setContentEncObj(key, value)
    self._contentEncObj[key] = value;

    return self._contentEncObj[key];
end

function ContentsEnc:getContentEncObj(key)
    return self._contentEncObj[key];
end

function ContentsEnc:clrContentEncObj()
    self._contentEncObj = nil;
end

--
-- function ContentsEnc:prtContentEncObj()
--     print('Contents:prtContentEncObj');

--     for k, v in pairs(self._contentEncObj) do
--         print('k : ', k, 'v : ', v);
--     end
-- end

-- function ContentsEnc:jsonStringifyContentEnc()
--     local jsonStr = json.stringify(self._contentEncObj, true);
--     -- print('jsonStr : ', jsonStr);

--     local rtnJsonStr = '{"' .. self._contentEncName .. '":' .. jsonStr .. '}';
--     -- print('rtnJsonStr : ', rtnJsonStr);

--     return rtnJsonStr;
-- end

function ContentsEnc:prtContentEncObj(key)
    print('Contents:prtContentEncObj');

    if (key == nil) then
        for k, v in pairs(self._contentEncObj) do
            print('k : ', k, 'v : ', v);
            -- print('k : ', k);
        end
    else
        for k, v in pairs(self._contentEncObj[key]) do
            print('k : ', k, 'v : ', v);
            -- print('k : ', k);
        end
    end
end

--
function ContentsEnc:jsonStringifyContentEnc(key)
    local jsonStr;

    if (key == nil) then
        jsonStr = json.stringify(self._contentEncObj, true);
    else
        jsonStr = json.stringify(self._contentEncObj[key], true);
    end
    
    -- print('jsonStr : ', jsonStr);

    local rtnJsonStr = '{"' .. self._contentEncName .. '":' .. jsonStr .. '}';
    -- print('rtnJsonStr : ', rtnJsonStr);

    return rtnJsonStr;
end
--------------------------------------------------------

--
function ContentsEnc:makeEncJsonMsg(encMsg, encXPubkey, myXPubkey, encJsonFilePath)
    --
    self:setContentEncObj('contentsEnc', encMsg);
    self:setContentEncObj('encXPubkey', encXPubkey);
    self:setContentEncObj('myXPubkey', myXPubkey);
    -- self:prtContentEncObj(nil);

    --
    local encJsonMsg = self:jsonStringifyContentEnc(nil);

    if (encJsonFilePath ~= nil) then
        _commonUtil.writeBinaryFile(encJsonFilePath, encJsonMsg);
    end

    return encJsonMsg;
end

--------------------------------------------------------
function ContentsEnc:makeContentsJsonEncP1ByFile(contentsFilePath, peerXPubkeyFilePath, myXPrikeyFilePath, contentsEncFilePath)
    -------------------------------------------------------
    -- Phase 1
    --
    local plaintext = _commonUtil.readBinaryFile(contentsFilePath);
    -- print('plaintext.len : ', string.len(plaintext));

    local plaintextHexStr = _commonUtil.bytesToHexStr(plaintext);
    print('plaintextHexStr.len : ', string.len(plaintextHexStr));
    print('plaintextHexStr : ', plaintextHexStr);

    -- peerXPubkey
    local peerXPubkey = ed25519GetPubkey(peerXPubkeyFilePath);
    -- local peerXPubkey = '308b942a2eae006d4adf46761cfa58b3c86c89d76bd0d05b3ee68b480552ab21'; -- Pubkey of FBN1
    print("peerXPubkey : ", peerXPubkey);

    -- myXPrikeyFile
    local myXPrikeyFile = _commonUtil.readBinaryFile(myXPrikeyFilePath);
    -- print('myXPrikeyFile.len : ', string.len(myXPrikeyFile));
    -- print("myXPrikeyFile : ", myXPrikeyFile);

    -- encMsg
    local encMsg = x25519MixEnc(myXPrikeyFile, peerXPubkey, plaintextHexStr, string.len(plaintextHexStr));
    -- print("encMsg : ", encMsg);

    if (contentsEncFilePath ~= nil) then
        local encMsg_b = _commonUtil.hexStrToBytes(encMsg);
        _commonUtil.writeBinaryFile(contentsEncFilePath, encMsg_b);
    end
    -------------------------------------------------------

    return encMsg;
end

function ContentsEnc:makeContentsJsonEncP2ByFile(encMsg, peerXPubkeyFilePath, myXPubkeyFilePath, encJsonFilePath)
    -------------------------------------------------------
    -- Phase 2
    -- peerXPubkey
    local peerXPubkey = ed25519GetPubkey(peerXPubkeyFilePath);
    -- local peerXPubkey = '308b942a2eae006d4adf46761cfa58b3c86c89d76bd0d05b3ee68b480552ab21'; -- Pubkey of FBN1
    print("peerXPubkey : ", peerXPubkey);

    -- myXPubkey
    local myXPubkey = ed25519GetPubkey(myXPubkeyFilePath);
    -- print("myXPubkey : ", myXPubkey);
    
    --
    local encXPubkeyF = _commonUtil.insertStr(peerXPubkey, '05', 0);
    local myXPubkeyF = _commonUtil.insertStr(myXPubkey, '05', 0);
    local encJsonMsg = self:makeEncJsonMsg(encMsg, encXPubkeyF, myXPubkeyF, encJsonFilePath);
    -------------------------------------------------------

    return encJsonMsg;
end

function ContentsEnc:makeContentsJsonEncP1(contentsFilePath, peerXPubkey, myXPrikeyFilePath, contentsEncFilePath)
    -------------------------------------------------------
    -- Phase 1
    --
    local plaintext = _commonUtil.readBinaryFile(contentsFilePath);
    -- print('plaintext.len : ', string.len(plaintext));

    local plaintextHexStr = _commonUtil.bytesToHexStr(plaintext);
    print('plaintextHexStr.len : ', string.len(plaintextHexStr));
    print('plaintextHexStr : ', plaintextHexStr);

    -- myXPrikeyFile
    local myXPrikeyFile = _commonUtil.readBinaryFile(myXPrikeyFilePath);
    -- print('myXPrikeyFile.len : ', string.len(myXPrikeyFile));
    -- print("myXPrikeyFile : ", myXPrikeyFile);

    -- encMsg
    local encMsg = x25519MixEnc(myXPrikeyFile, peerXPubkey, plaintextHexStr, string.len(plaintextHexStr));
    -- print("encMsg : ", encMsg);

    if (contentsEncFilePath ~= nil) then
        local encMsg_b = _commonUtil.hexStrToBytes(encMsg);
        _commonUtil.writeBinaryFile(contentsEncFilePath, encMsg_b);
    end
    -------------------------------------------------------

    return encMsg;
end

function ContentsEnc:makeContentsJsonEncP2(encMsg, peerXPubkey, myXPubkeyFilePath, encJsonFilePath)
    -------------------------------------------------------
    -- Phase 2

    -- myXPubkey
    local myXPubkey = ed25519GetPubkey(myXPubkeyFilePath);
    -- print("myXPubkey : ", myXPubkey);

    --
    local encXPubkeyF = _commonUtil.insertStr(peerXPubkey, '05', 0);
    local myXPubkeyF = _commonUtil.insertStr(myXPubkey, '05', 0);
    local encJsonMsg = self:makeEncJsonMsg(encMsg, encXPubkeyF, myXPubkeyF, encJsonFilePath);
    -------------------------------------------------------

    return encJsonMsg;
end
--------------------------------------------------------

function ContentsEnc:makeContentsJsonDecByFile(encJsonFilePath, contentsEncFilePath, peerXPubkeyFilePath, myXPrikeyFilePath)
    -- Phase 1
    --
    local encMsg;
    local encMsgHexStr;

    if (encJsonFilePath ~= nil) then
        local encJsonMsg = _commonUtil.readBinaryFile(encJsonFilePath);
        -- print('encJsonMsg.length : ', string.len(encJsonMsg));
    
        --
        local encJson = json.parse(encJsonMsg);
        -- _commonUtil.prtTable(encJson['jsonEnc']);

        --
        -- encMsg = encJson['jsonEnc']['contentsEnc'];
        encMsgHexStr = encJson['jsonEnc']['contentsEnc'];
    elseif (contentsEncFilePath ~= nil) then
        encMsg = _commonUtil.readBinaryFile(contentsEncFilePath);
        encMsgHexStr = _commonUtil.bytesToHexStr(encMsg);
    else
        return false;
    end

    -- print('encMsg.len : ', string.len(encMsg));
    -- print('encMsg : ', encMsg);

    -- local encMsgHexStr = _commonUtil.bytesToHexStr(encMsg);
    -- print('encMsgHexStr.len : ', string.len(encMsgHexStr));
    -- print('encMsgHexStr : ', encMsgHexStr);

    --
    local peerXPubkey = ed25519GetPubkey(peerXPubkeyFilePath);
    -- print("peerXPubkey : ", peerXPubkey);

    --
    local myXPrikeyFile = _commonUtil.readBinaryFile(myXPrikeyFilePath);
    -- print('myXPrikeyFile.len : ', string.len(myXPrikeyFile));
    -- print("myXPrikeyFile : ", myXPrikeyFile);

    plaintext = x25519MixDec(myXPrikeyFile, peerXPubkey, encMsgHexStr, string.len(encMsgHexStr));
    -- print('plaintext.len : ', string.len(plaintext));
    -- print("plaintext : ", plaintext);

    return plaintext;
end

function ContentsEnc:makeContentsJsonDec(encJsonFilePath, contentsEncFilePath, peerXPubkey, myXPrikeyFilePath)
    --
    local encMsg;
    local encMsgHexStr;

    if (encJsonFilePath ~= nil) then
        -- Phase 1
        local encJsonMsg = _commonUtil.readBinaryFile(encJsonFilePath);
        -- print('encJsonMsg.length : ', string.len(encJsonMsg));
    
        --
        local encJson = json.parse(encJsonMsg);
        -- _commonUtil.prtTable(encJson['jsonEnc']);

        --
        -- encMsg = encJson['jsonEnc']['contentsEnc'];
        encMsgHexStr = encJson['jsonEnc']['contentsEnc'];
    elseif (contentsEncFilePath ~= nil) then
        -- Phase 2
        encMsg = _commonUtil.readBinaryFile(contentsEncFilePath);
        encMsgHexStr = _commonUtil.bytesToHexStr(encMsg);
    else
        return false;
    end

    -- print('encMsg.len : ', string.len(encMsg));
    -- print('encMsg : ', encMsg);

    -- local encMsgHexStr = _commonUtil.bytesToHexStr(encMsg);
    -- print('encMsgHexStr.len : ', string.len(encMsgHexStr));
    -- print('encMsgHexStr : ', encMsgHexStr);

    --
    local myXPrikeyFile = _commonUtil.readBinaryFile(myXPrikeyFilePath);
    -- print('myXPrikeyFile.len : ', string.len(myXPrikeyFile));
    -- print("myXPrikeyFile : ", myXPrikeyFile);

    plaintext = x25519MixDec(myXPrikeyFile, peerXPubkey, encMsgHexStr, string.len(encMsgHexStr));
    -- print('plaintext.len : ', string.len(plaintext));
    -- print("plaintext : ", plaintext);

    return plaintext;
end
