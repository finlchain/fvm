
print('core.contents.contents');

Contents = class();

--
local cObjs = {}; -- Contents Objects

--------------------------------------------------------
--
Contents._contentObj = {};
local _contentObj = Contents._contentObj;

Contents._contentName = {
    'keyGen', 
    'addUser', 
    'changeUserPubkey', 
    'createToken', 
    'changeTokenPubkey', 
    'changeTokenLockTx', 
    'changeTokenLockTime', 
    'changeTokenLockWallet'
};

local _contentName = Contents._contentName;
--------------------------------------------------------

--
function Contents:init()
    cObjs[self] = self;

    for _, val in pairs(self._contentName) do
        self:setContentObj(val, '');
    end

    -- self:clrContentObj();
end

function Contents:remove()
    cObjs[self] = nil;
end

--------------------------------------------------------
--
function Contents:setContentObj(key, value)
    self._contentObj[key] = value;

    return self._contentObj[key];
end

function Contents:getContentObj(key)
    return self._contentObj[key];
end

function Contents:clrContentObj()
    self._contentObj = nil;
end

--
function Contents:prtContentObj()
    print('Contents:prtContentObj');

    for k, v in pairs(self._contentObj) do
        print('k : ', k, 'v : ', v);
    end
end

function Contents:prtContentObjVal(key)
    print('Contents:prtContentObjVal');

    for k, v in pairs(self._contentObj[key]) do
        print('k : ', k, 'v : ', v);
    end
end

--
function Contents:jsonStringifyContent(key, unicode)
    local jsonStr = json.stringify(self._contentObj[key], unicode);
    -- print('jsonStr : ', jsonStr);

    local rtnJsonStr = '{"' .. self._myContentsName .. '":' .. jsonStr .. '}';
    -- print('rtnJsonStr : ', rtnJsonStr);

    return rtnJsonStr;
end
--------------------------------------------------------
