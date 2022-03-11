
print('core.contract.contract');

Contract = class();

local cObjs = {}; -- Contract OBJectS

Contract._contractRootObj = {};
-- local _contractRootObj = Contract._contractRootObj;

Contract._contractObj = {};
-- local _contractObj = Contract._contractObj;

Contract._contractName = 'contract';

Contract._contractList = {
    'create_tm', 
    'fintech', 
    'privacy', 
    'fee', 
    'from_account', 
    'to_account', 
    'action', 
    'contents', 
    'memo', 
    'sig', 
    'signed_pubkey'
};

-- local fieldName = Contract._contractList;

function Contract:init()
    cObjs[self] = self;

    for _, fn in pairs(self._contractList) do
        self:setContractObj(fn, '');
    end
    
    -- self:clrContractObj();

    self:setContractRootObj(self._contractObj);
end

function Contract:remove()
    cObjs[self] = nil;
end

--
function Contract:setContractRootObj(value)
    self._contractRootObj[self._contractName] = value;
end

function Contract:getContractRootObj()
    return self._contractRootObj[self._contractName];
end

function Contract:clrContractRootObj()
    self._contractRootObj = nil;
end

--
function Contract:setContractObj(key, value)
    self._contractObj[key] = value;
end

function Contract:getContractObj(key)
    return self._contractObj[key];
end

function Contract:clrContractObj()
    self._contractObj = nil;
end

--
function Contract:prtMyContractObj()
    print('Contract:prtMyContractObj');

    for k, v in pairs(self._contractObj) do
        print('k : ', k, 'v : ', v);
    end
end

--
function Contract:jsonStringifyContent(key, unicode)
    local jsonStr = json.stringify(self._contractObj[key], unicode);
    -- print('jsonStr : ', jsonStr);

    -- local rtnJsonStr = '{"' .. self._myContentsName .. '":' .. jsonStr .. '}';
    -- print('rtnJsonStr : ', rtnJsonStr);

    return jsonStr;
end

--
function Contract:jsonStringifyContract(key, unicode)
    local jsonStr = json.stringify(self._contractRootObj[key], unicode);
    -- print('jsonStr : ', jsonStr);

    local rtnJsonStr = '{"' .. self._contractName .. '":' .. jsonStr .. '}';
    -- print('rtnJsonStr : ', rtnJsonStr);

    return rtnJsonStr;
end

--
function Contract:signBufferGenerator()
    local contentsStr = self:jsonStringifyContent(self._myContentsName, true);

    local mergedBuf = self._contractObj['create_tm'] .. self._contractObj['fintech'] .. self._contractObj['privacy'] .. self._contractObj['fee']
                     .. self._contractObj['from_account'] .. self._contractObj['to_account'] .. self._contractObj['action'] .. contentsStr .. self._contractObj['memo'];

    return mergedBuf;
end