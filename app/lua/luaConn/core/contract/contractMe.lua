
print('core.contract.contractMe');

local Contr = Contract;

ContractMe = class(Contr);

local auObjs = {}; -- Contract Me Objects

-- 
function ContractMe:init()
    auObjs[self] = self;

    Contr.init(self);

    for _, val in pairs(self._myContentsList) do
        self:setMyContentObj(val, '');
    end

    self:setContractObj(self._myContentsName, self._myContentsObj);
end

function ContractMe:remove()
    auObjs[self] = nil;

    Contr.remove(self);
end

-- 
function ContractMe:setMyContentObj(key, value)
    self._myContentsObj[key] = value;
end

--
function ContractMe:getMyContentObj(key)
    return self._myContentsObj[key];
end

--
function ContractMe:clrMyContentObj()
    self._myContentsObj = nil;
end

--
-- 
-- function ContractMe:setMyFieldObj(value)
--     self._myContentsObj[self.] = value;
-- end

--
function ContractMe:prtMyContentObj()
    print('ContractMe:prtMyContentObj');

    for k, v in pairs(self._myContentsObj) do
        print('k : ', k, 'v : ', v);
    end
end
