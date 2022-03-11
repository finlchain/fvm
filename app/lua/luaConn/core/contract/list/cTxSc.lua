
print('core.contract.list.cCreateSc');

local ContrMe = ContractMe;

cTxSc = class(ContrMe);

local auObjs = {}; -- Add User Objects

cTxSc._myContentsObjIdx = {'sc'};

cTxSc._myContentsObj = {};
-- local _myContentsObj = AddUser._myContentsObj;

cTxSc._myContentsName = 'contents';
-- local _myContentsName = AddUser._myContentsName;

cTxSc._myContentsList = {
    'sc'
};

-- 
function cTxSc:init()
    auObjs[self] = self;

    ContrMe.init(self);
end

function cTxSc:remove()
    auObjs[self] = nil;

    ContrMe.remove(self);
end
