
print('core.contract.list.cTxToken');

local ContrMe = ContractMe;

cTxUtilToken = class(ContrMe);

local auObjs = {}; -- Add User Objects

cTxUtilToken._myContentsObjIdx = {'dst_account', 'amount'};

cTxUtilToken._myContentsObj = {};
-- local _myContentsObj = AddUser._myContentsObj;

cTxUtilToken._myContentsName = 'contents';
-- local _myContentsName = AddUser._myContentsName;

cTxUtilToken._myContentsList = {
    'dst_account', 
    'amount'
};

-- 
function cTxUtilToken:init()
    auObjs[self] = self;

    ContrMe.init(self);
end

function cTxUtilToken:remove()
    auObjs[self] = nil;

    ContrMe.remove(self);
end
