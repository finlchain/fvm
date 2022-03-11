
print('core.contract.list.cTxToken');

local ContrMe = ContractMe;

cTxSecToken = class(ContrMe);

local auObjs = {}; -- Add User Objects

cTxSecToken._myContentsObjIdx = {'amount'};

cTxSecToken._myContentsObj = {};
-- local _myContentsObj = AddUser._myContentsObj;

cTxSecToken._myContentsName = 'contents';
-- local _myContentsName = AddUser._myContentsName;

cTxSecToken._myContentsList = {
    'amount', 
};

-- 
function cTxSecToken:init()
    auObjs[self] = self;

    ContrMe.init(self);
end

function cTxSecToken:remove()
    auObjs[self] = nil;

    ContrMe.remove(self);
end
