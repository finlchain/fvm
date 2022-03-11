
print('core.contract.list.cCreateSc');

local ContrMe = ContractMe;

cCreateSc = class(ContrMe);

local auObjs = {}; -- Add User Objects

cCreateSc._myContentsObjIdx = {'sc_action', 'action_target', 'sc'};

cCreateSc._myContentsObj = {};
-- local _myContentsObj = AddUser._myContentsObj;

cCreateSc._myContentsName = 'contents';
-- local _myContentsName = AddUser._myContentsName;

cCreateSc._myContentsList = {
    'sc_action', 
    'action_target', 
    'sc'
};

-- 
function cCreateSc:init()
    auObjs[self] = self;

    ContrMe.init(self);
end

function cCreateSc:remove()
    auObjs[self] = nil;

    ContrMe.remove(self);
end
