
print('core.contract.list.cAddUser');

local ContrMe = ContractMe;

cAddUser = class(ContrMe);

local auObjs = {}; -- Add User Objects

cAddUser._myContentsObjIdx = {'owner_pk', 'qusuper_pkery', 'account_id'};

cAddUser._myContentsObj = {};
-- local _myContentsObj = AddUser._myContentsObj;

cAddUser._myContentsName = 'contents';
-- local _myContentsName = AddUser._myContentsName;

cAddUser._myContentsList = {
    'owner_pk', 
    'super_pk', 
    'account_id'
};

-- 
function cAddUser:init()
    auObjs[self] = self;

    ContrMe.init(self);
end

function cAddUser:remove()
    auObjs[self] = nil;

    ContrMe.remove(self);
end
