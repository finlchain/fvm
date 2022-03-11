
print('core.contract.list.cAddUser');

local ContrMe = ContractMe;

cCreateToken = class(ContrMe);

local auObjs = {}; -- Add User Objects

cCreateToken._myContentsObjIdx = {'owner_pk', 'super_pk', 'action', 'name', 'symbol', 'total_supply', 'decimal_point', 'lock_time_from', 'lock_time_to', 'lock_transfer', 'black_list', 'functions'};

cCreateToken._myContentsObj = {};
-- local _myContentsObj = AddUser._myContentsObj;

cCreateToken._myContentsName = 'contents';
-- local _myContentsName = AddUser._myContentsName;

cCreateToken._myContentsList = {
    'owner_pk', 
    'super_pk', 
    'action', 
    'name', 
    'symbol', 
    'total_supply', 
    'decimal_point', 
    'lock_time_from', 
    'lock_time_to', 
    'lock_transfer', 
    'black_list', 
    'functions'
};

-- 
function cCreateToken:init()
    auObjs[self] = self;

    ContrMe.init(self);
end

function cCreateToken:remove()
    auObjs[self] = nil;

    ContrMe.remove(self);
end
