
print('core.contents.list.addUser');

local ContMe = ContentsMe;

AddUser = class(ContMe);

local auObjs = {}; -- Add User Objects

AddUser._myContentsObj = {};
-- local _myContentsObj = AddUser._myContentsObj;

AddUser._myContentsName = 'addUser';
-- local _myContentsName = AddUser._myContentsName;

AddUser._myContentsList = {
    'ownerPrikey', 
    'ownerPrikeyPw', 
    'ownerPubkey', 
    'superPubkey', 
    'accountId'
};

-- 
function AddUser:init()
    auObjs[self] = self;

    ContMe.init(self);
end

function AddUser:remove()
    auObjs[self] = nil;

    ContMe.remove(self);
end
