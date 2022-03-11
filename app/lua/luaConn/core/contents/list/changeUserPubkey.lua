
print('core.contents.list.changeUserPubkey');

local ContMe = ContentsMe;

ChangeUserPubkey = class(ContMe);

local auObjs = {}; -- Change User Public Key Objects

ChangeUserPubkey._myContentsObj = {};
local _myContentsObj = ChangeUserPubkey._myContentsObj;

ChangeUserPubkey._myContentsName = 'changeUserPubkey';
local _myContentsName = ChangeUserPubkey._myContentsName;

ChangeUserPubkey._myContentsList = {
    'ownerPubkey', 
    'superPubkey', 
    'accountId', 
    'regSuperPrikey', 
    'regSuperPrikeyPw', 
    'regSuperPubkey'
};

-- 
function ChangeUserPubkey:init()
    auObjs[self] = self;

    ContMe.init(self);
end

function ChangeUserPubkey:remove()
    auObjs[self] = nil;

    ContMe.remove(self);
end
