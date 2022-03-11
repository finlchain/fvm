
print('core.contents.list.changeTokenLockTime');

local ContMe = ContentsMe;

ChangeTokenLockTime = class(ContMe);

local auObjs = {}; -- Change Token Lock Time Objects

ChangeTokenLockTime._myContentsObj = {};
-- local _myContentsObj = ChangeTokenLockTime._myContentsObj;

ChangeTokenLockTime._myContentsName = 'changeTokenLockTime';
-- local _myContentsName = ChangeTokenLockTime._myContentsName;

ChangeTokenLockTime._myContentsList = {
    'tokenAction', 
    'lockTimeFrom', 
    'lockTimeTo', 
    'regSuperPrikey', 
    'regSuperPrikeyPw', 
    'regSuperPubkey'
};

-- 
function ChangeTokenLockTime:init()
    auObjs[self] = self;

    ContMe.init(self);
end

function ChangeTokenLockTime:remove()
    auObjs[self] = nil;

    ContMe.remove(self);
end
