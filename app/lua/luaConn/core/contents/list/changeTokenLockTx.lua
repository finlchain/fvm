
print('core.contents.list.changeTokenLockTx');

local ContMe = ContentsMe;

ChangeTokenLockTx = class(ContMe);

local auObjs = {}; -- Change Token Lock Tx Objects

ChangeTokenLockTx._myContentsObj = {};
-- local _myContentsObj = ChangeTokenLockTx._myContentsObj;

ChangeTokenLockTx._myContentsName = 'changeTokenLockTx';
-- local _myContentsName = ChangeTokenLockTx._myContentsName;

ChangeTokenLockTx._myContentsList = {
    'tokenAction', 
    'lockTx', 
    'regSuperPrikey', 
    'regSuperPrikeyPw', 
    'regSuperPubkey'
};

-- 
function ChangeTokenLockTx:init()
    auObjs[self] = self;

    ContMe.init(self);
end

function ChangeTokenLockTx:remove()
    auObjs[self] = nil;

    ContMe.remove(self);
end
