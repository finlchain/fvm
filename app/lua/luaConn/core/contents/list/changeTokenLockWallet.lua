
print('core.contents.list.changeTokenLockWallet');

local ContMe = ContentsMe;

ChangeTokenLockWallet = class(ContMe);

local auObjs = {}; -- Change Token Lock Wallet Objects

ChangeTokenLockWallet._myContentsObj = {};
-- local _myContentsObj = ChangeTokenLockWallet._myContentsObj;

ChangeTokenLockWallet._myContentsName = 'changeTokenLockWallet';
-- local _myContentsName = ChangeTokenLockWallet._myContentsName;

ChangeTokenLockWallet._myContentsList = {
    'tokenAction', 
    'bloackPkList', 
    'whitePkList', 
    'regSuperPrikey', 
    'regSuperPrikeyPw', 
    'regSuperPubkey'
};

-- 
function ChangeTokenLockWallet:init()
    auObjs[self] = self;

    ContMe.init(self);
end

function ChangeTokenLockWallet:remove()
    auObjs[self] = nil;

    ContMe.remove(self);
end
