
print('core.contents.list.changeTokenPubkey');

local ContMe = ContentsMe;

ChangeTokenPubkey = class(ContMe);

local auObjs = {}; -- Change Token Public Key Objects

ChangeTokenPubkey._myContentsObj = {};
-- local _myContentsObj = ChangeTokenPubkey._myContentsObj;

ChangeTokenPubkey._myContentsName = 'changeTokenPubkey';
-- local _myContentsName = ChangeTokenPubkey._myContentsName;

ChangeTokenPubkey._myContentsList = {
    'ownerPubkey', 
    'superPubkey', 
    'tokenAction', 
    'regSuperPrikey', 
    'regSuperPrikeyPw', 
    'regSuperPubkey'
};

-- 
function ChangeTokenPubkey:init()
    auObjs[self] = self;

    ContMe.init(self);
end

function ChangeTokenPubkey:remove()
    auObjs[self] = nil;

    ContMe.remove(self);
end
