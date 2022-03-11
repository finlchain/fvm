
print('core.contents.list.createToken');

local ContMe = ContentsMe;

CreateToken = class(ContMe);

local auObjs = {}; -- Create Token Objects

CreateToken._myContentsObj = {};
-- local _myContentsObj = CreateToken._myContentsObj;

CreateToken._myContentsName = 'createToken';
-- local _myContentsName = CreateToken._myContentsName;

CreateToken._myContentsList = {
    'ownerPrikey', 
    'ownerPrikeyPw', 
    'ownerPubkey', 
    'superPubkey', 
    'tokenAction',
    'tokenName',
    'tokenSymbol',
    'totalSupply',
    'decimalPoint'
};

-- 
function CreateToken:init()
    auObjs[self] = self;

    ContMe.init(self);
end

function CreateToken:remove()
    auObjs[self] = nil;

    ContMe.remove(self);
end
