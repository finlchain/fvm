
print('core.contents.list.addUser');

local Cont = Contents;

AddUser = class(Cont);

local auObjs = {}; -- Add User Objects

AddUser._myContentsObj = {};
local _myContentsObj = AddUser._myContentsObj;

AddUser._myContentsName = 'addUser';
local _myContentsName = AddUser._myContentsName;

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

    Cont.init(self);

    for _, val in pairs(self._myContentsList) do
        self:setMyContentObj(val, '');
    end

    self:setContentObj(_myContentsName, _myContentsObj);
end

function AddUser:remove()
    auObjs[self] = nil;

    Cont.remove(self);
end

-- 
function AddUser:setMyContentObj(key, value)
    self._myContentsObj[key] = value;
end

--
function AddUser:getMyContentObj(key)
    return self._myContentsObj[key];
end

--
function AddUser:clrMyContentObj()
    self._myContentsObj = nil;
end

--
-- 
-- function AddUser:setMyFieldObj(value)
--     self._myContentsObj[self.] = value;
-- end

--
function AddUser:prtMyContentObj()
    print('AddUser:prtMyContentObj');

    for k, v in pairs(self._myContentsObj) do
        print('k : ', k, 'v : ', v);
    end
end
