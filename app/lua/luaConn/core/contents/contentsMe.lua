
print('core.contents.contentsMe');

local Cont = Contents;

ContentsMe = class(Cont);

local auObjs = {}; -- Contents Me Objects

-- 
function ContentsMe:init()
    auObjs[self] = self;

    Cont.init(self);

    for _, val in pairs(self._myContentsList) do
        self:setMyContentObj(val, '');
    end

    self:setContentObj(self._myContentsName, self._myContentsObj);
end

function ContentsMe:remove()
    auObjs[self] = nil;

    Cont.remove(self);
end

-- 
function ContentsMe:setMyContentObj(key, value)
    self._myContentsObj[key] = value;
end

--
function ContentsMe:getMyContentObj(key)
    return self._myContentsObj[key];
end

--
function ContentsMe:clrMyContentObj()
    self._myContentsObj = nil;
end

--
-- 
-- function ContentsMe:setMyFieldObj(value)
--     self._myContentsObj[self.] = value;
-- end

--
function ContentsMe:prtMyContentObj()
    print('AddUser:prtMyContentObj');

    for k, v in pairs(self._myContentsObj) do
        print('k : ', k, 'v : ', v);
    end
end
