-- _cb
-- _cb = {};
_cb = class();

--
local cObjs = {}; -- Contents Objects

--
_cb.m_cbFunc = nil;

--
function _cb:init()
    cObjs[self] = self;
end

function _cb:remove()
    cObjs[self] = nil;
end

--
function _cb:setCallback( cbFunc)
    self.m_cbFunc = cbFunc;
end

function _cb:runCallback()
    self.m_cbFunc();
end
