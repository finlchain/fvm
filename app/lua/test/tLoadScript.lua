print('test.tLoadScript');

tLoadScript = {
    --
};

function tLoadScript.exeFuncFromTbl(myTbl)
    --
    for k, v in pairs(myTbl) do
        -- print('k : ', k, 'v : ', v);

        local funcNamet = _commonUtil.splitStr(v, '.');
        local funcNameSplictLen = _commonUtil.getTableLen(funcNamet);
        -- print('funcNameSplictLen : ', funcNameSplictLen);

        if (funcNameSplictLen == 1) then
            _commonUtil.luaExeFunc(funcNamet[1]);
        elseif (funcNameSplictLen == 2) then
            -- ex : _commonUtil.luaExeFunc('tCurl', 'testCase');
            _commonUtil.luaExeFunc(funcNamet[1], funcNamet[2]);
        end
    end
end

function tLoadScript.testCase()
    --
    -- local myStr = "return { test = function() print('Test') end }";
    local myScriptStr;
    myScriptStr = " print ('Hello, world. Lua version is', _VERSION)";
    my_require('myModule.lua', myScriptStr);

    myScriptStr = "return { test = function () print('Test'); print('Test23'); _commonUtil.luaExeFunc('tCurl', 'testCase'); end}";
    pre_require("fromstring", myScriptStr);
    local fromstring = require 'fromstring'
    fromstring.test();
end