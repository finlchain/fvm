
print('core.utils.commonUtil')

_commonUtil = {
    --
};

function _commonUtil.getTableLen(T)
    local count = 0
    for _ in pairs(T) do count = count + 1 end
    return count
end

function _commonUtil.prtTable(T)
    print('_commonUtil:prtTabble');

    for k, v in pairs(T) do
        print('k : ', k, 'v : ', v);
    end
end

function _commonUtil.splitStr (inputstr, sep)
    if sep == nil then
            sep = "%s"
    end
    local t={}
    for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
            table.insert(t, str)
    end
    return t
end

function _commonUtil.hexStrToBytes(hexStr)
    return (hexStr:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

function _commonUtil.bytesToHexStr(str)
    return (str:gsub('.', function (c)
        return string.format('%02x', string.byte(c))
    end))
end

-- function _commonUtil.bytesToHexStr (str)
--     local len = string.len( str )
--     local hex = ""
    
--     for i = 1, len do
--         local ord = string.byte( str, i )
--         hex = hex .. string.format( "%02X", ord )
--     end

--     return hex
-- end

function _commonUtil.readBinaryFile(filePath)
    local file = assert(io.open(filePath, "rb"));
    local fData = file:read("*all");
    assert(file:close());
    -- local hexD = _debug.hex_dump(fData);
    -- print('hexD : ');
    -- print(hexD);

    return fData;
end

function _commonUtil.writeBinaryFile(filePath, fData)
    local file = assert(io.open(filePath, "wb"));
    file:write(fData);
    assert(file:close());
    -- local hexD = _debug.hex_dump(fData);
    -- print('hexD : ');
    -- print(hexD);
end

function _commonUtil.readFile(filePath)
    local file = assert(io.open(filePath, "r"));
    local fData = file:read("*all");
    assert(file:close());

    return fData;
end

function _commonUtil.writeFile(filePath, fData)
    local file = assert(io.open(filePath, "w"));
    file:write(fData);
    assert(file:close());
end

--
function _commonUtil.unescape(text)
    for uchar in string.gmatch(text, "\\u([0-9a-f][0-9a-f][0-9a-f][0-9a-f])") do
        print('uchar : ', uchar);
        -- text = text:gsub("\\u"..uchar, utf8.char("0x"..uchar));
        text = text:gsub("\\u"..uchar, string.format( "%02x", uchar ));
    end
    return text;
end 

--
function _commonUtil.insertStr(str1, str2, pos)
    return str1:sub(0,pos)..str2..str1:sub(pos+0);
end

local clock = os.clock
function _commonUtil.sleep(n)  -- seconds
    local t0 = clock()
    while clock() - t0 <= n do end
end

-- Refer to :
-- https://stackoverflow.com/questions/25403979/lua-only-call-a-function-if-it-exists/25557991
-- https://www.geeks3d.com/hacklab/20171129/how-to-check-if-a-lua-function-exists/
function _commonUtil.luaExeFunc(mainFunc, subFunc)
    if (mainFunc ~= nil) and (subFunc ~= nil) then
        if (_G[mainFunc] ~= nil) then
            -- print("%s lib is exposed.", mainFunc);

            if _G[mainFunc][subFunc] ~= nil then 
                -- print("%s.%s() is exposed.", mainFunc, subFunc); 
                _G[mainFunc][subFunc]();
            else
                -- print("%s.%s() is NOT exposed.", mainFunc, subFunc);
            end
        else
            -- print("%s lib is NOT exposed.", mainFunc);
        end
    elseif (mainFunc ~= nil) then
        if (_G[mainFunc] ~= nil) then
            -- print("%s lib is exposed.", mainFunc);
            _G[mainFunc]();
        else
            -- print("%s lib is NOT exposed.", mainFunc);
        end
    else
        -- print("Any lib is NOT exposed.");
    end
end
