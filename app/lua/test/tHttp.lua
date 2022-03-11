
print('test.tHttp')

tHttp = {
    --
};

--
local prikeyFilePath = './../../../../conf/test/key/ed/key_06/ed_privkey.fin';

function tHttp.encodeURIComponent()
    local prikeyFin = _commonUtil.readBinaryFile(prikeyFilePath);
    local prikeyFinHexStr = _commonUtil.bytesToHexStr(prikeyFin);
    print('prikeyFinHexStr : ', prikeyFinHexStr);

    -- ownerPrikeyPw
    -- io.write('password for *.fin : ');
    -- local ownerPrikeyPw = io.read();
    local prikeyFinPw = "asdfQWER1234!@#$";

    --
    local prikey = aesDecBinary(prikeyFinHexStr, prikeyFinPw, string.len(prikeyFinPw));
    print('prikey : ', prikey);
    local encUriComponent = _http.encodeURIComponent(prikey);
    print('encUriComponent : ', encUriComponent);
end

function tHttp.testCase()
    tHttp.encodeURIComponent();
end
