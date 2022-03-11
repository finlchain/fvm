print('test.keyGen')

keyGen = {
    --
};

local keyGenPath = './../../test/key/crypto/out/'; 

--
local pw = "신의 축복이 있기를.";
local pwLen = string.len(pw);

local mnemonic1 = "신의 축복이 있기를.";
local mnemonic2 = "신의 축복이 있기를.";
local rand_num = 0;

--
function keyGen.ed25519()

    io.write("insert your password : ");

    io.flush();

    local prikeyPw = io.read();

    -- local prikeyPw = "asdfQWER1234!@#$";

    local prikeyPwLen = string.len(prikeyPw);

    print("prikeyPw : ", prikeyPw);
    print("prikeyPwLen : ", prikeyPwLen);

    local pwChk = _chkPw.chkPwStrength(nil, prikeyPw);
    print("pwChk : ", pwChk);

    local ret = false;

    if (pwChk == true) then
        ret = ed25519KeyGenFinWithMnemonic(keyGenPath, pw, mnemonic1, mnemonic2, rand_num, prikeyPw, prikeyPwLen);
        -- ret = ed25519KeyGenFin(keyGenPath, prikeyPw, prikeyPwLen);
        print("ret ed25519 : ", ret);
    end

    return ret;
end

--
function keyGen.x25519()
    local ret = x25519KeyGenPemWithMnemonic(keyGenPath, pw, mnemonic1, mnemonic2, rand_num);
    -- local ret = x25519KeyGenPem(keyGenPath);
    print("ret x25519 : ", ret);

    return ret;
end

--
function keyGen.keyMasterChainCode()
    local rand_num = keyCreateMasterChainCode(pw, mnemonic1, mnemonic2);
    print(rand_num);

    local masterChainCode = keyRestoreMasterChainCode(pw, mnemonic1, mnemonic2, rand_num);
    print(masterChainCode);
end

--
function keyGen.ed25519Ori()
    -- io.write("insert your password : ");

    -- io.flush();

    -- local prikeyPw = io.read();

    local prikeyPw = "asdfQWER1234!@#$";

    local prikeyPwLen = string.len(prikeyPw);

    print("prikeyPw : ", prikeyPw);
    print("prikeyPwLen : ", prikeyPwLen);

    local pwChk = _chkPw.chkPwStrength(nil, prikeyPw);
    print("pwChk : ", pwChk);

    local ret = false;

    if (pwChk == true) then
        ret = ed25519KeyGenFinWithMnemonicOri(keyGenPath, mnemonic1, prikeyPw, prikeyPw, prikeyPwLen);
        -- ret = ed25519KeyGenFin(keyGenPath, prikeyPw, prikeyPwLen);
        print("ret ed25519 : ", ret);
    end

    return ret;
end

--
function keyGen.x25519Ori()
    local prikeyPw = "asdfQWER1234!@#$";

    local prikeyPwLen = string.len(prikeyPw);

    print("prikeyPw : ", prikeyPw);
    print("prikeyPwLen : ", prikeyPwLen);

    local ret = x25519KeyGenPemWithMnemonicOri(keyGenPath, mnemonic1, prikeyPw);
    -- local ret = x25519KeyGenPem(keyGenPath);
    print("ret x25519 : ", ret);

    return ret;
end

--
function keyGen.keyMasterChainCodeOri()
    local masterChainCodeStrLen = keyCreateMasterChainCodeOri(mnemonic1, pw);
    print("masterChainCodeStrLen : ", masterChainCodeStrLen);

    if (masterChainCodeStrLen > 0) then
        local masterChainCode = keyRestoreMasterChainCodeOri(mnemonic1, pw);
        print(masterChainCode);
    end
end

function keyGen.testCase()
    -- --
    -- local ret1 = keyGen.ed25519();

    -- --
    -- if (ret1 ~= false) then
    --     local ret2 = keyGen.x25519();
    -- end

    -- keyGen.keyMasterChainCode();

    -- --
    -- local ret1 = keyGen.ed25519Ori();

    -- --
    -- if (ret1 ~= false) then
    --     local ret2 = keyGen.x25519Ori();
    -- end

    keyGen.keyMasterChainCodeOri();
end