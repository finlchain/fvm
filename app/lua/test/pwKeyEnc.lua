print('test.pwKeyEnc')

pwKeyEnc = {
    --
};

--
local seedPath = "./../conf/seed";

--
local chainName = "finl";

-- 
local pwShard = "+" .. chainName .. "shard135@$";
local pwRepl = "+" .. chainName .. "repl@$135";
local pwReplIS = "+" .. chainName .. "rpis@$135";
local pwReplNN = "+" .. chainName .. "rpnn@$135";
local pwReplISAG = "+" .. chainName .. "rpisag@$135";
--
local pwRedis = chainName .. "+pwd";
local pwMariaIS = chainName .. "is+Pwd@1";
local pwMariaISAG = chainName .. "isag+Pwd@1";
local pwMariaNN = chainName .. "nn+Pwd@1";
local pwMariaFBN = chainName .. "fbn+Pwd@1";

--
local pwPathRoot = "./out/" .. chainName .. "/pw/"

--
function pwKeyEnc.pwShard()
    print("========= Shard PW Enc =========");
    local pw = pwShard;
    local pwLen = string.len(pw);
    local pwPath = pwPathRoot .. "pw_shard.fin";
    
    -- ** Encrypt Passwd
    -- *** return true : success, false : fail
    local testEncPw = aesEncPw(seedPath, pw, pwLen, pwPath);
    if (testEncPw == true) then
        print("success");
    else 
        print("fail");
    end
    
    -- ** Decrypt Passwd
    -- *** return passwd
    local testDecPw = aesDecPw(seedPath, pwPath);
    print(testDecPw);
end

function pwKeyEnc.pwRepl()
    print("========= Replication PW Enc =========");
    local pw = pwRepl;
    local pwLen = string.len(pw);
    local pwPath = pwPathRoot .. "pw_repl.fin";
    
    -- ** Encrypt Passwd
    -- *** return true : success, false : fail
    local testEncPw = aesEncPw(seedPath, pw, pwLen, pwPath);
    if (testEncPw == true) then
        print("success");
    else
        print("fail");
    end
    
    -- ** Decrypt Passwd
    -- *** return passwd
    local testDecPw = aesDecPw(seedPath, pwPath);
    print(testDecPw);
end

function pwKeyEnc.pwReplIS()
    print("========= Replication IS PW Enc =========");
    local pw = pwReplIS;
    local pwLen = string.len(pw);
    print("pwPathRoot : ", pwPathRoot)
    local pwPath = pwPathRoot .. "pw_is.fin";
    
    -- ** Encrypt Passwd
    -- *** return true : success, false : fail
    local testEncPw = aesEncPw(seedPath, pw, pwLen, pwPath);
    if (testEncPw == true) then
        print("success");
    else
        print("fail");
    end
    
    -- ** Decrypt Passwd
    -- *** return passwd
    local testDecPw = aesDecPw(seedPath, pwPath);
    print(testDecPw);
end

function pwKeyEnc.pwReplNN()
    print("========= Replication NN PW Enc =========");
    local pw = pwReplNN;
    local pwLen = string.len(pw);
    local pwPath = pwPathRoot .. "pw_nn.fin";
    
    -- ** Encrypt Passwd
    -- *** return true : success, false : fail
    local testEncPw = aesEncPw(seedPath, pw, pwLen, pwPath);
    if (testEncPw == true) then
        print("success");
    else
        print("fail");
    end
    
    -- ** Decrypt Passwd
    -- *** return passwd
    local testDecPw = aesDecPw(seedPath, pwPath);
    print(testDecPw);
end

function pwKeyEnc.pwReplISAG()
    print("========= Replication ISAG PW Enc =========");
    local pw = pwReplISAG;
    local pwLen = string.len(pw);
    local pwPath = pwPathRoot .. "pw_isag.fin";
    
    -- ** Encrypt Passwd
    -- *** return true : success, false : fail
    local testEncPw = aesEncPw(seedPath, pw, pwLen, pwPath);
    if (testEncPw == true) then
        print("success");
    else
        print("fail");
    end
    
    -- ** Decrypt Passwd
    -- *** return passwd
    local testDecPw = aesDecPw(seedPath, pwPath);
    print(testDecPw);
end

--
function pwKeyEnc.pwRedis()
    print("========= Redis PW Enc =========");
    local pw = pwRedis;
    local pwLen = string.len(pw);
    local pwPath = pwPathRoot .. "pw_redis.fin";
    
    -- ** Encrypt Passwd
    -- *** return true : success, false : fail
    local testEncPw = aesEncPw(seedPath, pw, pwLen, pwPath);
    if (testEncPw == true) then
        print("success");
    else
        print("fail");
    end
    
    -- ** Decrypt Passwd
    -- *** return passwd
    local testDecPw = aesDecPw(seedPath, pwPath);
    print(testDecPw);
end

function pwKeyEnc.pwMariaIS()
    print("========= IS Maria PW Enc =========");
    local pw = pwMariaIS;
    local pwLen = string.len(pw);
    local pwPath = pwPathRoot .. "pw_maria_is.fin";
    
    -- ** Encrypt Passwd
    -- *** return true : success, false : fail
    local testEncPw = aesEncPw(seedPath, pw, pwLen, pwPath);
    if (testEncPw == true) then
        print("success");
    else
        print("fail");
    end
    
    -- ** Decrypt Passwd
    -- *** return passwd
    local testDecPw = aesDecPw(seedPath, pwPath);
    print(testDecPw);
end

function pwKeyEnc.pwMariaISAG()
    print("========= ISAG Maria PW Enc =========");
    local pw = pwMariaISAG;
    local pwLen = string.len(pw);
    local pwPath = pwPathRoot .. "pw_maria_isag.fin";
    
    -- ** Encrypt Passwd
    -- *** return true : success, false : fail
    local testEncPw = aesEncPw(seedPath, pw, pwLen, pwPath);
    if (testEncPw == true) then
        print("success");
    else
        print("fail");
    end
    
    -- ** Decrypt Passwd
    -- *** return passwd
    local testDecPw = aesDecPw(seedPath, pwPath);
    print(testDecPw);
end

function pwKeyEnc.pwMariaNN()
    print("========= NN Maria PW Enc =========");
    local pw = pwMariaNN;
    local pwLen = string.len(pw);
    local pwPath = pwPathRoot .. "pw_maria_nn.fin";
    
    -- ** Encrypt Passwd
    -- *** return true : success, false : fail
    local testEncPw = aesEncPw(seedPath, pw, pwLen, pwPath);
    if (testEncPw == true) then
        print("success");
    else
        print("fail");
    end
    
    -- ** Decrypt Passwd
    -- *** return passwd
    local testDecPw = aesDecPw(seedPath, pwPath);
    print(testDecPw);
end

function pwKeyEnc.pwMariaFBN()
    print("========= FBN Maria PW Enc =========");
    local pw = pwMariaFBN;
    local pwLen = string.len(pw);
    local pwPath = pwPathRoot .. "pw_maria_fbn.fin";
    
    -- ** Encrypt Passwd
    -- *** return true : success, false : fail
    local testEncPw = aesEncPw(seedPath, pw, pwLen, pwPath);
    if (testEncPw == true) then
        print("success");
    else
        print("fail");
    end
    
    -- ** Decrypt Passwd
    -- *** return passwd
    local testDecPw = aesDecPw(seedPath, pwPath);
    print(testDecPw);
end

--
local edKeyPemName = "ed_privkey.pem";
local edKeyFinName = "ed_privkey.fin";
local xKeyPemName = "x_privkey.pem";

local keyPath = "./out/" .. chainName .."/key/";
local keyPathIS = keyPath .. "is_";

local keyPathNN1 = keyPath .. "nn1_";
local keyPathISAG1 = keyPath .. "isag1_";
local keyPathFBN1 = keyPath .. "fbn1_";

local keyPathNN2 = keyPath .. "nn2_";
local keyPathISAG2 = keyPath .. "isag2_";
local keyPathFBN2 = keyPath .. "fbn2_";

local keyPathNN3 = keyPath .. "nn3_";
local keyPathISAG3 = keyPath .. "isag3_";
local keyPathFBN3 = keyPath .. "fbn3_";

local keyPathNN4 = keyPath .. "nn4_";
local keyPathISAG4 = keyPath .. "isag4_";
local keyPathFBN4 = keyPath .. "fbn4_";

local keyPathNN5 = keyPath .. "nn5_";
local keyPathISAG5 = keyPath .. "isag5_";
local keyPathFBN5 = keyPath .. "fbn5_";

local keyPathNN6 = keyPath .. "nn6_";
local keyPathISAG6 = keyPath .. "isag6_";
local keyPathFBN6 = keyPath .. "fbn6_";

local keyPathNN7 = keyPath .. "nn7_";
local keyPathISAG7 = keyPath .. "isag7_";
local keyPathFBN7 = keyPath .. "fbn7_";

--
function pwKeyEnc.keyGenIS()
    --
    print("========= IS ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathIS);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= IS X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathIS);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncIS()
    --
    local srcPath = keyPathIS .. edKeyPemName;
    local seed = pwMariaIS;
    local seedLen = string.len(seed);
    local dstPath = keyPathIS .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

-------------------------------------------------------
-- Cluster 1
--
function pwKeyEnc.keyGenNN1()
    --
    print("========= NN1 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathNN1);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= NN1 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathNN1);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncNN1()
    --
    local srcPath = keyPathNN1 .. edKeyPemName;
    local seed = pwMariaNN;
    local seedLen = string.len(seed);
    local dstPath = keyPathNN1 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

--
function pwKeyEnc.keyGenISAG1()
    --
    print("========= ISAG1 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathISAG1);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= ISAG1 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathISAG1);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncISAG1()
    --
    local srcPath = keyPathISAG1 .. edKeyPemName;
    local seed = pwMariaISAG;
    local seedLen = string.len(seed);
    local dstPath = keyPathISAG1 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

--
function pwKeyEnc.keyGenFBN1()
    --
    print("========= FBN1 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathFBN1);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= FBN1 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathFBN1);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncFBN1()
    --
    local srcPath = keyPathFBN1 .. edKeyPemName;
    local seed = pwMariaFBN;
    local seedLen = string.len(seed);
    local dstPath = keyPathFBN1 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

-------------------------------------------------------
-- Cluster 2
--
function pwKeyEnc.keyGenNN2()
    --
    print("========= NN2 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathNN2);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= NN2 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathNN2);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncNN2()
    --
    local srcPath = keyPathNN2 .. edKeyPemName;
    local seed = pwMariaNN;
    local seedLen = string.len(seed);
    local dstPath = keyPathNN2 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

--
function pwKeyEnc.keyGenISAG2()
    --
    print("========= ISAG2 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathISAG2);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= ISAG2 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathISAG2);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncISAG2()
    --
    local srcPath = keyPathISAG2 .. edKeyPemName;
    local seed = pwMariaISAG;
    local seedLen = string.len(seed);
    local dstPath = keyPathISAG2 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

--
function pwKeyEnc.keyGenFBN2()
    --
    print("========= FBN2 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathFBN2);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= FBN2 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathFBN2);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncFBN2()
    --
    local srcPath = keyPathFBN2 .. edKeyPemName;
    local seed = pwMariaFBN;
    local seedLen = string.len(seed);
    local dstPath = keyPathFBN2 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

-------------------------------------------------------
-- Cluster 3
--
function pwKeyEnc.keyGenNN3()
    --
    print("========= NN3 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathNN3);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= NN3 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathNN3);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncNN3()
    --
    local srcPath = keyPathNN3 .. edKeyPemName;
    local seed = pwMariaNN;
    local seedLen = string.len(seed);
    local dstPath = keyPathNN3 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

--
function pwKeyEnc.keyGenISAG3()
    --
    print("========= ISAG3 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathISAG3);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= ISAG3 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathISAG3);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncISAG3()
    --
    local srcPath = keyPathISAG3 .. edKeyPemName;
    local seed = pwMariaISAG;
    local seedLen = string.len(seed);
    local dstPath = keyPathISAG3 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

--
function pwKeyEnc.keyGenFBN3()
    --
    print("========= FBN3 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathFBN3);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= FBN3 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathFBN3);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncFBN3()
    --
    local srcPath = keyPathFBN3 .. edKeyPemName;
    local seed = pwMariaFBN;
    local seedLen = string.len(seed);
    local dstPath = keyPathFBN3 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

-------------------------------------------------------
-- Cluster 4
--
function pwKeyEnc.keyGenNN4()
    --
    print("========= NN4 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathNN4);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= NN4 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathNN4);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncNN4()
    --
    local srcPath = keyPathNN4 .. edKeyPemName;
    local seed = pwMariaNN;
    local seedLen = string.len(seed);
    local dstPath = keyPathNN4 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

--
function pwKeyEnc.keyGenISAG4()
    --
    print("========= ISAG4 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathISAG4);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= ISAG4 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathISAG4);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncISAG4()
    --
    local srcPath = keyPathISAG4 .. edKeyPemName;
    local seed = pwMariaISAG;
    local seedLen = string.len(seed);
    local dstPath = keyPathISAG4 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

--
function pwKeyEnc.keyGenFBN4()
    --
    print("========= FBN4 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathFBN4);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= FBN4 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathFBN4);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncFBN4()
    --
    local srcPath = keyPathFBN4 .. edKeyPemName;
    local seed = pwMariaFBN;
    local seedLen = string.len(seed);
    local dstPath = keyPathFBN4 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

-------------------------------------------------------
-- Cluster 5
--
function pwKeyEnc.keyGenNN5()
    --
    print("========= NN5 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathNN5);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= NN5 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathNN5);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncNN5()
    --
    local srcPath = keyPathNN5 .. edKeyPemName;
    local seed = pwMariaNN;
    local seedLen = string.len(seed);
    local dstPath = keyPathNN5 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

--
function pwKeyEnc.keyGenISAG5()
    --
    print("========= ISAG5 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathISAG5);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= ISAG5 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathISAG5);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncISAG5()
    --
    local srcPath = keyPathISAG5 .. edKeyPemName;
    local seed = pwMariaISAG;
    local seedLen = string.len(seed);
    local dstPath = keyPathISAG5 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

--
function pwKeyEnc.keyGenFBN5()
    --
    print("========= FBN5 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathFBN5);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= FBN5 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathFBN5);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncFBN5()
    --
    local srcPath = keyPathFBN5 .. edKeyPemName;
    local seed = pwMariaFBN;
    local seedLen = string.len(seed);
    local dstPath = keyPathFBN5 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

-------------------------------------------------------
-- Cluster 6
--
function pwKeyEnc.keyGenNN6()
    --
    print("========= NN6 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathNN6);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= NN6 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathNN6);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncNN6()
    --
    local srcPath = keyPathNN6 .. edKeyPemName;
    local seed = pwMariaNN;
    local seedLen = string.len(seed);
    local dstPath = keyPathNN6 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

--
function pwKeyEnc.keyGenISAG6()
    --
    print("========= ISAG6 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathISAG6);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= ISAG6 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathISAG6);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncISAG6()
    --
    local srcPath = keyPathISAG6 .. edKeyPemName;
    local seed = pwMariaISAG;
    local seedLen = string.len(seed);
    local dstPath = keyPathISAG6 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

--
function pwKeyEnc.keyGenFBN6()
    --
    print("========= FBN6 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathFBN6);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= FBN6 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathFBN6);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncFBN6()
    --
    local srcPath = keyPathFBN6 .. edKeyPemName;
    local seed = pwMariaFBN;
    local seedLen = string.len(seed);
    local dstPath = keyPathFBN6 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

-------------------------------------------------------
-- Cluster 7
--
function pwKeyEnc.keyGenNN7()
    --
    print("========= NN7 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathNN7);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= NN7 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathNN7);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncNN7()
    --
    local srcPath = keyPathNN7 .. edKeyPemName;
    local seed = pwMariaNN;
    local seedLen = string.len(seed);
    local dstPath = keyPathNN7 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

--
function pwKeyEnc.keyGenISAG7()
    --
    print("========= ISAG7 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathISAG7);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= ISAG7 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathISAG7);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncISAG7()
    --
    local srcPath = keyPathISAG7 .. edKeyPemName;
    local seed = pwMariaISAG;
    local seedLen = string.len(seed);
    local dstPath = keyPathISAG7 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

--
function pwKeyEnc.keyGenFBN7()
    --
    print("========= FBN7 ED25519 Key Gen Pem =========");
    local retEdKeyGenPem = ed25519KeyGenPem(keyPathFBN7);
    print("retEdKeyGenPem : ", retEdKeyGenPem);
    
    print("========= FBN7 X25519 Key Gen Pem =========");
    local retXKeyGenPem = x25519KeyGenPem(keyPathFBN7);
    print("retXKeyGenPem : ", retXKeyGenPem);
end

function pwKeyEnc.keyEncFBN7()
    --
    local srcPath = keyPathFBN7 .. edKeyPemName;
    local seed = pwMariaFBN;
    local seedLen = string.len(seed);
    local dstPath = keyPathFBN7 .. edKeyFinName;

    print("seed : ", seed);
    print("seedLen : ", seedLen);

    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if(testEncFile == true) then 
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);
end

--
function pwKeyEnc.testCase()
    --
    pwKeyEnc.pwShard();
    pwKeyEnc.pwRepl();
    pwKeyEnc.pwReplIS();
    pwKeyEnc.pwReplNN();
    pwKeyEnc.pwReplISAG();
    --
    pwKeyEnc.pwRedis();
    pwKeyEnc.pwMariaIS();
    pwKeyEnc.pwMariaISAG();
    pwKeyEnc.pwMariaNN();
    pwKeyEnc.pwMariaFBN();
    
    --
    pwKeyEnc.keyGenIS();
    pwKeyEnc.keyEncIS();
    
    -- Cluster 1
    pwKeyEnc.keyGenNN1();
    pwKeyEnc.keyEncNN1();
    pwKeyEnc.keyGenISAG1();
    pwKeyEnc.keyEncISAG1();
    pwKeyEnc.keyGenFBN1();
    pwKeyEnc.keyEncFBN1();
    -- Cluster 2
    pwKeyEnc.keyGenNN2();
    pwKeyEnc.keyEncNN2();
    pwKeyEnc.keyGenISAG2();
    pwKeyEnc.keyEncISAG2();
    pwKeyEnc.keyGenFBN2();
    pwKeyEnc.keyEncFBN2();
    -- Cluster 3
    pwKeyEnc.keyGenNN3();
    pwKeyEnc.keyEncNN3();
    pwKeyEnc.keyGenISAG3();
    pwKeyEnc.keyEncISAG3();
    pwKeyEnc.keyGenFBN3();
    pwKeyEnc.keyEncFBN3();
    -- Cluster 4
    pwKeyEnc.keyGenNN4();
    pwKeyEnc.keyEncNN4();
    pwKeyEnc.keyGenISAG4();
    pwKeyEnc.keyEncISAG4();
    pwKeyEnc.keyGenFBN4();
    pwKeyEnc.keyEncFBN4();
    -- Cluster 5
    pwKeyEnc.keyGenNN5();
    pwKeyEnc.keyEncNN5();
    pwKeyEnc.keyGenISAG5();
    pwKeyEnc.keyEncISAG5();
    pwKeyEnc.keyGenFBN5();
    pwKeyEnc.keyEncFBN5();
    -- Cluster 6
    pwKeyEnc.keyGenNN6();
    pwKeyEnc.keyEncNN6();
    pwKeyEnc.keyGenISAG6();
    pwKeyEnc.keyEncISAG6();
    pwKeyEnc.keyGenFBN6();
    pwKeyEnc.keyEncFBN6();
    -- Cluster 7
    pwKeyEnc.keyGenNN7();
    pwKeyEnc.keyEncNN7();
    pwKeyEnc.keyGenISAG7();
    pwKeyEnc.keyEncISAG7();
    pwKeyEnc.keyGenFBN7();
    pwKeyEnc.keyEncFBN7();
end
