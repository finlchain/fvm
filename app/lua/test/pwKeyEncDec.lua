print('test.pwKeyEncDec')

pwKeyEncDec = {
    --
};

--
local seedPath = "./../../../../conf/seed";

--
local pwShard = "+purishard135@$";
local pwRepl = "+purirepl@$135";
local pwReplNN = "+purirpnn@$135";
local pwReplISAG = "+purirpisag@$135";
local pwRedis = "pure+pwd";
local pwMariaIS = "puriis+Pwd@1";
local pwMariaISAG = "puriisag+Pwd@1";
local pwMariaNN = "purinn+Pwd@1";
local pwMariaFBN = "purifbn+Pwd@1";

function pwKeyEncDec.pwShard()
    print("========= Shard PW Enc =========");
    local pw = pwShard;
    local pwLen = string.len(pw);
    local pwPath = "./out/puri/pw/pw_shard.fin";
    
    -- ** Encrypt Passwd
    -- *** return true : success, false : fail
    local testEncPw = aesEncPw(seedPath, pw, pwLen, pwPath);
    if (testEncPw == true) then
        print("success");
    else 
        printg("fail");
    end
    
    -- ** Decrypt Passwd
    -- *** return passwd
    local testDecPw = aesDecPw(seedPath, pwPath);
    print(testDecPw);
end

function pwKeyEncDec.pwRepl()
    print("========= Replication PW Enc =========");
    local pw = pwRepl;
    local pwLen = string.len(pw);
    local pwPath = "./out/puri/pw/pw_repl.fin";
    
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

function pwKeyEncDec.pwReplNN()
    print("========= Replication NN PW Enc =========");
    local pw = pwReplNN;
    local pwLen = string.len(pw);
    local pwPath = "./out/puri/pw/pw_nn.fin";
    
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

function pwKeyEncDec.pwReplISAG()
    print("========= Replication ISAG PW Enc =========");
    local pw = pwReplISAG;
    local pwLen = string.len(pw);
    local pwPath = "./out/puri/pw/pw_isag.fin";
    
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

function pwKeyEncDec.pwRedis()
    print("========= Redis PW Enc =========");
    local pw = pwRedis;
    local pwLen = string.len(pw);
    local pwPath = "./out/puri/pw/pw_redis.fin";
    
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

function pwKeyEncDec.pwMariaIS()
    print("========= IS Maria PW Enc =========");
    local pw = pwMariaIS;
    local pwLen = string.len(pw);
    local pwPath = "./out/puri/pw/pw_maria_is.fin";
    
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

function pwKeyEncDec.pwMariaISAG()
    print("========= ISAG Maria PW Enc =========");
    local pw = pwMariaISAG;
    local pwLen = string.len(pw);
    local pwPath = "./out/puri/pw/pw_maria_isag.fin";
    
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

function pwKeyEncDec.pwMariaNN()
    print("========= NN Maria PW Enc =========");
    local pw = pwMariaNN;
    local pwLen = string.len(pw);
    local pwPath = "./out/puri/pw/pw_maria_nn.fin";
    
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

function pwKeyEncDec.pwMariaFBN()
    print("========= FBN Maria PW Enc =========");
    local pw = pwMariaFBN;
    local pwLen = string.len(pw);
    local pwPath = "./out/puri/pw/pw_maria_fbn.fin";
    
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

function pwKeyEncDec.keyIS()
    local srcPath = "./../../../../conf/puri/is/key/me/ed_privkey.pem";
    local seed = pwMariaIS;
    local seedLen = string.len(seed);
    local dstPath = "./../../../../conf/puri/is/key/me/ed_privkey.fin";

    print("seed : ", seed);
    print("seedLen : ", seedLen);
    
    local testEncFile = aesEncFile(srcPath, dstPath, seed, seedLen);
    if (testEncFile == true) then
        print("success");
    else
        print("fail");
    end
    
    local testDecFile = aesDecFile(dstPath, seed, seedLen);
    print(testDecFile);

    print("testDecFileLen : ", string.len(testDecFile));
end

function pwKeyEncDec.keyISDec()
    local srcPath = "./../../../../conf/puri_is/key/me/ed_privkey.fin";
    local seed = pwMariaIS;
    local seedLen = string.len(seed);
    local dstPath = "./../../../../conf/puri_is/key/me/ed_privkey.pem";

    print("seed : ", seed);
    print("seedLen : ", seedLen);
    
    local testDecFile = aesDecFile(srcPath, seed, seedLen);
    print(testDecFile);

    print("testDecFileLen : ", string.len(testDecFile));

    -- _commonUtil.writeBinaryFile(dstPath, testDecFile);
end

function pwKeyEncDec.testCase()
    -- pwKeyEncDec.pwShard();
    -- pwKeyEncDec.pwRepl();
    -- pwKeyEncDec.pwReplNN();
    -- pwKeyEncDec.pwReplISAG();
    -- pwKeyEncDec.pwRedis();
    -- pwKeyEncDec.pwMariaIS();
    -- pwKeyEncDec.pwMariaISAG();
    -- pwKeyEncDec.pwMariaNN();
    -- pwKeyEncDec.pwMariaFBN();

    -- pwKeyEncDec.keyIS();
    pwKeyEncDec.keyISDec();
end
