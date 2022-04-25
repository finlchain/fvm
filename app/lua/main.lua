
require 'luaConn.init'

--
require 'test.tCallback'
require 'test.tCoroutine'
require 'test.tTimer'

require 'test.tCurl'
require 'test.tHttp'

require 'test.tLoadScript'
require 'test.tSec'
require 'test.tGetKey'
require 'test.tDsa'

-- 
require 'test.keyGen'
require 'test.pwKeyEncDec'
require 'test.pwKeyEnc'

--
require 'test.contentAddUser'
require 'test.contentChangeUserPubkey'
require 'test.contentCreateToken'
require 'test.contentChangeTokenPubkey'
require 'test.contentChangeTokenLockTx'
require 'test.contentChangeTokenLockTime'
require 'test.contentChangeTokenLockWallet'

--
require 'test.contractAddUser'
require 'test.contractCreateToken'
require 'test.contractTxSecToken'
require 'test.contractTxUtilToken'
require 'test.contractCreateSc'
require 'test.contractTxSc'

--
function luaTest()
    dataStr, count = luaRegOutTest();
    luaRegInTest(dataStr, count);

    hastStr = genSha256Str(dataStr);
    print("hastStr : ", hastStr);

    -- eddsaTest();
    -- x25519Test();
    -- aesTest();
    -- ariaTest();
end

function luaConn(myTbl)
    -- luaTest();

    -- -- 
    -- tLoadScript.exeFuncFromTbl(myTbl);
    -- tLoadScript.testCase();

    -- --
    -- tCoroutine.testCase();
    -- tCallback.testCase();
    -- tTimer.testCase();
    -- tCurl.testCase();
    -- tSec.testCase();
    -- tHttp.testCase();
    -- tGetKey.testCase();
    -- tDsa.testCase();

    -- 
    -- keyGen.testCase();
    -- pwKeyEncDec.testCase();
    -- pwKeyEnc.testCase();

    --
    contentAddUser.testCase();
    contentChangeUserPubkey.testCase();
    contentCreateToken.testCase();
    contentChangeTokenPubkey.testCase();
    contentChangeTokenLockTx.testCase();
    contentChangeTokenLockTime.testCase();
    contentChangeTokenLockWallet.testCase();

    contractAddUser.testCase();
    contractCreateToken.testCase();
    contractTxSecToken.testCase();
    contractTxUtilToken.testCase();
    contractCreateSc.testCase();
    contractTxSc.testCase();

    return "success";
end
