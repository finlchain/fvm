
print('test.tCurl');

tCurl = {
    --
};

function tCurl.testHttpGet()
    local ret;
    -- ret = curlHttpGet("https://example.com", "dummy");
    ret = curlHttpGet("http://purichain.com:4000/block/blkcnt", "dummy");
    print("ret : ", ret);
    ret = curlHttpGet("https://api.coingecko.com/api/v3/simple/price?ids=puriever&vs_currencies=usd", "dummy");
    print("ret : ", ret);
end

function tCurl.testCase()
    --
    tCurl.testHttpGet();
end
