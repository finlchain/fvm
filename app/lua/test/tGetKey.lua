
print('test.tGetKey');

tGetKey = {
    --
};

function tGetKey.testGetKey()
    local testKeyPath = './../keyStore.json';
    local testKey = _commonUtil.readBinaryFile(testKeyPath);
    print("testKey : ", testKey);

    --
    local testKeyJson = json.parse(testKey);
    -- _commonUtil.prtTable(testKeyJson['edPubkeyPem']);
    --
    local ed_pubkey = ed25519GetPubkeyNoFile(testKeyJson['edPubkeyPem']);
    print("ed_pubkey : ", ed_pubkey);
end

function tGetKey.testCase()
    --
    tGetKey.testGetKey();
end
