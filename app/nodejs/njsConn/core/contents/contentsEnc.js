//
const fs = require('fs');

//
module.exports.makeEncJsonMsg = (encMsg, encXPubkey, myXPubkey, encJsonFilePath) => {
    //
    let contentsEncJson = {
        jsonEnc : {
            contentsEnc : encMsg, 
            encXPubkey : encXPubkey,
            myXPubkey : myXPubkey
        }
    };

    let encJsonMsg = JSON.stringify(contentsEncJson);
    // console.log("encJsonMsg.length : " + encJsonMsg.length);
    // console.log("encJsonMsg : " + encJsonMsg);

    if (typeof encJsonFilePath !== 'undefined')
    {
        fs.writeFileSync(encJsonFilePath, encJsonMsg, 'binary');
    }

    return encJsonMsg;
}
