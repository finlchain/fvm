

//
module.exports.bytesToBuffer = (bytes) => {
    // var buff = Buffer.alloc(bytes.byteLength);
    var buff = Buffer.alloc(bytes.length);
    var view = new Uint8Array(bytes);
    
    for(var i = 0; i < buff.length; i++)
    {
        buff[i] = view[i];
    }
    return buff;
}