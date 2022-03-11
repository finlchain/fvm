// Using command

// 0. tool install
//    Refer to : https://m.blog.naver.com/remocon33/221580633458
//    npm install -g yarn
//    yarn global add windows-build-tools // in case windows base
//    npm install -g node-gyp
//    npm install --save bindings

// in ./binding.gyp
//    configure : "target_name": "crypto-finl",

// 
// 1. node-gyp clean
// 2. node-gyp configure
// 3. node-gyp build
// 4. node-gyp rebuild
// 4.1 node-gyp rebuild (release : default)
// 4.2 node-gyp rebuild --debug (option)
// 5. require("./build/Release/aes-finl");
// 6. Now Using
