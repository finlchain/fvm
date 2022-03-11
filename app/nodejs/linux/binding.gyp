{
    "targets" : [
        {
            "target_name": "crypto-ssl",
            "sources": 
            [
                "./../addon.cpp", 
                "./../../../src/utils/cpp_if.cpp", 
                "./../../../src/utils/debug.cpp", 
                "./../../../src/utils/util.cpp", 
                "./../../../src/sec/aes.cpp", 
                "./../../../src/sec/aes_test.cpp", 
                "./../../../src/sec/aria.cpp", 
                "./../../../src/sec/key.cpp", 
                "./../../../src/sec/sec_proc.cpp", 
                "./../../../src/curl/curl_http.cpp", 
                "./../../../src/openssl/openssl_util.cpp", 
                "./../../../src/openssl/openssl_aes.cpp", 
                "./../../../src/openssl/openssl_ec.cpp", 
                "./../../../src/openssl/openssl_ecdsa.cpp", 
                "./../../../src/openssl/openssl_ed.cpp", 
                "./../../../src/openssl/openssl_eddsa.cpp", 
                "./../../../src/openssl/openssl_x25519.cpp", 
                "./../../../src/lua/lua_conn.cpp",
            ],
            "include_dirs": 
            [
                "./../../../inc", 
                "./../../../inc/utils", 
                "./../../../inc/curl",
                "./../../../inc/openssl", 
                "./../../../inc/sec", 
                "./../../../inc/lua", 
                "./../../../../../usr/inc", 
                "./../../../../../usr/inc/libcrypto/openssl", 
                "./../../../../../usr/inc/liblua/lua5.2",
                "./../../../../../usr/inc/libcurl/curl7.79.1",
                "./../../../../../usr/inc/libutf8",
            ],
            "libraries": 
            [
                "-ldl", 
                "-lm", 
                "/home/finl/finlchain/usr/lib/libcrypto/openssl_111b/libcrypto.so", 
                "/home/finl/finlchain/usr/lib/liblua/lua5.2/liblua.so", 
                "/home/finl/finlchain/usr/lib/libcurl/curl7.79.1/libcurl.so", 
                "/home/finl/finlchain/usr/lib/libutf8/libutf8proc.so", 
            ],
            "cflags!": ["-fno-exceptions"],
            "cflags": [ "-std=c++11",  "-Wall", "-Werror", "-fstack-protector-all" ],
            "cflags_cc!" : ["-fno-exceptions"],
            "cflags_cc": [ "-std=c++11",  "-Wall", "-Werror", "-fstack-protector-all" ],
        }
    ]
}
