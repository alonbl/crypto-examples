#include <iostream>
#include <map>
#include <string>

#include "EncryptUtil.h"

int main() {

    EncryptUtil_process_init();

    try {
        auto plaintext = "long long long long long secret 1234";
        auto keyid = "1";
        auto key = "zCfT2/7poKMiGffo01qByQ==";
        auto envelope = "$ENC$|0|AES/CBC/PKCS5Padding|1|hBDLzX/rRKeSQfR3dtfdsQ==|VbjTH8Gi2xFnseakdHAUx5GDaA+gJ+Zc2CvLIafAdRKSRgy5CBP8KXXWKfB9BAGHDCyZz6jX3f84ESEbEwKvb9nuQti77pbWgi+DoCcKqmA=";

        std::map<std::string, std::string> keys;
        keys[keyid] = key;

        auto plaintext1 = EncryptUtil_decrypt(keys, envelope);

        std::cout << "plaintext='" << plaintext1 << "', ok=" << (plaintext1 == plaintext) << std::endl;
    }
    catch (std::exception &e) {
        std::cout << e.what() << std::endl;
    }

    EncryptUtil_process_terminate();

    return 0;
}
