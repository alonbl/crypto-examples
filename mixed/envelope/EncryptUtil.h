#ifndef __ENCRYPT_UTIL_H
#define __ENCRYPT_UTIL_H

void EncryptUtil_process_init();

void EncryptUtil_process_terminate();

std::string EncryptUtil_decrypt(
    const std::map<std::string, std::string> &keys,
    const std::string &envelope
);

#endif
