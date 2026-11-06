#include "himitsu/validation/auth_crypto.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <atomic>
#include <string_view>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace himitsu::validation::crypto {
std::array<unsigned char, 32> sha256(std::span<const unsigned char> input) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0;
    DWORD returned = 0;
    std::vector<unsigned char> object;
    std::array<unsigned char, 32> digest{};
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0
        || BCryptGetProperty(
            algorithm,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size),
            sizeof(object_size),
            &returned,
            0
        ) < 0) {
        if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
        throw std::runtime_error("SHA-256 provider initialization failed");
    }
    object.resize(object_size);
    bool success = BCryptCreateHash(
        algorithm,
        &hash,
        object.data(),
        object_size,
        nullptr,
        0,
        0
    ) >= 0;
    if (success && !input.empty()) {
        success = BCryptHashData(
            hash,
            const_cast<PUCHAR>(input.data()),
            static_cast<ULONG>(input.size()),
            0
        ) >= 0;
    }
    if (success) {
        success = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
    }
    if (hash != nullptr) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!success) throw std::runtime_error("SHA-256 operation failed");
    return digest;
}

std::string sha256_hex(std::span<const unsigned char> input) {
    const auto digest = sha256(input);
    std::string result;
    result.reserve(digest.size() * 2);
    char value[3]{};
    for (unsigned char byte : digest) {
        std::snprintf(value, sizeof(value), "%02x", byte);
        result.append(value);
    }
    return result;
}

std::string base64_encode(std::span<const unsigned char> input) {
    DWORD size = 0;
    if (!CryptBinaryToStringA(
            input.data(),
            static_cast<DWORD>(input.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            nullptr,
            &size
        )) {
        throw std::runtime_error("Base64 size calculation failed");
    }
    std::string result(size, '\0');
    if (!CryptBinaryToStringA(
            input.data(),
            static_cast<DWORD>(input.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            result.data(),
            &size
        )) {
        throw std::runtime_error("Base64 encoding failed");
    }
    if (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

std::vector<unsigned char> base64_decode(const std::string& input) {
    DWORD size = 0;
    if (!CryptStringToBinaryA(
            input.c_str(),
            static_cast<DWORD>(input.size()),
            CRYPT_STRING_BASE64,
            nullptr,
            &size,
            nullptr,
            nullptr
        )) {
        throw std::runtime_error("Invalid Base64 data");
    }
    std::vector<unsigned char> result(size);
    if (!CryptStringToBinaryA(
            input.c_str(),
            static_cast<DWORD>(input.size()),
            CRYPT_STRING_BASE64,
            result.data(),
            &size,
            nullptr,
            nullptr
        )) {
        throw std::runtime_error("Base64 decoding failed");
    }
    result.resize(size);
    return result;
}

std::string random_token(unsigned long size) {
    std::vector<unsigned char> bytes(size);
    if (BCryptGenRandom(nullptr, bytes.data(), size, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        throw std::runtime_error("Secure random generation failed");
    }
    return base64_encode(bytes);
}

bool constant_equals(
    std::span<const unsigned char> first,
    std::span<const unsigned char> second
) {
    if (first.size() != second.size()) return false;
    unsigned char difference = 0;
    for (std::size_t index = 0; index < first.size(); ++index) {
        difference |= first[index] ^ second[index];
    }
    return difference == 0;
}

std::vector<unsigned char> aes_gcm_decrypt(
    std::span<const unsigned char> key,
    std::span<const unsigned char> nonce,
    std::span<const unsigned char> ciphertext,
    std::span<const unsigned char> tag
) {
    BCRYPT_ALG_HANDLE aes = nullptr;
    BCRYPT_KEY_HANDLE key_handle = nullptr;
    DWORD object_size = 0;
    DWORD returned = 0;
    std::vector<unsigned char> key_object;
    std::vector<unsigned char> plaintext;
    bool ok = false;
    do {
        if (BCryptOpenAlgorithmProvider(&aes, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0
            || BCryptSetProperty(aes, BCRYPT_CHAINING_MODE,
                reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                static_cast<DWORD>(sizeof(BCRYPT_CHAIN_MODE_GCM)), 0) < 0
            || BCryptGetProperty(aes, BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &returned, 0) < 0) break;
        key_object.resize(object_size);
        if (BCryptGenerateSymmetricKey(aes, &key_handle, key_object.data(), object_size,
                const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0) < 0) break;
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth{};
        BCRYPT_INIT_AUTH_MODE_INFO(auth);
        auth.pbNonce = const_cast<PUCHAR>(nonce.data());
        auth.cbNonce = static_cast<ULONG>(nonce.size());
        auth.pbTag = const_cast<PUCHAR>(tag.data());
        auth.cbTag = static_cast<ULONG>(tag.size());
        plaintext.resize(ciphertext.size());
        ULONG written = 0;
        if (BCryptDecrypt(key_handle, const_cast<PUCHAR>(ciphertext.data()),
                static_cast<ULONG>(ciphertext.size()), &auth, nullptr, 0,
                plaintext.data(), static_cast<ULONG>(plaintext.size()), &written, 0) < 0) break;
        plaintext.resize(written);
        ok = true;
    } while (false);
    if (key_handle != nullptr) BCryptDestroyKey(key_handle);
    if (aes != nullptr) BCryptCloseAlgorithmProvider(aes, 0);
    if (!ok) throw std::runtime_error("AES-GCM decryption failed");
    return plaintext;
}

static std::vector<unsigned char> hmac_sha256_raw(
    std::span<const unsigned char> key_bytes,
    std::span<const unsigned char> data
) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD hash_size = 0;
    DWORD object_size = 0;
    DWORD returned = 0;
    std::vector<unsigned char> hash_object;
    std::array<unsigned char, 32> result{};
    bool ok = false;
    do {
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0) break;
        if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                reinterpret_cast<PUCHAR>(&hash_size), sizeof(hash_size), &returned, 0) < 0) break;
        if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &returned, 0) < 0) break;
        hash_object.resize(object_size);
        if (BCryptCreateHash(alg, &hash, hash_object.data(), object_size,
                const_cast<PUCHAR>(key_bytes.data()), static_cast<ULONG>(key_bytes.size()), 0) < 0) break;
        if (!data.empty() && BCryptHashData(hash, const_cast<PUCHAR>(data.data()),
                static_cast<ULONG>(data.size()), 0) < 0) break;
        if (BCryptFinishHash(hash, result.data(), hash_size, 0) < 0) break;
        ok = true;
    } while (false);
    if (hash != nullptr) BCryptDestroyHash(hash);
    if (alg != nullptr) BCryptCloseAlgorithmProvider(alg, 0);
    if (!ok) throw std::runtime_error("HMAC-SHA256 failed");
    return std::vector<unsigned char>(result.begin(), result.begin() + hash_size);
}

std::array<unsigned char, 32> hkdf_sha256(
    std::span<const unsigned char> salt,
    std::span<const unsigned char> info,
    unsigned long output_length
) {
    std::vector<unsigned char> initial_salt(salt.data(), salt.data() + salt.size());
    if (initial_salt.empty()) initial_salt.resize(32, 0);
    auto prk = hmac_sha256_raw(initial_salt, {});
    std::vector<unsigned char> okm;
    for (unsigned char c = 1; okm.size() < output_length; ++c) {
        std::vector<unsigned char> round_data(okm);
        round_data.insert(round_data.end(), info.begin(), info.end());
        round_data.push_back(c);
        auto t_block = hmac_sha256_raw(prk, round_data);
        okm.insert(okm.end(), t_block.begin(),
            t_block.begin() + (std::min)(static_cast<std::size_t>(32),
                output_length - okm.size()));
    }
    std::array<unsigned char, 32> result{};
    std::memcpy(result.data(), okm.data(), (std::min)(okm.size(), static_cast<std::size_t>(32)));
    return result;
}
}

namespace himitsu::validation::crypto {
namespace {
void wipe_saved(std::string& value) {if(!value.empty()) SecureZeroMemory(value.data(),value.size());value.clear();}
std::string token_blob(const std::string& username,const std::string& value,bool protect) {
    if(value.empty() || value.size()>32768) return {};
    std::vector<unsigned char> input;
    try {if(!protect) input=base64_decode(value);}
    catch(...) {return {};}
    std::string purpose="Secret.Refresh.v1:"+username;
    DATA_BLOB source{static_cast<DWORD>(protect?value.size():input.size()),
        protect?reinterpret_cast<BYTE*>(const_cast<char*>(value.data())):input.data()};
    DATA_BLOB entropy{static_cast<DWORD>(purpose.size()),reinterpret_cast<BYTE*>(purpose.data())},result{};
    BOOL ok=protect?CryptProtectData(&source,L"Secret remembered login",&entropy,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&result)
        :CryptUnprotectData(&source,nullptr,&entropy,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&result);
    if(!ok) return {};
    std::string output;
    try {
        if(protect) output=base64_encode({result.pbData,result.cbData});
        else if(result.cbData<=8192) output.assign(reinterpret_cast<char*>(result.pbData),result.cbData);
    } catch(...) {SecureZeroMemory(result.pbData,result.cbData);LocalFree(result.pbData);throw;}
    SecureZeroMemory(result.pbData,result.cbData);LocalFree(result.pbData);
    if(output.find('\0')!=std::string::npos) wipe_saved(output);
    return output;
}
std::string_view trim_saved(std::string_view value) {
    auto first=value.find_first_not_of(" \t\r\n");if(first==std::string_view::npos)return {};
    return value.substr(first,value.find_last_not_of(" \t\r\n")-first+1);
}
}
std::wstring credentials_path() {
    std::array<wchar_t,32768> profile{};
    DWORD size=GetEnvironmentVariableW(L"USERPROFILE",profile.data(),static_cast<DWORD>(profile.size()));
    if(!size || size>=profile.size()) return {};
    return std::wstring(profile.data(),size)+L"\\Secret.ini";
}
static bool write_credentials(const std::wstring& path,const std::string& username,const std::string& token,bool remember) {
    if(path.empty() || username.size()>159 || username.find_first_of("\r\n")!=std::string::npos
        || username.find('\0')!=std::string::npos || token.size()>8192) return false;
    const bool keep=remember && !username.empty() && !token.empty();
    std::string encoded;
    try {if(keep) encoded=token_blob(username,token,true);}catch(...) {return false;}
    if(keep && encoded.empty()) return false; // No plaintext fallback.
    std::string contents=std::string("[info]\r\nRemember = ")+(keep?"true":"false")
        +"\r\nusername = "+(keep?username:std::string{})
        +"\r\nrefresh_token = "+(keep?"dpapi:"+encoded:std::string{})+"\r\n";
    static std::atomic<unsigned long> serial{0};
    std::wstring temporary=path+L".tmp-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(++serial);
    HANDLE file=CreateFileW(temporary.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE) return false;
    DWORD written=0;
    bool ok=WriteFile(file,contents.data(),static_cast<DWORD>(contents.size()),&written,nullptr)
        && written==contents.size() && FlushFileBuffers(file);
    CloseHandle(file);
    if(ok) ok=MoveFileExW(temporary.c_str(),path.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)!=FALSE;
    if(!ok) DeleteFileW(temporary.c_str());
    return ok;
}
static HANDLE lock_credentials(const std::wstring& path) {
    if(path.empty()) return INVALID_HANDLE_VALUE;
    return CreateFileW((path+L".lock").c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN|FILE_FLAG_DELETE_ON_CLOSE,nullptr);
}
bool save_credentials(const std::wstring& path,const std::string& username,const std::string& token,bool remember) {
    HANDLE guard=lock_credentials(path);if(guard==INVALID_HANDLE_VALUE)return false;
    bool saved=false;
    try {saved=write_credentials(path,username,token,remember);}catch(...) {}
    CloseHandle(guard);return saved;
}
backend::Request load_credentials(const std::wstring& path,bool migrate) {
    backend::Request request{};if(path.empty()) return request;
    HANDLE file=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE) return request;
    LARGE_INTEGER size{};
    if(!GetFileSizeEx(file,&size) || size.QuadPart<=0 || size.QuadPart>65536){CloseHandle(file);return request;}
    std::string contents(static_cast<std::size_t>(size.QuadPart),'\0');DWORD count=0;
    bool read=ReadFile(file,contents.data(),static_cast<DWORD>(contents.size()),&count,nullptr)!=FALSE;CloseHandle(file);
    if(!read){wipe_saved(contents);return request;}contents.resize(count);
    bool info=false,remember=false,legacy=false;std::string encrypted;
    std::string_view text(contents);
    while(!text.empty()) {
        auto newline=text.find('\n');auto line=trim_saved(text.substr(0,newline));
        if(newline==std::string_view::npos) text={};else text.remove_prefix(newline+1);
        if(line.empty() || line.front()==';' || line.front()=='#') continue;
        if(line.front()=='[' && line.back()==']'){info=trim_saved(line.substr(1,line.size()-2))=="info";continue;}
        if(!info)continue;auto separator=line.find('=');if(separator==std::string_view::npos)continue;
        auto key=trim_saved(line.substr(0,separator));
        if(key=="password"){legacy=true;continue;} // Never populate or reuse a saved password.
        auto value=trim_saved(line.substr(separator+1));
        if(key=="Remember")remember=value=="true"||value=="TRUE"||value=="1";
        else if(key=="username" && value.size()<=159)request.username=value;
        else if(key=="refresh_token" && value.size()<=32768)encrypted=value;
    }
    if(remember && !request.username.empty() && encrypted.rfind("dpapi:",0)==0)
        request.refresh_token=token_blob(request.username,encrypted.substr(6),false);
    request.remember_me=!request.refresh_token.empty();
    wipe_saved(contents);
    if(legacy && migrate && !save_credentials(path,request.username,request.refresh_token,request.remember_me)) {
        wipe_saved(request.refresh_token);throw std::runtime_error("Cannot remove legacy plaintext credentials");
    }
    return request;
}
bool rotate_credentials(const std::wstring& path,const std::string& username,const std::string& previous,const std::string& next) {
    HANDLE guard=lock_credentials(path);if(guard==INVALID_HANDLE_VALUE)return false;
    bool saved=false;
    try {
        auto current=load_credentials(path,false);
        bool match=current.remember_me && current.username==username && current.refresh_token==previous;
        wipe_saved(current.refresh_token);
        saved=match && write_credentials(path,username,next,true);
    } catch(...) {}
    CloseHandle(guard);return saved;
}
}
