#include "himitsu/validation/auth_client.hpp"
#include "himitsu/validation/device_identity.hpp"
#include "himitsu/validation/auth_crypto.hpp"
#include <filesystem>
#include <windows.h>
#include <fstream>
#include <stdexcept>

#include <iostream>
#include <string>

static void require(bool value,const char* message) {if(!value)throw std::runtime_error(message);}
static int credential_checks(const std::filesystem::path& directory) {
    using namespace himitsu::validation::crypto;
    std::filesystem::create_directories(directory);
    auto file=directory/"fixture.ini";auto path=file.wstring();
    const std::string user="fixture-user",first="synthetic-refresh-A-not-an-account",second="synthetic-refresh-B-not-an-account";
    require(save_credentials(path,user,first,true),"DPAPI save failed");
    auto saved=load_credentials(path);
    require(saved.remember_me && saved.username==user && saved.password.empty() && saved.refresh_token==first,"DPAPI round trip failed");
    auto read=[&] {std::ifstream in(file,std::ios::binary);return std::string(std::istreambuf_iterator<char>(in),{});};
    auto text=read();require(text.find(first)==std::string::npos && text.find("password")==std::string::npos && text.find("dpapi:")!=std::string::npos,"plaintext persisted");
    require(rotate_credentials(path,user,first,second),"rotation failed");
    require(!rotate_credentials(path,user,first,"stale"),"stale rotation overwrote a newer login");
    require(load_credentials(path).refresh_token==second,"rotated token was lost");
    {std::ofstream out(file,std::ios::binary);out<<"[info]\r\nRemember = true\r\nusername = fixture-user\r\npassword = synthetic-legacy-password\r\n";}
    saved=load_credentials(path);require(saved.password.empty() && saved.refresh_token.empty() && !saved.remember_me,"legacy password reused");
    require(read().find("synthetic-legacy-password")==std::string::npos && read().find("password")==std::string::npos,"legacy password not removed");
    require(save_credentials(path,user,first,true),"second save failed");text=read();
    auto name=text.find(user);text.replace(name,user.size(),"different-user");
    {std::ofstream out(file,std::ios::binary);out<<text;}
    require(load_credentials(path).refresh_token.empty(),"username-bound DPAPI accepted another account");
    require(save_credentials(path,user,first,true),"third save failed");text=read();
    auto blob=text.find("dpapi:")+6;auto end=text.find("\r\n",blob);
    auto binary=base64_decode(text.substr(blob,end-blob));require(!binary.empty(),"missing DPAPI bytes");
    binary.back()^=1;text.replace(blob,end-blob,base64_encode(binary));
    {std::ofstream out(file,std::ios::binary);out<<text;}
    require(load_credentials(path).refresh_token.empty(),"damaged DPAPI authentication data accepted");
    require(save_credentials(path,user,first,true),"lock fixture save failed");
    HANDLE held=CreateFileW((path+L".lock").c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_ALWAYS,FILE_FLAG_DELETE_ON_CLOSE,nullptr);
    require(held!=INVALID_HANDLE_VALUE,"lock fixture missing");
    bool blocked=!save_credentials(path,{}, {},false) && !rotate_credentials(path,user,first,second);
    CloseHandle(held);require(blocked && load_credentials(path).refresh_token==first,"concurrent writer bypassed credential lock");
    require(save_credentials(path,{}, {},false),"forget failed");
    require(!rotate_credentials(path,user,first,second) && !load_credentials(path).remember_me,"late refresh resurrected forgotten credentials");
    std::cout<<"CREDENTIAL_STORAGE_PASS user_dpapi no_plaintext legacy_retired rotation_account_binding corrupt_blob_forget concurrent_writer_lock NO_NETWORK_NO_REAL_CREDENTIALS\n";
    return 0;
}

int main(int argc, char** argv) {
    if(argc==3 && std::string(argv[1])=="--credentials-check") {
        try {return credential_checks(std::filesystem::path(argv[2]));}
        catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
    }
    if (argc != 3) {
        std::cerr << "usage: himitsu_auth_test USER PASSWORD\n";
        return 2;
    }
    try {
        const auto identity = himitsu::validation::DeviceIdentity::load();
        const himitsu::validation::backend::Request password_request{
            argv[1], argv[2], true, {}
        };
        const auto first = himitsu::validation::authenticate_remote(password_request, identity);
        std::cout << "password_login=" << static_cast<int>(first.decision)
                  << " message=" << first.message << '\n';
        if (first.decision != himitsu::validation::backend::Decision::approved
            || first.refresh_token.empty()) {
            return 1;
        }

        const himitsu::validation::backend::Request refresh_request{
            argv[1], {}, true, first.refresh_token
        };
        const auto second = himitsu::validation::authenticate_remote(refresh_request, identity);
        std::cout << "refresh_login=" << static_cast<int>(second.decision)
                  << " message=" << second.message << '\n';
        if (second.decision != himitsu::validation::backend::Decision::approved
            || second.refresh_token.empty()) {
            return 1;
        }

        const auto replay = himitsu::validation::authenticate_remote(refresh_request, identity);
        std::cout << "old_token_replay=" << static_cast<int>(replay.decision)
                  << " message=" << replay.message << '\n';
        const himitsu::validation::backend::Request rotated_request{
            argv[1], {}, true, second.refresh_token
        };
        const auto rotated = himitsu::validation::authenticate_remote(rotated_request, identity);
        std::cout << "rotated_token=" << static_cast<int>(rotated.decision)
                  << " message=" << rotated.message << '\n';
        return replay.decision == himitsu::validation::backend::Decision::rejected
            && rotated.decision == himitsu::validation::backend::Decision::approved ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "error=" << error.what() << '\n';
        return 1;
    }
}
