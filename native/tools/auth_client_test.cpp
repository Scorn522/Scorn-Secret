#include "himitsu/validation/auth_client.hpp"
#include "himitsu/validation/device_identity.hpp"

#include <iostream>
#include <string>

int main(int argc, char** argv) {
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
