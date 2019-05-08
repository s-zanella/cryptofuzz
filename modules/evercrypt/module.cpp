#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>

extern "C" {
#include <EverCrypt.h>
}

#define crypto_hash_sha256_BYTES 32

namespace cryptofuzz {
namespace module {

EverCrypt::EverCrypt(void) :
    Module("EverCrypt") { }

std::optional<component::Digest> EverCrypt::SHA256(operation::Digest& op) const {
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t out[crypto_hash_sha256_BYTES];

    EverCrypt_Hash_hash(Spec_Hash_Definitions_SHA2_256, out, (uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize());

    ret = component::Digest(out, crypto_hash_sha256_BYTES);

    return ret;
}

std::optional<component::Digest> EverCrypt::OpDigest(operation::Digest& op) {
    switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA256"):
            return SHA256(op);
        default:
            return std::nullopt;
    }
}

} /* namespace module */
} /* namespace cryptofuzz */
