#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <sodium.h>

namespace cryptofuzz {
namespace module {

libsodium::libsodium(void) :
    Module("libsodium") {
    if ( sodium_init() == -1 ) {
        abort();
    }
}

std::optional<component::Digest> libsodium::SHA256(operation::Digest& op) const {
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t out[crypto_hash_sha256_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        crypto_hash_sha256(out, op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_sha256_BYTES);
    } else {
        crypto_hash_sha256_state state;

        util::Multipart parts;

        /* Initialize */
        {
            CF_CHECK_EQ(crypto_hash_sha256_init(&state), 0);
            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            CF_CHECK_EQ(crypto_hash_sha256_update(&state, part.first, part.second), 0);
        }

        /* Finalize */
        {
            CF_CHECK_EQ(crypto_hash_sha256_final(&state, out), 0);
        }

        ret = component::Digest(out, crypto_hash_sha256_BYTES);
    }

end:

    return ret;
}

std::optional<component::Digest> libsodium::OpDigest(operation::Digest& op) {
    switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA256"):
            return SHA256(op);
        default:
            return std::nullopt;
    }
}

} /* namespace module */
} /* namespace cryptofuzz */
