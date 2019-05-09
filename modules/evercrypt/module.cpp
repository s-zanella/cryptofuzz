#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>

extern "C" {
#include <EverCrypt.h>
}

#define crypto_hash_sha256_BYTES 32
#define crypto_hash_sha512_BYTES 64

namespace cryptofuzz {
namespace module {

EverCrypt::EverCrypt(void) :
    Module("EverCrypt") { }

std::optional<component::Digest> EverCrypt::SHA256(operation::Digest& op) const {
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t out[crypto_hash_sha256_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        EverCrypt_Hash_hash(Spec_Hash_Definitions_SHA2_256, out, (uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_sha256_BYTES);
    } else {
        EverCrypt_Hash_Incremental_state st;

        util::Multipart parts;

	/* Initialize */
        {
            st = EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_SHA2_256);
            parts = util::ToParts(ds, op.cleartext);
        }

	/* Process */
        for (const auto& part : parts) {
            st = EverCrypt_Hash_Incremental_update(Spec_Hash_Definitions_SHA2_256, st, (uint8_t*)part.first, part.second);
        }

	/* Finalize */
        {
            EverCrypt_Hash_Incremental_finish(Spec_Hash_Definitions_SHA2_256, st, out);
	    EverCrypt_Hash_free(st.hash_state);
	    free(st.buf);
        }

        ret = component::Digest(out, crypto_hash_sha256_BYTES);
    }

    return ret;
}

std::optional<component::Digest> EverCrypt::SHA512(operation::Digest& op) const {
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t out[crypto_hash_sha512_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        EverCrypt_Hash_hash(Spec_Hash_Definitions_SHA2_512, out, (uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_sha512_BYTES);
    } else {
        EverCrypt_Hash_Incremental_state st;

        util::Multipart parts;

	/* Initialize */
        {
            st = EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_SHA2_512);
            parts = util::ToParts(ds, op.cleartext);
        }

	/* Process */
        for (const auto& part : parts) {
            st = EverCrypt_Hash_Incremental_update(Spec_Hash_Definitions_SHA2_512, st, (uint8_t*)part.first, part.second);
        }

	/* Finalize */
        {
            EverCrypt_Hash_Incremental_finish(Spec_Hash_Definitions_SHA2_512, st, out);
	    EverCrypt_Hash_free(st.hash_state);
	    free(st.buf);
        }

        ret = component::Digest(out, crypto_hash_sha512_BYTES);
    }

    return ret;
}

std::optional<component::Digest> EverCrypt::OpDigest(operation::Digest& op) {
    switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA256"):
            return SHA256(op);
        case CF_DIGEST("SHA512"):
            return SHA512(op);
        default:
            return std::nullopt;
    }
}

} /* namespace module */
} /* namespace cryptofuzz */
