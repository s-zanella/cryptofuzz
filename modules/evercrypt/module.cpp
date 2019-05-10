#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>

#define crypto_hash_md5_BYTES    16
#define crypto_hash_sha1_BYTES   20
#define crypto_hash_sha224_BYTES 28
#define crypto_hash_sha256_BYTES 32
#define crypto_hash_sha384_BYTES 48
#define crypto_hash_sha512_BYTES 64

#define crypto_auth_hmacsha1_BYTES   20
#define crypto_auth_hmacsha256_BYTES 32
#define crypto_auth_hmacsha384_BYTES 48
#define crypto_auth_hmacsha512_BYTES 64

namespace cryptofuzz {
namespace module {

EverCrypt::EverCrypt(void) :
    Module("EverCrypt") { }

std::optional<component::Digest> EverCrypt::MD5(operation::Digest& op) const {
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t out[crypto_hash_md5_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        EverCrypt_Hash_hash(Spec_Hash_Definitions_MD5, out, (uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_md5_BYTES);
    } else {
        EverCrypt_Hash_Incremental_state st;

        util::Multipart parts;

	/* Initialize */
        {
            st = EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_MD5);
            parts = util::ToParts(ds, op.cleartext);
        }

	/* Process */
        for (const auto& part : parts) {
            st = EverCrypt_Hash_Incremental_update(Spec_Hash_Definitions_MD5, st, (uint8_t*)part.first, part.second);
        }

	/* Finalize */
        {
            EverCrypt_Hash_Incremental_finish(Spec_Hash_Definitions_MD5, st, out);
	    EverCrypt_Hash_free(st.hash_state);
	    free(st.buf);
        }

        ret = component::Digest(out, crypto_hash_md5_BYTES);
    }

    return ret;
}

std::optional<component::Digest> EverCrypt::SHA1(operation::Digest& op) const {
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t out[crypto_hash_sha1_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        EverCrypt_Hash_hash(Spec_Hash_Definitions_SHA1, out, (uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_sha1_BYTES);
    } else {
        EverCrypt_Hash_Incremental_state st;

        util::Multipart parts;

	/* Initialize */
        {
            st = EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_SHA1);
            parts = util::ToParts(ds, op.cleartext);
        }

	/* Process */
        for (const auto& part : parts) {
            st = EverCrypt_Hash_Incremental_update(Spec_Hash_Definitions_SHA1, st, (uint8_t*)part.first, part.second);
        }

	/* Finalize */
        {
            EverCrypt_Hash_Incremental_finish(Spec_Hash_Definitions_SHA1, st, out);
	    EverCrypt_Hash_free(st.hash_state);
	    free(st.buf);
        }

        ret = component::Digest(out, crypto_hash_sha1_BYTES);
    }

    return ret;
}

std::optional<component::Digest> EverCrypt::SHA224(operation::Digest& op) const {
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t out[crypto_hash_sha224_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        EverCrypt_Hash_hash(Spec_Hash_Definitions_SHA2_224, out, (uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_sha224_BYTES);
    } else {
        EverCrypt_Hash_Incremental_state st;

        util::Multipart parts;

	/* Initialize */
        {
            st = EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_SHA2_224);
            parts = util::ToParts(ds, op.cleartext);
        }

	/* Process */
        for (const auto& part : parts) {
            st = EverCrypt_Hash_Incremental_update(Spec_Hash_Definitions_SHA2_224, st, (uint8_t*)part.first, part.second);
        }

	/* Finalize */
        {
            EverCrypt_Hash_Incremental_finish(Spec_Hash_Definitions_SHA2_224, st, out);
	    EverCrypt_Hash_free(st.hash_state);
	    free(st.buf);
        }

        ret = component::Digest(out, crypto_hash_sha224_BYTES);
    }

    return ret;
}

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

std::optional<component::Digest> EverCrypt::SHA384(operation::Digest& op) const {
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t out[crypto_hash_sha384_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        EverCrypt_Hash_hash(Spec_Hash_Definitions_SHA2_384, out, (uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_sha384_BYTES);
    } else {
        EverCrypt_Hash_Incremental_state st;

        util::Multipart parts;

	/* Initialize */
        {
            st = EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_SHA2_384);
            parts = util::ToParts(ds, op.cleartext);
        }

	/* Process */
        for (const auto& part : parts) {
            st = EverCrypt_Hash_Incremental_update(Spec_Hash_Definitions_SHA2_384, st, (uint8_t*)part.first, part.second);
        }

	/* Finalize */
        {
            EverCrypt_Hash_Incremental_finish(Spec_Hash_Definitions_SHA2_384, st, out);
	    EverCrypt_Hash_free(st.hash_state);
	    free(st.buf);
        }

        ret = component::Digest(out, crypto_hash_sha384_BYTES);
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
        case CF_DIGEST("MD5"):
            return MD5(op);
        case CF_DIGEST("SHA1"):
            return SHA1(op);
        case CF_DIGEST("SHA224"):
            return SHA224(op);
        case CF_DIGEST("SHA256"):
            return SHA256(op);
        case CF_DIGEST("SHA384"):
            return SHA384(op);
        case CF_DIGEST("SHA512"):
            return SHA512(op);
        default:
            return std::nullopt;
    }
}

  std::optional<component::MAC> EverCrypt::HMAC(Spec_Hash_Definitions_hash_alg alg, uint32_t mac_len, operation::HMAC& op) const {
    std::optional<component::MAC> ret = std::nullopt;

    uint8_t out[mac_len];

    EverCrypt_HMAC_compute(alg, out, (uint8_t*)op.cipher.key.GetPtr(), op.cipher.key.GetSize(), (uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize());

    ret = component::MAC(out, mac_len);

    return ret;
}
  
std::optional<component::MAC> EverCrypt::OpHMAC(operation::HMAC& op) {
   switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA1"):
          return HMAC(Spec_Hash_Definitions_SHA1, crypto_auth_hmacsha1_BYTES, op);
        case CF_DIGEST("SHA256"):
          return HMAC(Spec_Hash_Definitions_SHA2_256, crypto_auth_hmacsha256_BYTES, op);
        case CF_DIGEST("SHA384"):
          return HMAC(Spec_Hash_Definitions_SHA2_384, crypto_auth_hmacsha384_BYTES, op);
        case CF_DIGEST("SHA512"):
          return HMAC(Spec_Hash_Definitions_SHA2_512, crypto_auth_hmacsha512_BYTES, op);
        default:
            return std::nullopt;
    }
}


} /* namespace module */
} /* namespace cryptofuzz */
