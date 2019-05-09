#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>

namespace cryptofuzz {
namespace module {

class EverCrypt : public Module {
    private:
        std::optional<component::Digest> SHA256(operation::Digest& op) const;
        std::optional<component::Digest> SHA512(operation::Digest& op) const;
    public:
        EverCrypt(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
