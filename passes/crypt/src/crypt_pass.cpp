#include "wvmp/passes/crypt/crypt_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/registry.hpp"

namespace wvmp::passes {

void CryptPass::run(ProtectionContext& /*ctx*/) {
    // TODO(crypt lane): run BytecodeCodec::encrypt_stream over the vm.program
    // bytecode and record codec metadata for the interpreter decrypt stub.
}

WVMP_REGISTER_PASS(CryptPass)

} // namespace wvmp::passes
