#include <fuzzing/datasource/datasource.hpp>
#include <fuzzing/datasource/id.hpp>
#include <cryptofuzz/util.h>
#include <cryptofuzz/operations.h>

namespace cryptofuzz {
  
template <class OperationType>
OperationType getOp(Datasource* parentDs, const uint8_t* data, const size_t size) {
    Datasource ds(data, size);
    
    if ( parentDs != nullptr ) {
        auto modifier = parentDs->GetData(0);
        return std::move( OperationType(ds, component::Modifier(modifier.data(), modifier.size())) );
    } else {
        return std::move( OperationType(ds, component::Modifier(nullptr, 0)) );
    }
}

void printOp(const uint8_t* data, const size_t size) {    
    using fuzzing::datasource::ID;

    Datasource ds(data, size);

    const auto operation = ds.Get<uint64_t>();
    const auto payload = ds.GetData(0, 1);

    switch ( operation ) {        
        case ID("Cryptofuzz/Operation/Digest"):
          {
            auto op = getOp<operation::Digest>(&ds, payload.data(), payload.size());
            printf("Operation:\n%s\n", op.ToString().c_str());
            break;
          }
        case ID("Cryptofuzz/Operation/HMAC"):
          {
            auto op = getOp<operation::HMAC>(&ds, payload.data(), payload.size());     
            printf("Operation:\n%s\n", op.ToString().c_str());
            break;
          }
        case ID("Cryptofuzz/Operation/KDF_HKDF"):
          {
            auto op = getOp<operation::KDF_HKDF>(&ds, payload.data(), payload.size());     
            printf("Operation:\n%s\n", op.ToString().c_str());
            break;
          }
        case ID("Cryptofuzz/Operation/SymmetricEncrypt"):
          {
            auto op = getOp<operation::SymmetricEncrypt>(&ds, payload.data(), payload.size());     
            printf("Operation:\n%s\n", op.ToString().c_str());
            break;
          }
        case ID("Cryptofuzz/Operation/SymmetricDecrypt"):
          {
            auto op = getOp<operation::SymmetricDecrypt>(&ds, payload.data(), payload.size());     
            printf("Operation:\n%s\n", op.ToString().c_str());
            break;
          }
    }
}

} // namespace cryptofuzz


int main(int argc, char **argv) {
   if (argc < 2) {
     printf("Usage: print_op FILE\n");
     return 1;
   }
     
   FILE* fd = fopen(argv[1], "rb");   
   if (!fd) {
     printf("Error: cannot open file %s\n", argv[1]);
     return 1;
   }

   fseek(fd, 0, SEEK_END);
   size_t size = ftell(fd);
   rewind(fd);
   
   auto buffer = cryptofuzz::util::malloc(size);
   fread(buffer, 1, size, fd);
  
   cryptofuzz::printOp(buffer, size);
   
   fclose(fd);
   free(buffer);

   return 0;
}
