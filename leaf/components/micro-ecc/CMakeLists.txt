# micro-ecc (BSD-2-Clause), commit 24c60e2 (the revision ESP-IDF v6.0.1 pins).
# Only secp256r1 is compiled in.
idf_component_register(SRCS "micro-ecc/uECC.c" INCLUDE_DIRS "micro-ecc")
target_compile_definitions(${COMPONENT_LIB} PUBLIC uECC_SUPPORTS_secp160r1=0 uECC_SUPPORTS_secp192r1=0
                           uECC_SUPPORTS_secp224r1=0 uECC_SUPPORTS_secp256k1=0 uECC_SUPPORTS_secp256r1=1
                           uECC_OPTIMIZATION_LEVEL=3 uECC_SQUARE_FUNC=1)
