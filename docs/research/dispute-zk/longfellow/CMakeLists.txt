# A City-G wrap dispute priced with Longfellow: its X25519 half and its
# hashing. Research code, not part of Longfellow.
proofs_add_tests(x25519_circuit_test)
target_link_libraries(x25519_circuit_test ec util crypto)
proofs_add_tests(keccak_chain_test)
target_link_libraries(keccak_chain_test sha3)
