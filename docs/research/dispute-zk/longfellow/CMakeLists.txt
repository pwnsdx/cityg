# A City-G wrap dispute proved with Longfellow: its X25519 half, its
# hashing, and the whole statement over F_{2^255-19}. Research code, not
# part of Longfellow.
proofs_add_tests(x25519_circuit_test)
target_link_libraries(x25519_circuit_test ec util crypto)
proofs_add_tests(keccak_chain_test)
target_link_libraries(keccak_chain_test sha3)
proofs_add_tests(dispute_test)
target_link_libraries(dispute_test sha3 util crypto)
