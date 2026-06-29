/**
 * Copyright (c) 2011-2026 libbitcoin developers (see AUTHORS)
 *
 * This file is part of libbitcoin.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "../../test.hpp"

BOOST_AUTO_TEST_SUITE(secp256k1_tests)

// ECDSA recoverable sign/recover roundtrip.
// ----------------------------------------------------------------------------
// sign_recoverable(), recover_public(ec_compressed), and
// recover_public(ec_uncompressed) ALL route through the direct engine
// (ufsecp/libbitcoin.hpp + secp256k1::fast::Point) under HAVE_ULTRAFAST —
// recover.cpp is 100% libsecp256k1-free in that mode — falling back to the
// libsecp256k1 C-API otherwise. The uncompressed path recovers the compressed
// key then decompresses to emit the 65-byte form. These tests assert the public
// contract (roundtrip equality, recovery_id range, wrong-hash mismatch) which
// holds identically in BOTH build modes, so they are not guarded.

const ec_secret recover_secret = base16_array(
    "8010b1bb119ad37d4b65a1022a314897b1b3614b345974332cb1b9582cf03536");

BOOST_AUTO_TEST_CASE(secp256k1__recover_public__round_trip__equals_secret_to_public)
{
    using namespace system::ecdsa;
    const auto hash = bitcoin_hash(to_chunk("recover-roundtrip"));

    // Expected public key derived directly from the secret.
    ec_compressed expected;
    BOOST_REQUIRE(secret_to_public(expected, recover_secret));

    recoverable_signature recoverable{};
    BOOST_REQUIRE(sign_recoverable(recoverable, recover_secret, hash));

    // Recovery id must be in the canonical 0..3 range (compressed flag stripped).
    BOOST_REQUIRE_LE(recoverable.recovery_id, 3u);

    // Compressed recovery returns the originating public key.
    ec_compressed recovered;
    BOOST_REQUIRE(recover_public(recovered, recoverable, hash));
    BOOST_REQUIRE_EQUAL(recovered, expected);

    // Uncompressed recovery matches the uncompressed form of the same key.
    ec_uncompressed expected_uncompressed;
    BOOST_REQUIRE(secret_to_public(expected_uncompressed, recover_secret));

    ec_uncompressed recovered_uncompressed;
    BOOST_REQUIRE(recover_public(recovered_uncompressed, recoverable, hash));
    BOOST_REQUIRE_EQUAL(recovered_uncompressed, expected_uncompressed);
}

BOOST_AUTO_TEST_CASE(secp256k1__recover_public__wrong_hash__not_originating_key)
{
    using namespace system::ecdsa;
    const auto hash = bitcoin_hash(to_chunk("recover-wrong-hash"));

    ec_compressed expected;
    BOOST_REQUIRE(secret_to_public(expected, recover_secret));

    recoverable_signature recoverable{};
    BOOST_REQUIRE(sign_recoverable(recoverable, recover_secret, hash));

    // Recover against a different hash. Recovery is algebraic so it may still
    // yield some point, but it must NOT yield the originating public key.
    auto wrong_hash = hash;
    wrong_hash[0] ^= 0xff;

    ec_compressed recovered;
    if (recover_public(recovered, recoverable, wrong_hash))
        BOOST_REQUIRE(recovered != expected);
}

BOOST_AUTO_TEST_SUITE_END()
