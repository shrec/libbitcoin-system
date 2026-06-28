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

// Schnorr sign+verify roundtrip.
// sign() routes through libsecp in both build modes; verify_signature() routes
// through the UltrafastSecp256k1 direct engine under HAVE_ULTRAFAST and through
// libsecp otherwise. Single verify is real in both modes, so these tests are
// not guarded.

const ec_secret schnorr_secret = base16_array(
    "8010b1bb119ad37d4b65a1022a314897b1b3614b345974332cb1b9582cf03536");

// Derive the x-only (32-byte) Schnorr public key from a secret by taking the
// low 32 bytes (the X coordinate) of the compressed point, dropping the
// 0x02/0x03 parity prefix byte. array_cast<uint8_t, 32, 1> casts the 33-byte
// compressed key to a 32-byte array starting at offset 1.
static ec_xonly to_xonly(const ec_secret& secret) NOEXCEPT
{
    ec_compressed compressed{};
    BOOST_REQUIRE(secret_to_public(compressed, secret));
    return array_cast<uint8_t, ec_xonly_size, 1>(compressed);
}

BOOST_AUTO_TEST_CASE(secp256k1__schnorr_sign__round_trip_positive__expected)
{
    using namespace system::schnorr;
    constexpr hash_digest auxiliary{};
    const auto hash = bitcoin_hash(to_chunk("schnorr-roundtrip"));
    const auto xonly = to_xonly(schnorr_secret);

    ec_signature signature{};
    BOOST_REQUIRE(sign(signature, schnorr_secret, hash, auxiliary));
    BOOST_REQUIRE(verify_signature(xonly, hash, signature));
}

BOOST_AUTO_TEST_CASE(secp256k1__schnorr_sign__round_trip_negative_signature__expected)
{
    using namespace system::schnorr;
    constexpr hash_digest auxiliary{};
    const auto hash = bitcoin_hash(to_chunk("schnorr-roundtrip-neg-sig"));
    const auto xonly = to_xonly(schnorr_secret);

    ec_signature signature{};
    BOOST_REQUIRE(sign(signature, schnorr_secret, hash, auxiliary));

    // Tamper one byte of the signature; verification must fail.
    signature[10] ^= 0xff;
    BOOST_REQUIRE(!verify_signature(xonly, hash, signature));
}

BOOST_AUTO_TEST_CASE(secp256k1__schnorr_sign__round_trip_negative_hash__expected)
{
    using namespace system::schnorr;
    constexpr hash_digest auxiliary{};
    auto hash = bitcoin_hash(to_chunk("schnorr-roundtrip-neg-hash"));
    const auto xonly = to_xonly(schnorr_secret);

    ec_signature signature{};
    BOOST_REQUIRE(sign(signature, schnorr_secret, hash, auxiliary));

    // Verify against a different hash; verification must fail.
    hash[0] ^= 0xff;
    BOOST_REQUIRE(!verify_signature(xonly, hash, signature));
}

BOOST_AUTO_TEST_SUITE_END()
