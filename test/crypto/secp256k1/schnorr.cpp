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
// Under HAVE_ULTRAFAST both sign() and verify_signature() route through the
// UltrafastSecp256k1 direct engine (ufsecp::lbtc::*); otherwise both route
// through libsecp256k1. Both engines are BIP-340 deterministic, so the sign
// path is real in both modes and these tests are not guarded. The positive
// case exercises the migrated sign path; the negative cases (tampered
// signature, tampered hash) confirm verification rejects mismatches.

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

// verify_commitment (BIP-341 x-only tweak-add-check with a raw tweak scalar).
// Under HAVE_ULTRAFAST this routes through the engine (lift_x even-Y internal
// key, Q' = P + t*G via dual_scalar_mul_gen_point, x/parity compare); otherwise
// through libsecp256k1's secp256k1_xonly_pubkey_tweak_add_check. The vector is
// built mode-independently using libbitcoin's public ec_add (point += G*scalar):
// the internal key is the generator's x-only (even Y, so the lift equals G), and
// Q = G + t*G is computed with the same raw tweak scalar the check consumes.

BOOST_AUTO_TEST_CASE(secp256k1__schnorr_verify_commitment__round_trip_positive__expected)
{
    using namespace system::schnorr;

    // Internal key P = G (even Y); its x-only is the low 32 bytes of the
    // compressed generator. lift_x of this x-only is exactly G.
    const auto internal = array_cast<uint8_t, ec_xonly_size, 1>(
        ec_compressed_generator);

    // Raw tweak scalar t (valid, < n, non-zero).
    const ec_secret tweak = base16_array(
        "8010b1bb119ad37d4b65a1022a314897b1b3614b345974332cb1b9582cf03536");

    // Q = P + t*G, computed via libbitcoin's public point arithmetic.
    auto q_point = ec_compressed_generator;  // 0x02 || Gx == lift_x(P) == G
    BOOST_REQUIRE(ec_add(q_point, tweak));

    const auto tweaked = array_cast<uint8_t, ec_xonly_size, 1>(q_point);
    const auto parity = (q_point.front() == ec_odd_sign);

    BOOST_REQUIRE(verify_commitment(internal, tweak, tweaked, parity));
}

BOOST_AUTO_TEST_CASE(secp256k1__schnorr_verify_commitment__round_trip_negative_parity__expected)
{
    using namespace system::schnorr;

    const auto internal = array_cast<uint8_t, ec_xonly_size, 1>(
        ec_compressed_generator);
    const ec_secret tweak = base16_array(
        "8010b1bb119ad37d4b65a1022a314897b1b3614b345974332cb1b9582cf03536");

    auto q_point = ec_compressed_generator;
    BOOST_REQUIRE(ec_add(q_point, tweak));

    const auto tweaked = array_cast<uint8_t, ec_xonly_size, 1>(q_point);
    const auto parity = (q_point.front() == ec_odd_sign);

    // Flip the parity bit; the commitment must be rejected.
    BOOST_REQUIRE(!verify_commitment(internal, tweak, tweaked, !parity));
}

BOOST_AUTO_TEST_CASE(secp256k1__schnorr_verify_commitment__round_trip_negative_tweak__expected)
{
    using namespace system::schnorr;

    const auto internal = array_cast<uint8_t, ec_xonly_size, 1>(
        ec_compressed_generator);
    const ec_secret tweak = base16_array(
        "8010b1bb119ad37d4b65a1022a314897b1b3614b345974332cb1b9582cf03536");

    auto q_point = ec_compressed_generator;
    BOOST_REQUIRE(ec_add(q_point, tweak));

    const auto tweaked = array_cast<uint8_t, ec_xonly_size, 1>(q_point);
    const auto parity = (q_point.front() == ec_odd_sign);

    // Verify against a different tweak; the commitment must be rejected.
    auto wrong_tweak = tweak;
    wrong_tweak[0] ^= 0xff;
    BOOST_REQUIRE(!verify_commitment(internal, wrong_tweak, tweaked, parity));
}

BOOST_AUTO_TEST_SUITE_END()
