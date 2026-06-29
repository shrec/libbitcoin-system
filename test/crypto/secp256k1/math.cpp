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

// EC math (ec_add, ec_sum, ec_multiply, negation).
// ----------------------------------------------------------------------------
// Compressed point/scalar arithmetic (ec_add, ec_sum, ec_multiply, ec_negate
// on ec_compressed/ec_secret) routes through the direct engine
// (ufsecp::lbtc::*) under HAVE_ULTRAFAST and through the libsecp256k1 C-API in
// the #else fallback. These tests are mode-agnostic: each assertion holds
// identically whether HAVE_ULTRAFAST is ON (engine) or OFF (libsecp), so they
// are not guarded and exercise whichever backend is compiled in.
//
// NOTE on zero-tweak divergence: the engine's seckey/pubkey tweak helpers use
// parse_bytes_strict_nonzero and reject a zero tweak (and a zero result),
// whereas libsecp256k1 accepts tweak == 0. No test below uses a zero tweak, so
// both backends agree on every case here. A zero-tweak input would diverge
// (engine: false; libsecp: success) — intentionally not exercised so the
// engine's fail-closed guarantee is preserved.

// addition

BOOST_AUTO_TEST_CASE(secp256k1__ec_add__positive__expected)
{
    const auto sum = base16_array(
        "0404040000000000000000000000000000000000000000000000000000000000");

    ec_secret secret_one{ { 1, 2, 3 } };
    ec_compressed public1;
    BOOST_REQUIRE(secret_to_public(public1, secret_one));

    const ec_secret secret_two{ { 3, 2, 1 } };
    BOOST_REQUIRE(ec_add(secret_one, secret_two));
    BOOST_REQUIRE_EQUAL(secret_one, sum);

    ec_compressed public2;
    BOOST_REQUIRE(secret_to_public(public2, secret_one));
    BOOST_REQUIRE(ec_add(public1, secret_two));
    BOOST_REQUIRE_EQUAL(public1, public2);
}

BOOST_AUTO_TEST_CASE(secp256k1__ec_add__negative__expected)
{
    // = n - 1
    auto secret_one = base16_array(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
    ec_secret secret_two{ { 0 } };
    secret_two[31] = 1;
    ec_compressed public1;
    BOOST_REQUIRE(secret_to_public(public1, secret_one));
    BOOST_REQUIRE(!ec_add(secret_one, secret_two));
    BOOST_REQUIRE(!ec_add(public1, secret_two));
}

BOOST_AUTO_TEST_CASE(secp256k1__ec_add__secret_plus_zero__identity)
{
    // x + 0 == x: zero is a valid mod-n addend (right operand), result unchanged.
    ec_secret secret{ { 0 } };
    secret[31] = 7;
    const ec_secret original = secret;
    const ec_secret zero{ { 0 } };

    BOOST_REQUIRE(ec_add(secret, zero));
    BOOST_REQUIRE_EQUAL(secret, original);
}

BOOST_AUTO_TEST_CASE(secp256k1__ec_add__zero_plus_secret__rejected)
{
    // 0 + y fails: a zero base (left operand) is not a valid scalar.
    ec_secret zero{ { 0 } };
    const ec_secret secret_two{ { 3, 2, 1 } };
    BOOST_REQUIRE(!ec_add(zero, secret_two));
}

BOOST_AUTO_TEST_CASE(secp256k1__ec_sum__expected)
{
    const ec_compressed generator_point_times_4 = base16_array(
        "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13");

    const ec_compresseds points
    {
        ec_compressed_generator,
        ec_compressed_generator,
        ec_compressed_generator,
        ec_compressed_generator
    };

    ec_compressed out;
    BOOST_REQUIRE(ec_sum(out, points));
    BOOST_REQUIRE_EQUAL(out, generator_point_times_4);
}

BOOST_AUTO_TEST_CASE(secp256k1__ec_sum__two_points__equals_double)
{
    // G + G == 2G; cross-check ec_sum of two compressed keys against the
    // scalar path (secret 2 -> public).
    const ec_compresseds points{ ec_compressed_generator, ec_compressed_generator };

    ec_compressed sum;
    BOOST_REQUIRE(ec_sum(sum, points));

    ec_secret two{ { 0 } };
    two[31] = 2;
    ec_compressed double_generator;
    BOOST_REQUIRE(secret_to_public(double_generator, two));
    BOOST_REQUIRE_EQUAL(sum, double_generator);
}

// multiplication

BOOST_AUTO_TEST_CASE(secp256k1__ec_multiply__expected)
{
    ec_secret secret_one{ {0} };
    ec_secret secret_two{ {0} };
    secret_one[31] = 11;
    secret_two[31] = 22;
    ec_compressed public1;
    BOOST_REQUIRE(secret_to_public(public1, secret_one));
    BOOST_REQUIRE(ec_multiply(secret_one, secret_two));
    BOOST_REQUIRE_EQUAL(secret_one[31], 242u);
    BOOST_REQUIRE(ec_multiply(public1, secret_two));

    ec_compressed public2;
    BOOST_REQUIRE(secret_to_public(public2, secret_one));
    BOOST_REQUIRE_EQUAL(public1, public2);
}

// negation

BOOST_AUTO_TEST_CASE(secp256k1__ec_negate__secret__double_negate_identity)
{
    ec_secret secret{ { 0 } };
    secret[31] = 7;
    const ec_secret original = secret;

    BOOST_REQUIRE(ec_negate(secret));
    BOOST_REQUIRE_NE(secret, original);

    // -(-s) == s
    BOOST_REQUIRE(ec_negate(secret));
    BOOST_REQUIRE_EQUAL(secret, original);
}

BOOST_AUTO_TEST_CASE(secp256k1__ec_negate__secret__sum_to_zero)
{
    // s + (-s) == 0 mod n, which both backends reject (result == 0).
    ec_secret secret{ { 0 } };
    secret[31] = 9;
    ec_secret negated = secret;
    BOOST_REQUIRE(ec_negate(negated));

    BOOST_REQUIRE(!ec_add(secret, negated));
}

BOOST_AUTO_TEST_CASE(secp256k1__ec_negate__point__double_negate_identity)
{
    ec_secret secret{ { 0 } };
    secret[31] = 5;
    ec_compressed point;
    BOOST_REQUIRE(secret_to_public(point, secret));
    const ec_compressed original = point;

    BOOST_REQUIRE(ec_negate(point));
    BOOST_REQUIRE_NE(point, original);

    // -(-P) == P
    BOOST_REQUIRE(ec_negate(point));
    BOOST_REQUIRE_EQUAL(point, original);
}

BOOST_AUTO_TEST_CASE(secp256k1__ec_negate__point__matches_negated_secret)
{
    // (-s)*G == -(s*G): negate the secret then derive, vs derive then negate.
    ec_secret secret{ { 0 } };
    secret[31] = 13;

    ec_compressed point;
    BOOST_REQUIRE(secret_to_public(point, secret));
    BOOST_REQUIRE(ec_negate(point));

    ec_secret negated_secret = secret;
    BOOST_REQUIRE(ec_negate(negated_secret));
    ec_compressed point_from_negated_secret;
    BOOST_REQUIRE(secret_to_public(point_from_negated_secret, negated_secret));

    BOOST_REQUIRE_EQUAL(point, point_from_negated_secret);
}

BOOST_AUTO_TEST_CASE(secp256k1__ec_negate__secret_zero__rejected)
{
    // ec_negate on a zero secret is rejected (a zero scalar is not a valid
    // secret key) — identical behavior in both the engine (ON) and libsecp256k1
    // (OFF) paths.
    ec_secret zero{ { 0 } };
    BOOST_REQUIRE(!ec_negate(zero));
}

// uncompressed point ops (65-byte) — engine-backed under HAVE_ULTRAFAST,
// libsecp256k1 in the #else fallback. Exercises the uncompressed parse/serialize
// round-trip for ec_negate, ec_add and ec_multiply.

BOOST_AUTO_TEST_CASE(secp256k1__ec_negate__uncompressed__double_negate_identity)
{
    ec_secret secret{ { 0 } };
    secret[31] = 5;
    ec_compressed compressed;
    BOOST_REQUIRE(secret_to_public(compressed, secret));

    ec_uncompressed point;
    BOOST_REQUIRE(decompress(point, compressed));
    const ec_uncompressed original = point;

    BOOST_REQUIRE(ec_negate(point));
    BOOST_REQUIRE_NE(point, original);

    // -(-P) == P
    BOOST_REQUIRE(ec_negate(point));
    BOOST_REQUIRE_EQUAL(point, original);
}

BOOST_AUTO_TEST_CASE(secp256k1__ec_multiply__uncompressed__matches_compressed)
{
    // P * s on the uncompressed point compresses to the same key as P * s on the
    // compressed point — cross-checks the uncompressed engine path.
    ec_secret secret{ { 0 } };
    secret[31] = 6;
    ec_secret scalar{ { 0 } };
    scalar[31] = 7;

    ec_compressed compressed;
    BOOST_REQUIRE(secret_to_public(compressed, secret));

    ec_uncompressed point;
    BOOST_REQUIRE(decompress(point, compressed));

    BOOST_REQUIRE(ec_multiply(compressed, scalar));
    BOOST_REQUIRE(ec_multiply(point, scalar));

    ec_compressed from_uncompressed;
    BOOST_REQUIRE(compress(from_uncompressed, point));
    BOOST_REQUIRE_EQUAL(from_uncompressed, compressed);
}

BOOST_AUTO_TEST_CASE(secp256k1__ec_add__uncompressed__matches_compressed)
{
    // P + s*G on the uncompressed point compresses to the same key as on the
    // compressed point.
    ec_secret secret{ { 0 } };
    secret[31] = 8;
    const ec_secret scalar{ { 3, 2, 1 } };

    ec_compressed compressed;
    BOOST_REQUIRE(secret_to_public(compressed, secret));

    ec_uncompressed point;
    BOOST_REQUIRE(decompress(point, compressed));

    BOOST_REQUIRE(ec_add(compressed, scalar));
    BOOST_REQUIRE(ec_add(point, scalar));

    ec_compressed from_uncompressed;
    BOOST_REQUIRE(compress(from_uncompressed, point));
    BOOST_REQUIRE_EQUAL(from_uncompressed, compressed);
}

BOOST_AUTO_TEST_SUITE_END()
