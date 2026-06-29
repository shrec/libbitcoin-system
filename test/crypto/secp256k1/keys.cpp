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

// Key ops (secret_to_public, compress/decompress, generator).
// ----------------------------------------------------------------------------
// Every key op has a full engine implementation under HAVE_ULTRAFAST:
//   secret_to_public(compressed)  -> ufsecp::lbtc::pubkey_create (CT)
//   secret_to_public(uncompressed)-> pubkey_create + engine decompress
//   verify_secret                 -> ufsecp::lbtc::seckey_verify
//   verify_point (compressed)     -> ufsecp::lbtc::pubkey_parse
//   verify_point (uncompressed)   -> engine field/point on-curve parse
//   compress / decompress         -> fast::Point (de)serialize
// In ON mode this TU is 100% libsecp256k1-free; in OFF mode it routes through
// the libsecp256k1 C-API. These tests are mode-agnostic: the accept/reject and
// round-trip contracts are identical in both modes, so they are not guarded.

const ec_secret secret1 = base16_array("8010b1bb119ad37d4b65a1022a314897b1b3614b345974332cb1b9582cf03536");
const ec_compressed compressed1 = base16_array("0309ba8621aefd3b6ba4ca6d11a4746e8df8d35d9b51b383338f627ba7fc732731");
const ec_uncompressed uncompressed1 = base16_array("0409ba8621aefd3b6ba4ca6d11a4746e8df8d35d9b51b383338f627ba7fc7327318c3a6ec6acd33c36328b8fb4349b31671bcd3a192316ea4f6236ee1ae4a7d8c9");

// generator

BOOST_AUTO_TEST_CASE(secp256k1__generator__expected)
{
    const ec_secret one = base16_array("0000000000000000000000000000000000000000000000000000000000000001");

    ec_compressed generator;
    BOOST_REQUIRE(secret_to_public(generator, one));
    BOOST_REQUIRE_EQUAL(generator, ec_compressed_generator);
}

BOOST_AUTO_TEST_CASE(secp256k1__compress__round_trip__expected)
{
    ec_uncompressed uncompressed;
    BOOST_REQUIRE(decompress(uncompressed, compressed1));

    ec_compressed compressed;
    BOOST_REQUIRE(compress(compressed, uncompressed));
    BOOST_REQUIRE_EQUAL(compressed, compressed1);
}

BOOST_AUTO_TEST_CASE(secp256k1__decompress__positive__expected)
{
    ec_uncompressed point;
    BOOST_REQUIRE(decompress(point, compressed1));
    BOOST_REQUIRE_EQUAL(point, uncompressed1);
}

BOOST_AUTO_TEST_CASE(secp256k1__secret_to_public__compressed_positive__expected)
{
    ec_compressed point;
    BOOST_REQUIRE(secret_to_public(point, secret1));
    BOOST_REQUIRE_EQUAL(point, compressed1);
}

BOOST_AUTO_TEST_CASE(secp256k1__secret_to_public__uncompressed_positive__expected)
{
    ec_uncompressed point;
    BOOST_REQUIRE(secret_to_public(point, secret1));
    BOOST_REQUIRE_EQUAL(point, uncompressed1);
}

// verify_secret (engine path: ufsecp::lbtc::seckey_verify under HAVE_ULTRAFAST,
// libsecp fallback otherwise). Mode-agnostic: identical accept/reject contract.

BOOST_AUTO_TEST_CASE(secp256k1__verify_secret__valid__true)
{
    BOOST_REQUIRE(verify_secret(secret1));
}

BOOST_AUTO_TEST_CASE(secp256k1__verify_secret__zero__false)
{
    const ec_secret zero = base16_array(
        "0000000000000000000000000000000000000000000000000000000000000000");
    BOOST_REQUIRE(!verify_secret(zero));
}

BOOST_AUTO_TEST_CASE(secp256k1__verify_secret__order__false)
{
    // n (the curve order) is out of range: valid secrets are 0 < sk < n.
    const ec_secret order = base16_array(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    BOOST_REQUIRE(!verify_secret(order));
}

BOOST_AUTO_TEST_CASE(secp256k1__verify_secret__above_order__false)
{
    // 0xff..ff is >= n: must be rejected (strict, no silent reduction mod n).
    const ec_secret above = base16_array(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    BOOST_REQUIRE(!verify_secret(above));
}

// verify_point (engine path: ufsecp::lbtc::pubkey_parse for 33-byte compressed
// under HAVE_ULTRAFAST; uncompressed/garbage route to the libsecp fallback).

BOOST_AUTO_TEST_CASE(secp256k1__verify_point__compressed__true)
{
    BOOST_REQUIRE(verify_point(compressed1));
}

BOOST_AUTO_TEST_CASE(secp256k1__verify_point__uncompressed__true)
{
    BOOST_REQUIRE(verify_point(uncompressed1));
}

BOOST_AUTO_TEST_CASE(secp256k1__verify_point__compressed_garbage__false)
{
    // Valid 0x02 prefix + 32-byte X that is not on the curve.
    const auto garbage = base16_array(
        "02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    BOOST_REQUIRE(!verify_point(garbage));
}

BOOST_AUTO_TEST_CASE(secp256k1__verify_point__bad_prefix__false)
{
    // 33 bytes but prefix is neither 0x02 nor 0x03 — not a compressed key.
    const auto bad_prefix = base16_array(
        "0009ba8621aefd3b6ba4ca6d11a4746e8df8d35d9b51b383338f627ba7fc732731");
    BOOST_REQUIRE(!verify_point(bad_prefix));
}

BOOST_AUTO_TEST_SUITE_END()
