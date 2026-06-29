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

// ECDSA batch verify (SoA column spans).
// ----------------------------------------------------------------------------
// ecdsa::batch holds parallel column spans (correlates/digests/points/
// signatures) over equal-length backing arrays. Under HAVE_ULTRAFAST,
// batch::evaluate() routes the columns straight into the UltrafastSecp256k1
// direct engine (ufsecp::lbtc::ecdsa_verify_columns) and returns a per-row
// results buffer (1 = valid, 0 = invalid); otherwise evaluate() is a stub
// returning an empty buffer.
//
// IMPORTANT — what is and is not validated here:
//   * evaluate() is the engine verdict surface. The HAVE_ULTRAFAST-guarded
//     assertions below check the actual per-row verdicts the direct engine
//     produces, including detection of a tampered row. This is the real test
//     of the column integration.
//   * batch::verify() additionally runs correlate()->get_failures() to map the
//     per-row results to failing link ids. That correlation pass is NOT yet
//     implemented upstream (its body is commented out in src/.../batch.cpp and
//     it returns {} in every build mode). Tests therefore do NOT assert on
//     verify()'s links_t result, because today it cannot report failures even
//     when the engine detects them. This is a tracked blocker, reported back to
//     Codex; it is not exercised as a success condition.
//   * The single-signature primitive verify (ecdsa::verify_signature) is real
//     in both build modes and is asserted unguarded as a baseline.

const ec_secret batch_secret0 = base16_array(
    "8010b1bb119ad37d4b65a1022a314897b1b3614b345974332cb1b9582cf03536");
const ec_secret batch_secret1 = base16_array(
    "33436393f770d9b3f5d11c20be561837300f89515284008965d2fd3f714b8fce");
const ec_secret batch_secret2 = base16_array(
    "0000000000000000000000000000000000000000000000000000000000000001");

// Build single-signature correlate rows with unique ids and group 0 so each row
// is its own (single-signature) group.
static ecdsa::batch::correlate_t ecdsa_single_row(uint8_t id) NOEXCEPT
{
    // pair=0 (single signature), group=0 (each row is its own group), id is a
    // 3-byte little-endian link with a unique low byte per row. Typed literals
    // avoid -Wnarrowing in the braced aggregate initializers.
    const batched::link link{ id, uint8_t{ 0 }, uint8_t{ 0 } };
    return ecdsa::batch::correlate_t{ uint8_t{ 0 }, uint16_t{ 0 }, link };
}

#if defined(HAVE_ULTRAFAST)
// Exposes the protected static evaluate() (the engine verdict surface) so tests
// can assert the per-row results the direct column engine produces.
struct ecdsa_batch_accessor
  : public ecdsa::batch
{
    using ecdsa::batch::evaluate;
};
#endif

BOOST_AUTO_TEST_CASE(secp256k1__ecdsa_batch_evaluate__singles_all_valid__all_rows_pass)
{
    using namespace system::ecdsa;
    const auto hash = bitcoin_hash(to_chunk("batch-ecdsa-valid"));

    std::vector<hash_digest> digests{ hash, hash, hash };

    std::vector<ec_compressed> points(3);
    BOOST_REQUIRE(secret_to_public(points.at(0), batch_secret0));
    BOOST_REQUIRE(secret_to_public(points.at(1), batch_secret1));
    BOOST_REQUIRE(secret_to_public(points.at(2), batch_secret2));

    std::vector<ec_signature> signatures(3);
    BOOST_REQUIRE(sign(signatures.at(0), batch_secret0, hash));
    BOOST_REQUIRE(sign(signatures.at(1), batch_secret1, hash));
    BOOST_REQUIRE(sign(signatures.at(2), batch_secret2, hash));

    // Baseline (both build modes): each signature verifies at the primitive level.
    BOOST_REQUIRE(verify_signature(points.at(0), hash, signatures.at(0)));
    BOOST_REQUIRE(verify_signature(points.at(1), hash, signatures.at(1)));
    BOOST_REQUIRE(verify_signature(points.at(2), hash, signatures.at(2)));

    std::vector<batch::correlate_t> correlates
    {
        ecdsa_single_row(0),
        ecdsa_single_row(1),
        ecdsa_single_row(2)
    };

    const batch b
    {
        correlates,
        digests,
        points,
        signatures
    };

    stopper cancel{};

#if defined(HAVE_ULTRAFAST)
    // Engine verdict surface: the column verify runs and reports every row valid.
    const auto results = ecdsa_batch_accessor::evaluate(cancel, b);
    BOOST_REQUIRE_EQUAL(results.size(), 3u);
    BOOST_REQUIRE(results.at(0) != 0);
    BOOST_REQUIRE(results.at(1) != 0);
    BOOST_REQUIRE(results.at(2) != 0);
#else
    (void)cancel;
    (void)b;
#endif
}

BOOST_AUTO_TEST_CASE(secp256k1__ecdsa_batch_evaluate__singles_one_tampered__row_rejected)
{
    using namespace system::ecdsa;
    const auto hash = bitcoin_hash(to_chunk("batch-ecdsa-tampered"));

    std::vector<hash_digest> digests{ hash, hash, hash };

    std::vector<ec_compressed> points(3);
    BOOST_REQUIRE(secret_to_public(points.at(0), batch_secret0));
    BOOST_REQUIRE(secret_to_public(points.at(1), batch_secret1));
    BOOST_REQUIRE(secret_to_public(points.at(2), batch_secret2));

    std::vector<ec_signature> signatures(3);
    BOOST_REQUIRE(sign(signatures.at(0), batch_secret0, hash));
    BOOST_REQUIRE(sign(signatures.at(1), batch_secret1, hash));
    BOOST_REQUIRE(sign(signatures.at(2), batch_secret2, hash));

    // Tamper the third row's signature.
    signatures.at(2)[10] ^= 0xff;

    // Baseline (both build modes): the tampered row is genuinely invalid and the
    // others remain valid at the primitive level.
    BOOST_REQUIRE(verify_signature(points.at(0), hash, signatures.at(0)));
    BOOST_REQUIRE(verify_signature(points.at(1), hash, signatures.at(1)));
    BOOST_REQUIRE(!verify_signature(points.at(2), hash, signatures.at(2)));

    std::vector<batch::correlate_t> correlates
    {
        ecdsa_single_row(0),
        ecdsa_single_row(1),
        ecdsa_single_row(2)
    };

    const batch b
    {
        correlates,
        digests,
        points,
        signatures
    };

    stopper cancel{};

#if defined(HAVE_ULTRAFAST)
    // Engine verdict surface: the column verify detects the tampered row 2.
    // (This is the meaningful HAVE_ULTRAFAST assertion: a real failure verdict
    // from the direct engine, not the stubbed verify()/get_failures path.)
    const auto results = ecdsa_batch_accessor::evaluate(cancel, b);
    BOOST_REQUIRE_EQUAL(results.size(), 3u);
    BOOST_REQUIRE(results.at(0) != 0);
    BOOST_REQUIRE(results.at(1) != 0);
    BOOST_REQUIRE(results.at(2) == 0);
#else
    (void)cancel;
    (void)b;
#endif
}

// Schnorr batch verify (SoA column spans).
// ----------------------------------------------------------------------------
// schnorr::batch holds parallel column spans (correlates/digests/points/
// signatures) over equal-length backing arrays. points are x-only (32-byte)
// per BIP-340. Under HAVE_ULTRAFAST, batch::evaluate() routes the columns into
// the UltrafastSecp256k1 direct engine (ufsecp::lbtc::schnorr_verify_columns)
// and returns a per-row results buffer (1 = valid, 0 = invalid); otherwise
// evaluate() is a stub returning an empty buffer.
//
// As with the ECDSA cases above, tests assert on evaluate()'s per-row engine
// verdicts, NOT on verify()'s links_t (correlate()->get_failures() is a tracked
// upstream stub returning {} in every build mode).

const ec_secret schnorr_batch_secret0 = base16_array(
    "8010b1bb119ad37d4b65a1022a314897b1b3614b345974332cb1b9582cf03536");
const ec_secret schnorr_batch_secret1 = base16_array(
    "33436393f770d9b3f5d11c20be561837300f89515284008965d2fd3f714b8fce");
const ec_secret schnorr_batch_secret2 = base16_array(
    "0000000000000000000000000000000000000000000000000000000000000001");

// Derive the x-only (32-byte) Schnorr public key from a secret by taking the
// low 32 bytes (the X coordinate) of the compressed point, dropping the
// 0x02/0x03 parity prefix byte.
static ec_xonly schnorr_batch_xonly(const ec_secret& secret) NOEXCEPT
{
    ec_compressed compressed{};
    BOOST_REQUIRE(secret_to_public(compressed, secret));
    return array_cast<uint8_t, ec_xonly_size, 1>(compressed);
}

// Build single-signature schnorr correlate rows: category=single, pair=0,
// group=0 (each row is its own single-signature group), unique id low byte.
static schnorr::batch::correlate_t schnorr_single_row(uint8_t id) NOEXCEPT
{
    const batched::link link{ id, uint8_t{ 0 }, uint8_t{ 0 } };
    return schnorr::batch::correlate_t
    {
        uint8_t{ 0 } /*category: single*/,
        uint16_t{ 0 } /*pair*/,
        uint16_t{ 0 } /*group*/,
        link
    };
}

#if defined(HAVE_ULTRAFAST)
// Exposes the protected static evaluate() (the engine verdict surface) so tests
// can assert the per-row results the direct column engine produces.
struct schnorr_batch_accessor
  : public schnorr::batch
{
    using schnorr::batch::evaluate;
};
#endif

BOOST_AUTO_TEST_CASE(secp256k1__schnorr_batch_evaluate__singles_all_valid__all_rows_pass)
{
    using namespace system::schnorr;
    constexpr hash_digest auxiliary{};
    const auto hash = bitcoin_hash(to_chunk("batch-schnorr-valid"));

    std::vector<hash_digest> digests{ hash, hash, hash };

    std::vector<ec_xonly> points
    {
        schnorr_batch_xonly(schnorr_batch_secret0),
        schnorr_batch_xonly(schnorr_batch_secret1),
        schnorr_batch_xonly(schnorr_batch_secret2)
    };

    std::vector<ec_signature> signatures(3);
    BOOST_REQUIRE(sign(signatures.at(0), schnorr_batch_secret0, hash, auxiliary));
    BOOST_REQUIRE(sign(signatures.at(1), schnorr_batch_secret1, hash, auxiliary));
    BOOST_REQUIRE(sign(signatures.at(2), schnorr_batch_secret2, hash, auxiliary));

    // Baseline (both build modes): each signature verifies at the primitive level.
    BOOST_REQUIRE(verify_signature(points.at(0), hash, signatures.at(0)));
    BOOST_REQUIRE(verify_signature(points.at(1), hash, signatures.at(1)));
    BOOST_REQUIRE(verify_signature(points.at(2), hash, signatures.at(2)));

    std::vector<batch::correlate_t> correlates
    {
        schnorr_single_row(0),
        schnorr_single_row(1),
        schnorr_single_row(2)
    };

    const batch b
    {
        correlates,
        digests,
        points,
        signatures
    };

    stopper cancel{};

#if defined(HAVE_ULTRAFAST)
    // Engine verdict surface: the column verify runs and reports every row valid.
    const auto results = schnorr_batch_accessor::evaluate(cancel, b);
    BOOST_REQUIRE_EQUAL(results.size(), 3u);
    BOOST_REQUIRE(results.at(0) != 0);
    BOOST_REQUIRE(results.at(1) != 0);
    BOOST_REQUIRE(results.at(2) != 0);
#else
    (void)cancel;
    (void)b;
#endif
}

BOOST_AUTO_TEST_CASE(secp256k1__schnorr_batch_evaluate__singles_one_tampered__row_rejected)
{
    using namespace system::schnorr;
    constexpr hash_digest auxiliary{};
    const auto hash = bitcoin_hash(to_chunk("batch-schnorr-tampered"));

    std::vector<hash_digest> digests{ hash, hash, hash };

    std::vector<ec_xonly> points
    {
        schnorr_batch_xonly(schnorr_batch_secret0),
        schnorr_batch_xonly(schnorr_batch_secret1),
        schnorr_batch_xonly(schnorr_batch_secret2)
    };

    std::vector<ec_signature> signatures(3);
    BOOST_REQUIRE(sign(signatures.at(0), schnorr_batch_secret0, hash, auxiliary));
    BOOST_REQUIRE(sign(signatures.at(1), schnorr_batch_secret1, hash, auxiliary));
    BOOST_REQUIRE(sign(signatures.at(2), schnorr_batch_secret2, hash, auxiliary));

    // Tamper the third row's signature.
    signatures.at(2)[10] ^= 0xff;

    // Baseline (both build modes): the tampered row is genuinely invalid and the
    // others remain valid at the primitive level.
    BOOST_REQUIRE(verify_signature(points.at(0), hash, signatures.at(0)));
    BOOST_REQUIRE(verify_signature(points.at(1), hash, signatures.at(1)));
    BOOST_REQUIRE(!verify_signature(points.at(2), hash, signatures.at(2)));

    std::vector<batch::correlate_t> correlates
    {
        schnorr_single_row(0),
        schnorr_single_row(1),
        schnorr_single_row(2)
    };

    const batch b
    {
        correlates,
        digests,
        points,
        signatures
    };

    stopper cancel{};

#if defined(HAVE_ULTRAFAST)
    // Engine verdict surface: the column verify detects the tampered row 2.
    // (This is the meaningful HAVE_ULTRAFAST assertion: a real failure verdict
    // from the direct engine, not the stubbed verify()/get_failures path.)
    const auto results = schnorr_batch_accessor::evaluate(cancel, b);
    BOOST_REQUIRE_EQUAL(results.size(), 3u);
    BOOST_REQUIRE(results.at(0) != 0);
    BOOST_REQUIRE(results.at(1) != 0);
    BOOST_REQUIRE(results.at(2) == 0);
#else
    (void)cancel;
    (void)b;
#endif
}

BOOST_AUTO_TEST_SUITE_END()
