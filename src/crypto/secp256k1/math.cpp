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
#include <bitcoin/system/crypto/secp256k1.hpp>

#include <algorithm>
#if defined(HAVE_ULTRAFAST)
    // Direct C++ integration: every point/scalar op routes through the engine
    // (ufsecp::lbtc::* and the secp256k1::fast C++ API). There is NO libsecp256k1
    // header and NO libsecp link in this mode.
    #include <ufsecp/libbitcoin.hpp>
    #include <secp256k1/scalar.hpp>
    #include <secp256k1/point.hpp>
    #include <secp256k1/field.hpp>
    #include <secp256k1/field_52.hpp>
    #include <vector>
#else
    #include <secp256k1.h>
    #include "ec_context.hpp"
    #include "serialize.hpp"
#endif
#include <bitcoin/system/data/data.hpp>
#include <bitcoin/system/math/math.hpp>

namespace libbitcoin {
namespace system {

#if defined(HAVE_ULTRAFAST)

// local — engine (HAVE_ULTRAFAST) path
// ----------------------------------------------------------------------------
// All point/scalar math routes through the direct engine. Compressed point and
// scalar tweak ops use ufsecp::lbtc::*; the 65-byte uncompressed point ops use
// the engine's secp256k1::fast C++ API directly (decompose the 65-byte affine
// encoding into a fast::Point, apply the op, re-serialize). No libsecp256k1.

namespace {

// Parse a 65-byte uncompressed point (0x04 || X(32) || Y(32), big-endian) into a
// fast::Point. Validates the encoding header, that X and Y are canonical field
// elements (< p), and that (X, Y) lies on the curve (y^2 == x^3 + 7). Returns
// false (point untouched) on any failure.
bool uncompressed_to_point(const std::uint8_t* p65,
    secp256k1::fast::Point& out) NOEXCEPT
{
    using secp256k1::fast::FieldElement;
    using secp256k1::fast::FieldElement52;
    using secp256k1::fast::Point;

    if (p65[0] != 0x04)
        return false;

    FieldElement x;
    FieldElement y;
    if (!FieldElement::parse_bytes_strict(p65 + 1, x))
        return false;
    if (!FieldElement::parse_bytes_strict(p65 + 33, y))
        return false;

    // On-curve check: y^2 == x^3 + 7 (computed in the 5x52 field domain).
    static const std::uint64_t k7[4] = { 7u, 0u, 0u, 0u };
    const FieldElement52 x52 = FieldElement52::from_fe(x);
    const FieldElement52 y52 = FieldElement52::from_fe(y);
    const FieldElement52 rhs = x52.square() * x52 +
        FieldElement52::from_4x64_limbs(k7);
    if (!(y52.square() == rhs))
        return false;

    out = Point::from_affine(x, y);
    return !out.is_infinity();
}

} // namespace

// Add EC values
// ----------------------------------------------------------------------------

bool ec_add(ec_compressed& point, const ec_secret& scalar) NOEXCEPT
{
    // point := point + scalar*G (in place) via the engine.
    return ufsecp::lbtc::pubkey_tweak_add(point.data(), scalar.data());
}

bool ec_add(ec_uncompressed& point, const ec_secret& scalar) NOEXCEPT
{
    // P := P + scalar*G == dual_scalar_mul_gen_point(scalar, 1, P).
    secp256k1::fast::Point P;
    if (!uncompressed_to_point(point.data(), P))
        return false;

    secp256k1::fast::Scalar t;
    if (!secp256k1::fast::Scalar::parse_bytes_strict_nonzero(scalar.data(), t))
        return false;

    const auto result = secp256k1::fast::Point::dual_scalar_mul_gen_point(
        t, secp256k1::fast::Scalar::one(), P);
    if (result.is_infinity())
        return false;

    point = result.to_uncompressed();
    return true;
}

// libbitcoin's ec_scalar treats a secret as a full mod-n field element where 0 is
// a valid addend (x + 0 == x succeeds; see ec_scalar__sum__plus_zero) but 0 is
// not a valid base and a zero result is rejected. We model this with fast::Scalar
// directly (not seckey_tweak_add, which is strict-nonzero on both operands):
//   left  via parse_bytes_strict_nonzero (reject 0 / >= n)
//   right via parse_bytes_strict         (allow 0, reject >= n)
//   r = left + right; reject if r == 0.
// So x+0 succeeds, 0+y fails, x+(-x) fails — matching the libsecp fallback.
bool ec_add(ec_secret& left, const ec_secret& right) NOEXCEPT
{
    secp256k1::fast::Scalar L;
    if (!secp256k1::fast::Scalar::parse_bytes_strict_nonzero(left.data(), L))
        return false;

    secp256k1::fast::Scalar R;
    if (!secp256k1::fast::Scalar::parse_bytes_strict(right.data(), R))
        return false;

    const auto r = L + R;
    if (r.is_zero())
        return false;

    const auto bytes = r.to_bytes();
    std::copy(bytes.begin(), bytes.end(), left.data());
    return true;
}

bool ec_add(ec_compressed& left, const ec_compressed& right) NOEXCEPT
{
    // Delegates to ec_sum, which routes through the engine.
    return ec_sum(left, { left, right });
}

bool ec_add(ec_compressed& left, const ec_uncompressed& right) NOEXCEPT
{
    // compress(right) is engine-backed in this mode (keys.cpp), then the
    // compressed/compressed delegation routes through ec_sum.
    ec_compressed out;
    return compress(out, right) && ec_add(left, out);
}

bool ec_sum(ec_compressed& out, const ec_compresseds& points) NOEXCEPT
{
    if (points.empty())
        return false;

    // Point combine (P1 + P2 + ... + Pn) via the engine.
    std::vector<const std::uint8_t*> ptrs;
    ptrs.reserve(points.size());
    for (const auto& p: points)
        ptrs.push_back(p.data());

    return ufsecp::lbtc::pubkey_combine(ptrs.data(), points.size(), out.data());
}

// Multiply EC values
// ----------------------------------------------------------------------------

bool ec_multiply(ec_compressed& point, const ec_secret& scalar) NOEXCEPT
{
    // point := point * scalar (in place) via the engine.
    return ufsecp::lbtc::pubkey_tweak_mul(point.data(), scalar.data());
}

bool ec_multiply(ec_uncompressed& point, const ec_secret& scalar) NOEXCEPT
{
    // P := P * scalar via the engine.
    secp256k1::fast::Point P;
    if (!uncompressed_to_point(point.data(), P))
        return false;

    secp256k1::fast::Scalar t;
    if (!secp256k1::fast::Scalar::parse_bytes_strict_nonzero(scalar.data(), t))
        return false;

    const auto result = P.scalar_mul(t);
    if (result.is_infinity())
        return false;

    point = result.to_uncompressed();
    return true;
}

bool ec_multiply(ec_secret& left, const ec_secret& right) NOEXCEPT
{
    // CT modular scalar mul (left = left * right mod n) via the engine.
    return ufsecp::lbtc::seckey_tweak_mul(left.data(), right.data());
}

// Negate EC values
// ----------------------------------------------------------------------------

// Negate a secret scalar (scalar = n - scalar mod n). Matches libsecp256k1's
// secp256k1_ec_seckey_negate, which REJECTS a zero (and out-of-range) input —
// so we parse with parse_bytes_strict_nonzero. (libbitcoin's ec_scalar models
// subtraction-by-zero as an identity at the ec_scalar layer, not by negating a
// zero secret here.) Modelled with the engine's mod-n fast::Scalar so behavior
// is byte-identical to the OFF/libsecp path.
bool ec_negate(ec_secret& scalar) NOEXCEPT
{
    secp256k1::fast::Scalar s;
    if (!secp256k1::fast::Scalar::parse_bytes_strict_nonzero(scalar.data(), s))
        return false;

    const auto n = s.negate();
    const auto bytes = n.to_bytes();
    std::copy(bytes.begin(), bytes.end(), scalar.data());
    return true;
}

bool ec_negate(ec_compressed& point) NOEXCEPT
{
    // point := -point (in place): (x, y) -> (x, -y) via the engine.
    return ufsecp::lbtc::pubkey_negate(point.data());
}

bool ec_negate(ec_uncompressed& point) NOEXCEPT
{
    // P := -P via the engine.
    secp256k1::fast::Point P;
    if (!uncompressed_to_point(point.data(), P))
        return false;

    const auto result = P.negate();
    if (result.is_infinity())
        return false;

    point = result.to_uncompressed();
    return true;
}

#else // !HAVE_ULTRAFAST

// local — libsecp256k1 (fallback) path
// ----------------------------------------------------------------------------
// These static helpers and overloads exist ONLY for the libsecp256k1 C-API path;
// they are compiled out entirely when HAVE_ULTRAFAST is defined (so they never
// appear as unused in the engine build).

static constexpr auto ec_success = 1;

// Create an array of secp256k1_pubkey pointers for secp256k1 call.
static std::vector<const secp256k1_pubkey*> to_secp256k1_pubkey_pointers(
    const std::vector<secp256k1_pubkey>& keys) NOEXCEPT
{
    std::vector<const secp256k1_pubkey*> pointers(keys.size());
    std::transform(keys.begin(), keys.end(), pointers.begin(),
        [](const secp256k1_pubkey& point) NOEXCEPT
        {
            return &point;
        });

    return pointers;
}

static bool ec_public_keys_parse(const secp256k1_context* context,
    std::vector<secp256k1_pubkey>& out, const ec_compresseds& points) NOEXCEPT
{
    out.resize(points.size());
    auto key = out.begin();

    for (const auto& point: points)
        if (!ec_public_key_parse(context, *key++, point))
            return false;

    return true;
}

template <size_t Size>
static bool ec_add(const secp256k1_context* context, data_array<Size>& in_out,
    const ec_secret& secret) NOEXCEPT
{
    secp256k1_pubkey pubkey;
    return ec_public_key_parse(context, pubkey, in_out) &&
        secp256k1_ec_pubkey_tweak_add(context, &pubkey, secret.data()) ==
        ec_success && ec_public_key_serialize(context, in_out, pubkey);
}

template <size_t Size>
static bool ec_multiply(const secp256k1_context* context,
    data_array<Size>& in_out, const ec_secret& secret) NOEXCEPT
{
    secp256k1_pubkey pubkey;
    return ec_public_key_parse(context, pubkey, in_out) &&
        secp256k1_ec_pubkey_tweak_mul(context, &pubkey, secret.data()) ==
        ec_success && ec_public_key_serialize(context, in_out, pubkey);
}

template <size_t Size>
static bool ec_negate(const secp256k1_context* context,
    data_array<Size>& in_out) NOEXCEPT
{
    secp256k1_pubkey pubkey;
    return ec_public_key_parse(context, pubkey, in_out) &&
        secp256k1_ec_pubkey_negate(context, &pubkey) == ec_success &&
        ec_public_key_serialize(context, in_out, pubkey);
}

// Add EC values
// ----------------------------------------------------------------------------

bool ec_add(ec_compressed& point, const ec_secret& scalar) NOEXCEPT
{
    const auto context = ec_context_verify::context();
    return ec_add(context, point, scalar);
}

bool ec_add(ec_uncompressed& point, const ec_secret& scalar) NOEXCEPT
{
    const auto context = ec_context_verify::context();
    return ec_add(context, point, scalar);
}

bool ec_add(ec_secret& left, const ec_secret& right) NOEXCEPT
{
    const auto context = ec_context_verify::context();
    return secp256k1_ec_seckey_tweak_add(context, left.data(), right.data())
        == ec_success;
}

bool ec_add(ec_compressed& left, const ec_compressed& right) NOEXCEPT
{
    return ec_sum(left, { left, right });
}

bool ec_add(ec_compressed& left, const ec_uncompressed& right) NOEXCEPT
{
    ec_compressed out;
    return compress(out, right) && ec_add(left, out);
}

bool ec_sum(ec_compressed& out, const ec_compresseds& points) NOEXCEPT
{
    if (points.empty())
        return false;

    const auto context = ec_context_verify::context();

    std::vector<secp256k1_pubkey> keys;
    if (!ec_public_keys_parse(context, keys, points))
        return false;

    secp256k1_pubkey pubkey;
    return secp256k1_ec_pubkey_combine(context, &pubkey,
        to_secp256k1_pubkey_pointers(keys).data(), points.size()) ==
            ec_success && ec_public_key_serialize(context, out, pubkey);
}

// Multiply EC values
// ----------------------------------------------------------------------------

bool ec_multiply(ec_compressed& point, const ec_secret& scalar) NOEXCEPT
{
    const auto context = ec_context_verify::context();
    return ec_multiply(context, point, scalar);
}

bool ec_multiply(ec_uncompressed& point, const ec_secret& scalar) NOEXCEPT
{
    const auto context = ec_context_verify::context();
    return ec_multiply(context, point, scalar);
}

bool ec_multiply(ec_secret& left, const ec_secret& right) NOEXCEPT
{
    const auto context = ec_context_verify::context();
    return secp256k1_ec_seckey_tweak_mul(context, left.data(), right.data()) ==
        ec_success;
}

// Negate EC values
// ----------------------------------------------------------------------------

bool ec_negate(ec_secret& scalar) NOEXCEPT
{
    const auto context = ec_context_verify::context();
    return secp256k1_ec_seckey_negate(context, scalar.data()) == ec_success;
}

bool ec_negate(ec_compressed& point) NOEXCEPT
{
    const auto context = ec_context_verify::context();
    return ec_negate(context, point);
}

bool ec_negate(ec_uncompressed& point) NOEXCEPT
{
    const auto context = ec_context_verify::context();
    return ec_negate(context, point);
}

#endif // HAVE_ULTRAFAST

} // namespace system
} // namespace libbitcoin
