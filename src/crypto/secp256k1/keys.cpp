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

#if defined(HAVE_ULTRAFAST)
    // Direct C++ integration: every key op is implemented against the engine's
    // native C++ API (ufsecp::lbtc::* and secp256k1::fast::*). No <secp256k1.h>,
    // no libsecp256k1 C-API, no shim/bridge/C-ABI. This translation unit is
    // 100% libsecp256k1-free in this build mode.
    #include <ufsecp/libbitcoin.hpp>
    #include <secp256k1/point.hpp>
    #include <secp256k1/field.hpp>
#else
    #include <secp256k1.h>
    #include "ec_context.hpp"
    #include "serialize.hpp"
#endif
#include <bitcoin/system/data/data.hpp>
#include <bitcoin/system/hash/hash.hpp>

namespace libbitcoin {
namespace system {

// local
// ----------------------------------------------------------------------------

#if defined(HAVE_ULTRAFAST)

// Parse a 65-byte uncompressed public key (0x04 || X big-endian || Y big-endian)
// into a curve point using only the engine's C++ field/point primitives.
// from_affine() does NOT validate the on-curve relation, so we verify
// y^2 == x^3 + 7 (mod p) explicitly and reject the point at infinity.
static bool uncompressed_to_point(const data_slice& point,
    secp256k1::fast::Point& out) NOEXCEPT
{
    using secp256k1::fast::FieldElement;
    using secp256k1::fast::Point;

    if (point.size() != ec_uncompressed_size ||
        point.front() != ec_uncompressed_sign)
        return false;

    FieldElement x, y;
    if (!FieldElement::parse_bytes_strict(point.data() + 1u, x))
        return false;
    if (!FieldElement::parse_bytes_strict(point.data() + 1u + 32u, y))
        return false;

    // On-curve check: y^2 == x^3 + 7 (mod p).
    const auto seven = FieldElement::from_uint64(7u);
    const auto lhs = y.square();
    const auto rhs = x.square() * x + seven;
    if (!(lhs == rhs))
        return false;

    out = Point::from_affine(x, y);
    return !out.is_infinity();
}

#else // !HAVE_ULTRAFAST

static constexpr auto ec_success = 1;

template <size_t Size>
static bool secret_to_public(const secp256k1_context* context,
    data_array<Size>& out, const ec_secret& secret) NOEXCEPT
{
    secp256k1_pubkey pubkey;
    return secp256k1_ec_pubkey_create(context, &pubkey, secret.data()) ==
        ec_success && ec_public_key_serialize(context, out, pubkey);
}

#endif // HAVE_ULTRAFAST

// Convert keys
// ----------------------------------------------------------------------------

bool compress(ec_compressed& out, const ec_uncompressed& point) NOEXCEPT
{
#if defined(HAVE_ULTRAFAST)
    // Parse the uncompressed point via the engine, re-serialize compressed.
    secp256k1::fast::Point P;
    if (!uncompressed_to_point(point, P))
        return false;
    const auto compressed = P.to_compressed();
    std::copy(compressed.begin(), compressed.end(), out.begin());
    return true;
#else
    secp256k1_pubkey pubkey;
    const auto context = ec_context_verify::context();
    return ec_public_key_parse(context, pubkey, point) &&
        ec_public_key_serialize(context, out, pubkey);
#endif
}

bool decompress(ec_uncompressed& out, const ec_compressed& point) NOEXCEPT
{
#if defined(HAVE_ULTRAFAST)
    // Decompress the 33-byte compressed key to a point, then serialize 65-byte.
    secp256k1::fast::Point P;
    if (!ufsecp::lbtc::detail::decompress(point.data(), P))
        return false;
    const auto uncompressed = P.to_uncompressed();
    std::copy(uncompressed.begin(), uncompressed.end(), out.begin());
    return true;
#else
    secp256k1_pubkey pubkey;
    const auto context = ec_context_verify::context();
    return ec_public_key_parse(context, pubkey, point) &&
        ec_public_key_serialize(context, out, pubkey);
#endif
}

bool secret_to_public(ec_compressed& out, const ec_secret& secret) NOEXCEPT
{
#if defined(HAVE_ULTRAFAST)
    // Direct C++ integration: derive the compressed pubkey through the engine's
    // CT path (ct::generator_mul_blinded internally — constant-time wrt secret).
    return ufsecp::lbtc::pubkey_create(secret.data(), out.data());
#else
    const auto context = ec_context_sign::context();
    return secret_to_public(context, out, secret);
#endif
}

bool secret_to_public(ec_uncompressed& out, const ec_secret& secret) NOEXCEPT
{
#if defined(HAVE_ULTRAFAST)
    // Derive the compressed pubkey via the engine's CT path, decompress it to a
    // full point, then serialize the 65-byte uncompressed form.
    ec_compressed compressed;
    if (!ufsecp::lbtc::pubkey_create(secret.data(), compressed.data()))
        return false;
    secp256k1::fast::Point P;
    if (!ufsecp::lbtc::detail::decompress(compressed.data(), P))
        return false;
    const auto uncompressed = P.to_uncompressed();
    std::copy(uncompressed.begin(), uncompressed.end(), out.begin());
    return true;
#else
    const auto context = ec_context_sign::context();
    return secret_to_public(context, out, secret);
#endif
}

// Verify keys
// ----------------------------------------------------------------------------

bool verify_secret(const ec_secret& secret) NOEXCEPT
{
#if defined(HAVE_ULTRAFAST)
    // Direct C++ integration: strict 0 < sk < n check through the engine.
    return ufsecp::lbtc::seckey_verify(secret.data());
#else
    const auto context = ec_context_verify::context();
    return secp256k1_ec_seckey_verify(context, secret.data()) == ec_success;
#endif
}

bool verify_point(const data_slice& point) NOEXCEPT
{
#if defined(HAVE_ULTRAFAST)
    // Compressed (33-byte, 0x02/0x03) → engine compressed parse.
    // Uncompressed (65-byte, 0x04) → engine field/point on-curve parse.
    const auto size = point.size();
    if (size == ec_compressed_size &&
        (point.front() == ec_even_sign || point.front() == ec_odd_sign))
        return ufsecp::lbtc::pubkey_parse(point.data());

    if (size == ec_uncompressed_size &&
        point.front() == ec_uncompressed_sign)
    {
        secp256k1::fast::Point P;
        return uncompressed_to_point(point, P);
    }

    return false;
#else
    secp256k1_pubkey pubkey;
    const auto context = ec_context_verify::context();
    return ec_public_key_parse(context, pubkey, point);
#endif
}

// Detect public keys
// ----------------------------------------------------------------------------

bool is_even_key(const ec_compressed& point) NOEXCEPT
{
    return point.front() == ec_even_sign;
}

bool is_compressed_key(const data_slice& point) NOEXCEPT
{
    const auto size = point.size();
    if (size != ec_compressed_size)
        return false;

    const auto first = point.front();
    return first == ec_even_sign || first == ec_odd_sign;
}

bool is_uncompressed_key(const data_slice& point) NOEXCEPT
{
    const auto size = point.size();
    if (size != ec_uncompressed_size)
        return false;

    const auto first = point.front();
    return first == ec_uncompressed_sign;
}

bool is_hybrid_key(const data_slice& point) NOEXCEPT
{
    const auto size = point.size();
    if (size != ec_uncompressed_size)
        return false;

    const auto first = point.front();
    return first == ec_hybrid_even_sign || first == ec_hybrid_odd_sign;
}

bool is_public_key(const data_slice& point) NOEXCEPT
{
    return is_compressed_key(point) || is_uncompressed_key(point);
}

bool is_endorsement(const endorsement& endorsement) NOEXCEPT
{
    const auto size = endorsement.size();
    return size >= min_endorsement_size && size <= max_endorsement_size;
}

} // namespace system
} // namespace libbitcoin
