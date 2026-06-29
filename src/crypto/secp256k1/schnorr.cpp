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
    // Direct C++ integration: route every Schnorr/Taproot operation through the
    // UltrafastSecp256k1 engine inline. In this mode libsecp256k1 is NOT linked
    // and <secp256k1.h>/<secp256k1_schnorrsig.h> are NOT included — this file
    // is 100% libsecp-free so the single-package ON build needs no libsecp.
    #include <ufsecp/libbitcoin.hpp>
    #include <secp256k1/point.hpp>
    #include <secp256k1/scalar.hpp>
    #include <secp256k1/field.hpp>
    #include <secp256k1/field_52.hpp>
    #include <secp256k1/taproot.hpp>
    #include <cstdint>
    #include <cstring>
#else
    #include <secp256k1.h>
    #include <secp256k1_schnorrsig.h>
    #include "ec_context.hpp"
    #include "serialize.hpp"
#endif
#include <bitcoin/system/data/data.hpp>
#include <bitcoin/system/hash/hash.hpp>
#include <bitcoin/system/math/math.hpp>

namespace libbitcoin {
namespace system {
namespace schnorr {

#if !defined(HAVE_ULTRAFAST)
static constexpr auto ec_success = 1;
#endif

// Schnorr parse/sign/verify
// ----------------------------------------------------------------------------
// `ec_signature` is a public format for schnorr.

// It is recommended to verify a signature after signing.
bool sign(ec_signature& out, const ec_secret& secret,
    const hash_digest& hash, const hash_digest& auxiliary) NOEXCEPT
{
#if defined(HAVE_ULTRAFAST)
    // Direct engine signing. The engine signs against a verified x-only pubkey
    // derived from the secret (ct::* internally). Both libsecp and the engine
    // are BIP-340 deterministic given the same aux, so the produced 64-byte
    // signature (R.x BE || s BE) is byte-identical to the libsecp fallback.
    std::uint8_t xonly[32];
    if (!ufsecp::lbtc::schnorr_keypair_create(secret.data(), xonly))
        return false;

    return ufsecp::lbtc::schnorr_sign(xonly, secret.data(), hash.data(),
        auxiliary.data(), out.data());
#else
    secp256k1_keypair keypair;
    const auto context = ec_context_sign::context();

    return
        secp256k1_keypair_create(context, &keypair, secret.data()) ==
            ec_success &&
        secp256k1_schnorrsig_sign32(context, out.data(), hash.data(), &keypair,
            auxiliary.data()) == ec_success;
#endif
}

// BIP341: A Taproot signature is a 64-byte Schnorr sig, as defined in BIP340.
bool verify_signature(const data_chunk& x_point, const hash_digest& hash,
    const ec_signature& signature) NOEXCEPT
{
    constexpr auto size = ec_xonly_size;
    if (x_point.size() != size)
        return false;

    const auto& public_key = unsafe_array_cast<uint8_t, size>(x_point.data());
    return verify_signature(public_key, hash, signature);
}

// BIP341: A Taproot signature is a 64-byte Schnorr sig, as defined in BIP340.
bool verify_signature(const ec_xonly& x_point, const hash_digest& hash,
    const ec_signature& signature) NOEXCEPT
{
#if defined(HAVE_ULTRAFAST)
    return ufsecp::lbtc::schnorr_verify(x_point.data(), hash.data(),
        signature.data());
#else
    secp256k1_xonly_pubkey pubkey;
    const auto context = ec_context_verify::context();

    return
        secp256k1_xonly_pubkey_parse(context, &pubkey, x_point.data()) ==
            ec_success &&
        secp256k1_schnorrsig_verify(context, signature.data(), hash.data(),
            hash_size, &pubkey) == ec_success;
#endif
}

// BIP341: If q != x(Q) or c[0] & 1 != y(Q) mod 2, fail.
bool verify_commitment(const ec_xonly& internal_key, const hash_digest& tweak,
    const ec_xonly& tweaked_key, bool tweaked_key_parity) NOEXCEPT
{
#if defined(HAVE_ULTRAFAST)
    // Direct engine taproot tweak-add-check with a PRE-COMPUTED 32-byte tweak
    // scalar (libbitcoin computes H_TapTweak upstream and hands us the raw
    // scalar). The engine's secp256k1::taproot_verify_commitment /
    // ufsecp::lbtc::taproot_tweak_add_check recompute t = H_TapTweak(P||root)
    // internally, so they are NOT usable here — we implement the raw-scalar
    // check directly with the fast::Point API:
    //
    //   1. lift_x: the x-only internal key P implies an even-Y point. We build
    //      the 33-byte compressed encoding (0x02 || X) and reuse the engine's
    //      detail::decompress (parse X, y = sqrt(x^3+7), even-Y branch).
    //   2. parse the tweak t with Scalar::parse_bytes_strict (reject t >= n;
    //      t == 0 is accepted, matching BIP-341 / libsecp tweak_add_check).
    //   3. Q' = dual_scalar_mul_gen_point(t, 1, P) = t*G + 1*P = P + t*G.
    //   4. accept iff !Q'.is_infinity() AND Q'.x == tweaked_key AND
    //      (Q' has odd Y) == tweaked_key_parity.
    using secp256k1::fast::Point;
    using secp256k1::fast::Scalar;

    std::uint8_t compressed[ec_compressed_size];
    compressed[0] = ec_even_sign;                  // x-only implies even Y
    std::memcpy(&compressed[1], internal_key.data(), ec_xonly_size);

    Point internal{};
    if (!ufsecp::lbtc::detail::decompress(compressed, internal))
        return false;

    Scalar t;
    if (!Scalar::parse_bytes_strict(tweak.data(), t))
        return false;

    const auto output = Point::dual_scalar_mul_gen_point(t, Scalar::one(),
        internal);
    if (output.is_infinity())
        return false;

    const auto [x_bytes, y_is_odd] = output.x_bytes_and_parity();
    return y_is_odd == tweaked_key_parity &&
        std::memcmp(x_bytes.data(), tweaked_key.data(), ec_xonly_size) == 0;
#else
    secp256k1_xonly_pubkey pubkey;
    const auto context = ec_context_verify::context();
    const auto parity = to_int(tweaked_key_parity);

    return
        secp256k1_xonly_pubkey_parse(context, &pubkey, internal_key.data()) ==
            ec_success &&
        secp256k1_xonly_pubkey_tweak_add_check(context, tweaked_key.data(),
            parity, &pubkey, tweak.data()) == ec_success;
#endif
}

} // namespace schnorr
} // namespace system
} // namespace libbitcoin
