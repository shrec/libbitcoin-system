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
// Direct C++ integration: recover.cpp is 100% libsecp256k1-free under
// HAVE_ULTRAFAST. Every recoverable sign/recover path routes through the
// engine's inline C++ API (ufsecp::lbtc::* + secp256k1::fast::Point) — no
// <secp256k1.h>, no <secp256k1_recovery.h>, no libsecp link.
#include <ufsecp/libbitcoin.hpp>
#include <secp256k1/point.hpp>
#include <secp256k1/field.hpp>
#include <secp256k1/field_52.hpp>
#include <cstring>
#else
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include "ec_context.hpp"
#include "serialize.hpp"
#endif
#include <bitcoin/system/hash/hash.hpp>
#include <bitcoin/system/math/math.hpp>

namespace libbitcoin {
namespace system {
namespace ecdsa {

// local
// ----------------------------------------------------------------------------

#if !defined(HAVE_ULTRAFAST)
// OFF (libsecp256k1) path: shared compressed/uncompressed recover helper.
static constexpr auto ec_success = 1;

template <size_t Size>
static bool recover_public(const secp256k1_context* context,
    data_array<Size>& out, const recoverable_signature& recoverable,
    const hash_digest& hash) NOEXCEPT
{
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_recoverable_signature sign;
    const auto recovery_id = sign_cast<int>(recoverable.recovery_id);
    return
        secp256k1_ecdsa_recoverable_signature_parse_compact(context,
            &sign, recoverable.signature.data(), recovery_id) == ec_success &&
        secp256k1_ecdsa_recover(context, &pubkey, &sign, hash.data()) ==
            ec_success && ec_public_key_serialize(context, out, pubkey);
}
#endif

// ECDSA recoverable sign/recover
// ----------------------------------------------------------------------------
// It is recommended to verify a signature after signing.

bool sign_recoverable(recoverable_signature& out, const ec_secret& secret,
    const hash_digest& hash) NOEXCEPT
{
#if defined(HAVE_ULTRAFAST)
    // Direct C++ integration: route recoverable signing through the engine's CT
    // path (ct::ecdsa_sign_recoverable — constant-time wrt private key/nonce).
    // The engine emits a 65-byte compact recoverable signature:
    //   [27 + recid + (compressed?4:0)] [r:32 BE] [s:32 BE]
    // and sets compressed=true, so header = 31 + recid. Bytes [1..65) are the
    // BIG-ENDIAN compact form — exactly what libbitcoin stores in
    // out.signature (the serialize_compact wire form).
    std::uint8_t sig65[65];
    if (!ufsecp::lbtc::ecdsa_sign_recoverable(hash.data(), secret.data(),
        sig65))
        return false;

    int recid = static_cast<int>(sig65[0]) - 27;
    if (recid >= 4)
        recid -= 4;                 // strip the compressed flag

    if (recid < 0 || recid > 3)
        return false;

    // BE compact r||s — matches libbitcoin's stored recoverable form.
    std::memcpy(out.signature.data(), sig65 + 1, 64);
    out.recovery_id = static_cast<uint8_t>(recid);
    return true;
#else
    int recovery_id{};
    const auto context = ec_context_sign::context();
    secp256k1_ecdsa_recoverable_signature signature;

    const auto result =
        secp256k1_ecdsa_sign_recoverable(context, &signature, hash.data(),
            secret.data(), secp256k1_nonce_function_rfc6979, nullptr) ==
            ec_success &&
        secp256k1_ecdsa_recoverable_signature_serialize_compact(context,
            out.signature.data(), &recovery_id, &signature) ==
            ec_success;

    static constexpr auto maximum_recovery_id = 3;
    if (is_negative(recovery_id) || recovery_id > maximum_recovery_id)
        return false;

    out.recovery_id = narrow_sign_cast<uint8_t>(recovery_id);
    return result;
#endif
}

bool recover_public(ec_compressed& out,
    const recoverable_signature& recoverable, const hash_digest& hash) NOEXCEPT
{
#if defined(HAVE_ULTRAFAST)
    // Direct C++ integration: the engine's ecdsa_recover requires the signature
    // in OPAQUE LITTLE-ENDIAN limbs, but recoverable.signature is stored in the
    // BIG-ENDIAN compact wire form. Convert BE compact → opaque LE first
    // (strict: rejects r/s == 0 or >= n), then recover the 33-byte compressed
    // key. Recovery branches only on public data (r, recid).
    std::uint8_t le64[64];
    if (!ufsecp::lbtc::ecdsa_signature_parse_compact(recoverable.signature
        .data(), le64))
        return false;

    return ufsecp::lbtc::ecdsa_recover(hash.data(), le64,
        static_cast<int>(recoverable.recovery_id), out.data());
#else
    const auto context = ec_context_verify::context();
    return recover_public(context, out, recoverable, hash);
#endif
}

bool recover_public(ec_uncompressed& out,
    const recoverable_signature& recoverable, const hash_digest& hash) NOEXCEPT
{
#if defined(HAVE_ULTRAFAST)
    // Direct C++ integration: the engine's ecdsa_recover yields a 33-byte
    // COMPRESSED key (no uncompressed serialize entry point), so we recover
    // compressed then decompress to a fast::Point and emit the 65-byte
    // uncompressed form. Same BE compact → opaque LE conversion as the
    // compressed overload. All branches are on public data (r, recid).
    std::uint8_t le64[64];
    if (!ufsecp::lbtc::ecdsa_signature_parse_compact(recoverable.signature
        .data(), le64))
        return false;

    std::uint8_t pub33[33];
    if (!ufsecp::lbtc::ecdsa_recover(hash.data(), le64,
        static_cast<int>(recoverable.recovery_id), pub33))
        return false;

    // Decompress the 33-byte compressed key to a curve point, then serialize
    // the 65-byte uncompressed encoding (0x04 || X BE || Y BE).
    secp256k1::fast::Point point;
    if (!ufsecp::lbtc::detail::decompress(pub33, point))
        return false;

    const auto uncompressed = point.to_uncompressed();
    std::memcpy(out.data(), uncompressed.data(), uncompressed.size());
    return true;
#else
    const auto context = ec_context_verify::context();
    return recover_public(context, out, recoverable, hash);
#endif
}

} // namespace ecdsa
} // namespace system
} // namespace libbitcoin
