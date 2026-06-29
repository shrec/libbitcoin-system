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
    // Single-package direct integration: every ECDSA op routes through the engine
    // (ufsecp::lbtc::* + the secp256k1::fast C++ API). There is NO <secp256k1.h>
    // and NO libsecp256k1 link in this mode. The engine exposes no DER parser
    // (missing entrypoint), so decode_signature uses an inline pure-C++ lax DER
    // parser here — no libsecp256k1, no shim — and src/crypto/der_parser.cpp is
    // excluded from the ON build by CMake.
    #include <ufsecp/libbitcoin.hpp>
    #include <secp256k1/point.hpp>
    #include <secp256k1/field.hpp>
    #include <secp256k1/field_52.hpp>
    #include <cstdint>
    #include <cstring>
#else
    #include <secp256k1.h>
    #include <bitcoin/system/crypto/der_parser.hpp>
    #include "ec_context.hpp"
    #include "serialize.hpp"
#endif
#include <bitcoin/system/data/data.hpp>
#include <bitcoin/system/hash/hash.hpp>
#include <bitcoin/system/math/math.hpp>

namespace libbitcoin {
namespace system {
namespace ecdsa {

#if defined(HAVE_ULTRAFAST)

// local — engine (HAVE_ULTRAFAST) path
// ----------------------------------------------------------------------------
// `ec_signature` is byte-identical to the engine's opaque little-endian sig64
// (r limbs LE || s limbs LE). All ops below use only ufsecp::lbtc::* and the
// secp256k1::fast C++ API. No libsecp256k1.

namespace {

// Parse a 65-byte uncompressed point (0x04 || X(32) || Y(32), big-endian) into a
// fast::Point. Validates the header, that X/Y are canonical (< p), and that
// (X, Y) is on the curve (y^2 == x^3 + 7). Returns false (point untouched) on
// any failure.
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

// Strict BIP66 DER encoding check (no sighash byte). Inlined here because the
// canonical definition lives in src/crypto/der_parser.cpp, which is excluded
// from the single-package ON build. Logic is identical to libbitcoin's
// is_valid_bip66_signature_encoding.
bool der_bip66_valid(const data_slice& sig) NOEXCEPT
{
    if (sig.size() < 8u) return false;
    if (sig.size() > 72u) return false;
    if (sig[0] != 0x30u) return false;
    if (sig[1] != sig.size() - 2u) return false;

    const size_t lenR = sig[3];
    if (5u + lenR >= sig.size()) return false;

    const size_t lenS = sig[5u + lenR];
    if (lenR + lenS + 6u != sig.size()) return false;

    if (sig[2] != 0x02u) return false;
    if (lenR == 0u) return false;
    if (sig[4u] & 0x80u) return false;
    if (lenR > 1u && sig[4u] == 0x00u && !(sig[5u] & 0x80u)) return false;

    if (sig[4u + lenR] != 0x02u) return false;
    if (lenS == 0u) return false;
    if (sig[6u + lenR] & 0x80u) return false;
    if (lenS > 1u && sig[6u + lenR] == 0x00u && !(sig[7u + lenR] & 0x80u))
        return false;

    return true;
}

// Parse a "lax DER" signature into a 64-byte BIG-ENDIAN compact buffer
// (r BE || s BE). Returns false on structural error; on integer overflow
// (R or S longer than 32 bytes) the whole buffer is zeroed (the caller maps a
// zero component to a guaranteed-invalid signature, matching the lax contract:
// validation with the result is guaranteed to fail). Ported from Pieter
// Wuille's lax parser with the libsecp256k1 calls removed — the output is the
// raw BE compact buffer, converted to the engine's opaque form by the caller.
bool der_parse_lax_be(const std::uint8_t* input, std::size_t inputlen,
    std::uint8_t out_be64[64]) NOEXCEPT
{
    std::memset(out_be64, 0, 64);

    std::size_t rpos, rlen, spos, slen;
    std::size_t pos = 0;
    std::size_t lenbyte;
    bool overflow = false;

    // Sequence tag byte.
    if (pos == inputlen || input[pos] != 0x30)
        return false;

    // Sequence length bytes.
    if (++pos == inputlen)
        return false;

    lenbyte = input[pos++];
    if (lenbyte & 0x80u)
    {
        lenbyte -= 0x80u;
        if (lenbyte > inputlen - pos)
            return false;

        pos += lenbyte;
    }

    // Integer tag byte for R.
    if (pos == inputlen || input[pos] != 0x02)
        return false;

    pos++;

    // Integer length for R.
    if (pos == inputlen)
        return false;

    lenbyte = input[pos++];
    if (lenbyte & 0x80u)
    {
        lenbyte -= 0x80u;
        if (lenbyte > inputlen - pos)
            return false;

        while (lenbyte > 0 && input[pos] == 0) { pos++; lenbyte--; }
        if (lenbyte >= sizeof(std::size_t))
            return false;

        rlen = 0;
        while (lenbyte > 0) { rlen = (rlen << 8) + input[pos]; pos++; lenbyte--; }
    }
    else
    {
        rlen = lenbyte;
    }

    if (rlen > inputlen - pos)
        return false;

    rpos = pos;
    pos += rlen;

    // Integer tag byte for S.
    if (pos == inputlen || input[pos] != 0x02)
        return false;

    pos++;

    // Integer length for S.
    if (pos == inputlen)
        return false;

    lenbyte = input[pos++];
    if (lenbyte & 0x80u)
    {
        lenbyte -= 0x80u;
        if (lenbyte > inputlen - pos)
            return false;

        while (lenbyte > 0 && input[pos] == 0) { pos++; lenbyte--; }
        if (lenbyte >= sizeof(std::size_t))
            return false;

        slen = 0;
        while (lenbyte > 0) { slen = (slen << 8) + input[pos]; pos++; lenbyte--; }
    }
    else
    {
        slen = lenbyte;
    }

    if (slen > inputlen - pos)
        return false;

    spos = pos;

    // Ignore leading zeroes in R.
    while (rlen > 0 && input[rpos] == 0) { rlen--; rpos++; }
    if (rlen > 32)
        overflow = true;
    else
        std::memcpy(out_be64 + 32 - rlen, input + rpos, rlen);

    // Ignore leading zeroes in S.
    while (slen > 0 && input[spos] == 0) { slen--; spos++; }
    if (slen > 32)
        overflow = true;
    else
        std::memcpy(out_be64 + 64 - slen, input + spos, slen);

    if (overflow)
        std::memset(out_be64, 0, 64);

    return true;
}

} // namespace

// ECDSA parse/encode
// ----------------------------------------------------------------------------

bool encode_signature(der_signature& out, const ec_signature& signature) NOEXCEPT
{
    // Serialize DER through the engine. ec_signature is byte-identical to the
    // engine's opaque LE sig64; max DER size is 72.
    out.resize(72);
    std::size_t len = 0;
    if (!ufsecp::lbtc::ecdsa_signature_serialize_der(signature.data(),
        out.data(), len))
        return false;

    out.resize(len);
    return true;
}

bool decode_signature(ec_signature& out, const data_slice& der_signature,
    bool strict) NOEXCEPT
{
    std::memset(out.data(), 0, ec_signature_size);

    // BIP66: strict parse is not called for when signature is empty.
    if (der_signature.empty())
        return false;

    // BIP66: requires a specific (non-standard) DER signature encoding.
    if (strict && !der_bip66_valid(der_signature))
        return false;

    // ************************************************************************
    // CONSENSUS: This function parses DER with various errors as allowed by
    // Bitcoin prior to activation of BIP66, codifying the lax rules applied by
    // version(s) of OpenSSL in use up to that time. The engine exposes no DER
    // parser (missing entrypoint), so this is an inline pure-C++ lax parser —
    // no libsecp256k1, no shim. Out-of-range/overflow values yield a
    // guaranteed-invalid signature, never a spuriously valid one.
    // ************************************************************************
    std::uint8_t be64[64];
    if (!der_parse_lax_be(der_signature.data(), der_signature.size(), be64))
        return false;

    // Convert BE compact -> opaque LE (strict: rejects r/s >= n or == 0). On
    // rejection ecdsa_signature_parse_compact zeroes out (guaranteed-invalid),
    // and we still report a successful structural parse (lax contract).
    if (!ufsecp::lbtc::ecdsa_signature_parse_compact(be64, out.data()))
        std::memset(out.data(), 0, ec_signature_size);

    return true;
}

// Return indicates modified, not success/fail. Engine normalizes in place and
// returns true iff the signature was modified (high-S -> low-S).
bool normalize_signature(ec_signature& out, const ec_signature& in) NOEXCEPT
{
    out = in;
    return ufsecp::lbtc::ecdsa_signature_normalize(out.data());
}

// Convert to low-s big-endian canonical (compact) signature.
bool canonicalize_signature(ec_signature& out, const ec_signature& in) NOEXCEPT
{
    ec_signature tmp = in;
    // Normalize to low-S (return value intentionally discarded — we only need
    // the normalized form for serialization).
    (void)ufsecp::lbtc::ecdsa_signature_normalize(tmp.data());
    ufsecp::lbtc::ecdsa_signature_serialize_compact(tmp.data(), out.data());
    return true;
}

// ECDSA sign/verify signature
// ----------------------------------------------------------------------------
// It is recommended to verify a signature after signing.

// Produces low-s private form (opaque LE r||s limbs), usable in verify.
bool sign(ec_signature& out, const ec_secret& secret,
    const hash_digest& hash) NOEXCEPT
{
    // Route signing through the engine's CT ECDSA path (ct::ecdsa_sign
    // internally — constant-time wrt private key and nonce). Both libbitcoin and
    // the engine use RFC6979, so output is byte-identical.
    return ufsecp::lbtc::ecdsa_sign(hash.data(), secret.data(), out.data());
}

bool verify_signature(const data_chunk& point, const hash_digest& hash,
    const ec_signature& signature) NOEXCEPT
{
    // Engine verify accepts both low-S and high-S (no pre-normalize needed).
    if (point.size() == ec_compressed_size &&
        (point.front() == ec_even_sign || point.front() == ec_odd_sign))
        return ufsecp::lbtc::ecdsa_verify(point.data(), hash.data(),
            signature.data());

    if (point.size() == ec_uncompressed_size)
    {
        secp256k1::fast::Point P;
        if (!uncompressed_to_point(point.data(), P))
            return false;

        const auto compressed = P.to_compressed();
        return ufsecp::lbtc::ecdsa_verify(compressed.data(), hash.data(),
            signature.data());
    }

    return false;
}

bool verify_signature(const ec_compressed& compressed,
    const hash_digest& hash, const ec_signature& signature) NOEXCEPT
{
    return ufsecp::lbtc::ecdsa_verify(compressed.data(), hash.data(),
        signature.data());
}

#else // !HAVE_ULTRAFAST — libsecp256k1 fallback

// local
// ----------------------------------------------------------------------------
// `ec_signature` is an alias for secp256k1_ecdsa_signature (private format).
// The output of ecdsa_signature_parse_der_lax (via decode_signature) is in a
// fixed-width (64 byte) form but is not in a standard/public form. The output
// of secp256k1_ecdsa_signature_normalize (in verify_signature) is also in a
// private format.

static constexpr auto ec_success = 1;

// Return indicates modified, not success/fail.
// BIP62 required low-s signatures, but that is not active.
// secp256k1_ecdsa_verify rejects non-normalized (low-s) signatures, but
// bitcoin does not have such a limitation, so we always normalize.
// This normalization produces secp256k1_ecdsa_signature (private format).
static bool normalize_signature(const secp256k1_context* context,
    ec_signature& out, const ec_signature& in) NOEXCEPT
{
    static constexpr auto modified = 1;

    // Return indicates modified, not success/fail.
    return secp256k1_ecdsa_signature_normalize(context,
        pointer_cast<secp256k1_ecdsa_signature>(out.data()),
            pointer_cast<const secp256k1_ecdsa_signature>(in.data()))
                == modified;
}

// ec_signature is an alias for secp256k1_ecdsa_signature (private format).
static bool verify_signature(const secp256k1_context* context,
    const secp256k1_pubkey& point, const hash_digest& hash,
    const ec_signature& signature) NOEXCEPT
{
    ec_signature normal;
    /* bool */ normalize_signature(context, normal, signature);

    return secp256k1_ecdsa_verify(context,
        pointer_cast<secp256k1_ecdsa_signature>(normal.data()),
            hash.data(), &point) == ec_success;
}

// ECDSA parse/encode
// ----------------------------------------------------------------------------

// ec_signature is an alias for secp256k1_ecdsa_signature (private format).
bool encode_signature(der_signature& out,
    const ec_signature& signature) NOEXCEPT
{
    const auto sign = pointer_cast<const secp256k1_ecdsa_signature>(
        signature.data());

    const auto context = ec_context_sign::context();
    auto size = max_der_signature_size;
    out.resize(size);

    if (secp256k1_ecdsa_signature_serialize_der(context, out.data(), &size,
        sign) != ec_success)
        return false;

    out.resize(size);
    return true;
}

// ec_signature is an alias for secp256k1_ecdsa_signature (private format).
bool decode_signature(ec_signature& out, const data_slice& der_signature,
    bool strict) NOEXCEPT
{
    // BIP66: strict parse is not called for when signature is empty.
    if (der_signature.empty())
        return false;

    // BIP66: requires a specific (non-standard) DER signature encoding.
    if (strict && !is_valid_bip66_signature_encoding(der_signature))
        return false;

    const auto context = ec_context_verify::context();
    auto parsed = pointer_cast<secp256k1_ecdsa_signature>(out.data());

    // ************************************************************************
    // CONSENSUS: This function parses DER with various errors as allowed by
    // Bitcoin prior to activation of BIP66. This attempts to codify the lax
    // rules applied by version(s) of OpenSSL in use up to that time.
    // ************************************************************************
    return ecdsa_signature_parse_der_lax(context, parsed, der_signature.data(),
        der_signature.size());
}

// Return indicates modified, not success/fail.
// Convert a secp256k1_ecdsa_signature to low-s secp256k1_ecdsa_signature.
bool normalize_signature(ec_signature& out, const ec_signature& in) NOEXCEPT
{
    const auto context = ec_context_sign::context();
    return normalize_signature(context, out, in) == ec_success;
}

// Convert a secp256k1_ecdsa_signature to low-s big-endian canonical signature.
bool canonicalize_signature(ec_signature& out, const ec_signature& in) NOEXCEPT
{
    const auto context = ec_context_sign::context();

    ec_signature normal;
    /* bool */ normalize_signature(context, normal, in);

    return secp256k1_ecdsa_signature_serialize_compact(context, out.data(),
        pointer_cast<secp256k1_ecdsa_signature>(normal.data()))
            == ec_success;
}

// ECDSA sign/verify signature
// ----------------------------------------------------------------------------
// It is recommended to verify a signature after signing.

// Produces low-s private form `secp256k1_ecdsa_signature` (usable in verify).
bool sign(ec_signature& out, const ec_secret& secret,
    const hash_digest& hash) NOEXCEPT
{
    const auto context = ec_context_sign::context();

    return secp256k1_ecdsa_sign(context,
        pointer_cast<secp256k1_ecdsa_signature>(out.data()), hash.data(),
            secret.data(), secp256k1_nonce_function_rfc6979, nullptr)
                == ec_success;
}

// Expects private form `secp256k1_ecdsa_signature` (converts to low-s).
// This expected signature form is the output of decode_signature(...).
bool verify_signature(const data_chunk& point, const hash_digest& hash,
    const ec_signature& signature) NOEXCEPT
{
    const auto context = ec_context_verify::context();

    secp256k1_pubkey pubkey;
    return ec_public_key_parse(context, pubkey, point) &&
        verify_signature(context, pubkey, hash, signature);
}

// Expects private form `secp256k1_ecdsa_signature` (converts to low-s).
// This expected signature form is the output of decode_signature(...).
bool verify_signature(const ec_compressed& compressed,
    const hash_digest& hash, const ec_signature& signature) NOEXCEPT
{
    const auto context = ec_context_verify::context();

    secp256k1_pubkey pubkey;
    return ec_public_key_parse(context, pubkey, compressed) &&
        verify_signature(context, pubkey, hash, signature);
}

#endif // HAVE_ULTRAFAST

} // namespace ecdsa
} // namespace system
} // namespace libbitcoin
