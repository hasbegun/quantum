/**
 * WOTS+ (Winternitz One-Time Signature Plus) Implementation
 * FIPS 205 Section 5
 *
 * WOTS+ is the base one-time signature scheme used in SLH-DSA.
 */

#ifndef SLHDSA_WOTS_HPP
#define SLHDSA_WOTS_HPP

#include "params.hpp"
#include "address.hpp"
#include "hash_functions.hpp"
#include "utils.hpp"
#include <vector>
#include <span>
#include <cstdint>

namespace slhdsa {

/**
 * Algorithm 4: chain(X, i, s, PK.seed, ADRS)
 *
 * Compute the s-step hash chain starting at X from position i.
 *
 * @param hash_funcs Hash function instantiation
 * @param X Starting value (n bytes)
 * @param i Starting index in chain
 * @param s Number of steps
 * @param pk_seed Public seed
 * @param adrs Address structure (will be modified)
 * @return Chain output (n bytes)
 */
inline std::vector<uint8_t> chain(
    const HashFunctions& hash_funcs,
    std::span<const uint8_t> X,
    uint32_t i,
    uint32_t s,
    std::span<const uint8_t> pk_seed,
    ADRS& adrs) {

    if (s == 0) {
        return std::vector<uint8_t>(X.begin(), X.end());
    }

    if (i + s > hash_funcs.params().w()) {
        return {};  // Invalid parameters
    }

    std::vector<uint8_t> tmp(X.begin(), X.end());
    for (uint32_t j = i; j < i + s; ++j) {
        adrs.set_hash_address(j);
        tmp = hash_funcs.F(pk_seed, adrs, tmp);
    }

    return tmp;
}

/**
 * Algorithm 5: wots_pkGen(SK.seed, PK.seed, ADRS)
 *
 * Generate a WOTS+ public key.
 *
 * @param hash_funcs Hash function instantiation
 * @param sk_seed Secret seed
 * @param pk_seed Public seed
 * @param adrs Address structure
 * @return WOTS+ public key (n bytes, compressed)
 */
inline std::vector<uint8_t> wots_pkGen(
    const HashFunctions& hash_funcs,
    std::span<const uint8_t> sk_seed,
    std::span<const uint8_t> pk_seed,
    const ADRS& adrs) {

    const auto& params = hash_funcs.params();
    size_t n = params.n;
    size_t len_total = params.len_total();
    size_t w = params.w();

    // Set up address structures
    ADRS sk_adrs = adrs.copy();
    sk_adrs.set_type(AddressType::WOTS_PRF);
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    ADRS chain_adrs = adrs.copy();
    chain_adrs.set_type(AddressType::WOTS_HASH);
    chain_adrs.set_key_pair_address(adrs.get_key_pair_address());

    // Generate chain endpoints
    std::vector<uint8_t> tmp;
    tmp.reserve(len_total * n);

    for (size_t i = 0; i < len_total; ++i) {
        // Generate secret key element
        sk_adrs.set_chain_address(static_cast<uint32_t>(i));
        auto sk_i = hash_funcs.PRF(pk_seed, sk_seed, sk_adrs);

        // Compute chain endpoint
        chain_adrs.set_chain_address(static_cast<uint32_t>(i));
        auto endpoint = chain(hash_funcs, sk_i, 0, static_cast<uint32_t>(w - 1), pk_seed, chain_adrs);
        tmp.insert(tmp.end(), endpoint.begin(), endpoint.end());
    }

    // Compress public key
    ADRS pk_adrs = adrs.copy();
    pk_adrs.set_type(AddressType::WOTS_PK);
    pk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    return hash_funcs.T_l(pk_seed, pk_adrs, tmp);
}

/**
 * Algorithm 6: wots_sign(M, SK.seed, PK.seed, ADRS)
 *
 * Generate a WOTS+ signature for message M.
 *
 * @param hash_funcs Hash function instantiation
 * @param M Message to sign (n bytes)
 * @param sk_seed Secret seed
 * @param pk_seed Public seed
 * @param adrs Address structure
 * @return WOTS+ signature (len_total * n bytes)
 */
inline std::vector<uint8_t> wots_sign(
    const HashFunctions& hash_funcs,
    std::span<const uint8_t> M,
    std::span<const uint8_t> sk_seed,
    std::span<const uint8_t> pk_seed,
    const ADRS& adrs) {

    const auto& params = hash_funcs.params();
    size_t n = params.n;
    size_t len1 = params.len1();
    size_t len2 = params.len2();
    size_t len_total = params.len_total();
    size_t w = params.w();
    size_t lg_w = params.lg_w;

    // Convert message to base-w
    auto msg = base_2b(M, lg_w, len1);

    // Compute checksum
    uint32_t csum = 0;
    for (size_t i = 0; i < len1; ++i) {
        csum += static_cast<uint32_t>(w - 1 - msg[i]);
    }

    // Append checksum in base-w
    size_t csum_bits = len2 * lg_w;
    size_t shift = (8 - (csum_bits % 8)) % 8;
    size_t csum_bytes_len = (csum_bits + 7) / 8;
    auto csum_bytes = toByte(static_cast<uint64_t>(csum) << shift, csum_bytes_len);
    auto csum_base_w = base_2b(csum_bytes, lg_w, len2);

    // Combine message and checksum
    msg.insert(msg.end(), csum_base_w.begin(), csum_base_w.end());

    // Set up address structures
    ADRS sk_adrs = adrs.copy();
    sk_adrs.set_type(AddressType::WOTS_PRF);
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    ADRS chain_adrs = adrs.copy();
    chain_adrs.set_type(AddressType::WOTS_HASH);
    chain_adrs.set_key_pair_address(adrs.get_key_pair_address());

    // Generate signature
    std::vector<uint8_t> sig;
    sig.reserve(len_total * n);

    for (size_t i = 0; i < len_total; ++i) {
        sk_adrs.set_chain_address(static_cast<uint32_t>(i));
        auto sk_i = hash_funcs.PRF(pk_seed, sk_seed, sk_adrs);

        chain_adrs.set_chain_address(static_cast<uint32_t>(i));
        auto sig_i = chain(hash_funcs, sk_i, 0, msg[i], pk_seed, chain_adrs);
        sig.insert(sig.end(), sig_i.begin(), sig_i.end());
    }

    return sig;
}

/**
 * Algorithm 7: wots_pkFromSig(sig, M, PK.seed, ADRS)
 *
 * Compute WOTS+ public key from signature.
 *
 * @param hash_funcs Hash function instantiation
 * @param sig WOTS+ signature
 * @param M Message (n bytes)
 * @param pk_seed Public seed
 * @param adrs Address structure
 * @return Recovered public key (n bytes)
 */
inline std::vector<uint8_t> wots_pkFromSig(
    const HashFunctions& hash_funcs,
    std::span<const uint8_t> sig,
    std::span<const uint8_t> M,
    std::span<const uint8_t> pk_seed,
    const ADRS& adrs) {

    const auto& params = hash_funcs.params();
    size_t n = params.n;
    size_t len1 = params.len1();
    size_t len2 = params.len2();
    size_t len_total = params.len_total();
    size_t w = params.w();
    size_t lg_w = params.lg_w;

    // Convert message to base-w
    auto msg = base_2b(M, lg_w, len1);

    // Compute checksum
    uint32_t csum = 0;
    for (size_t i = 0; i < len1; ++i) {
        csum += static_cast<uint32_t>(w - 1 - msg[i]);
    }

    // Append checksum in base-w
    size_t csum_bits = len2 * lg_w;
    size_t shift = (8 - (csum_bits % 8)) % 8;
    size_t csum_bytes_len = (csum_bits + 7) / 8;
    auto csum_bytes = toByte(static_cast<uint64_t>(csum) << shift, csum_bytes_len);
    auto csum_base_w = base_2b(csum_bytes, lg_w, len2);

    // Combine message and checksum
    msg.insert(msg.end(), csum_base_w.begin(), csum_base_w.end());

    // Set up address structure
    ADRS chain_adrs = adrs.copy();
    chain_adrs.set_type(AddressType::WOTS_HASH);
    chain_adrs.set_key_pair_address(adrs.get_key_pair_address());

    // Compute chain endpoints from signature
    std::vector<uint8_t> tmp;
    tmp.reserve(len_total * n);

    for (size_t i = 0; i < len_total; ++i) {
        chain_adrs.set_chain_address(static_cast<uint32_t>(i));
        std::span<const uint8_t> sig_i = sig.subspan(i * n, n);
        auto endpoint = chain(hash_funcs, sig_i, msg[i],
                              static_cast<uint32_t>(w - 1 - msg[i]), pk_seed, chain_adrs);
        tmp.insert(tmp.end(), endpoint.begin(), endpoint.end());
    }

    // Compress to get public key
    ADRS pk_adrs = adrs.copy();
    pk_adrs.set_type(AddressType::WOTS_PK);
    pk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    return hash_funcs.T_l(pk_seed, pk_adrs, tmp);
}

} // namespace slhdsa

#endif // SLHDSA_WOTS_HPP
