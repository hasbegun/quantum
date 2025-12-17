/**
 * SLH-DSA Address Structure (FIPS 205 Section 4.2)
 *
 * The ADRS structure is used for domain separation in hash function calls.
 * It is a 32-byte array with different fields depending on the address type.
 */

#ifndef SLHDSA_ADDRESS_HPP
#define SLHDSA_ADDRESS_HPP

#include <cstdint>
#include <cstddef>
#include <array>
#include <cstring>
#include <vector>

namespace slhdsa {

/**
 * Address types as defined in FIPS 205 Table 2
 */
enum class AddressType : uint32_t {
    WOTS_HASH = 0,
    WOTS_PK = 1,
    TREE = 2,
    FORS_TREE = 3,
    FORS_ROOTS = 4,
    WOTS_PRF = 5,
    FORS_PRF = 6
};

/**
 * ADRS - 32-byte address structure for domain separation
 *
 * Layout (all fields are big-endian):
 * Bytes 0-3:   Layer address
 * Bytes 4-11:  Tree address (64 bits)
 * Bytes 12-15: Type (determines remaining field meanings)
 * Bytes 16-19: Key pair address (for WOTS/FORS types)
 * Bytes 20-23: Chain address / Tree height
 * Bytes 24-27: Hash address / Tree index
 * Bytes 28-31: Reserved/unused
 */
class ADRS {
public:
    static constexpr size_t SIZE = 32;

    ADRS() noexcept {
        data_.fill(0);
    }

    // Get raw bytes
    [[nodiscard]] const std::array<uint8_t, SIZE>& bytes() const noexcept {
        return data_;
    }

    [[nodiscard]] std::array<uint8_t, SIZE>& bytes() noexcept {
        return data_;
    }

    // Return as bytes vector
    [[nodiscard]] std::vector<uint8_t> to_bytes() const {
        return std::vector<uint8_t>(data_.begin(), data_.end());
    }

    // Copy constructor and assignment
    ADRS(const ADRS&) = default;
    ADRS& operator=(const ADRS&) = default;

    // Create a copy
    [[nodiscard]] ADRS copy() const {
        return ADRS(*this);
    }

    // Layer address (bytes 0-3)
    void set_layer_address(uint32_t layer) noexcept {
        set_u32(0, layer);
    }

    [[nodiscard]] uint32_t get_layer_address() const noexcept {
        return get_u32(0);
    }

    // Tree address (bytes 4-11, 64 bits)
    void set_tree_address(uint64_t tree) noexcept {
        set_u64(4, tree);
    }

    [[nodiscard]] uint64_t get_tree_address() const noexcept {
        return get_u64(4);
    }

    // Type (bytes 12-15)
    void set_type(AddressType type) noexcept {
        set_u32(12, static_cast<uint32_t>(type));
        // When type changes, clear type-specific fields (bytes 16-31)
        std::memset(&data_[16], 0, 16);
    }

    [[nodiscard]] AddressType get_type() const noexcept {
        return static_cast<AddressType>(get_u32(12));
    }

    // Key pair address (bytes 16-19) - for WOTS and FORS types
    void set_key_pair_address(uint32_t kp) noexcept {
        set_u32(16, kp);
    }

    [[nodiscard]] uint32_t get_key_pair_address() const noexcept {
        return get_u32(16);
    }

    // Chain address (bytes 20-23) - for WOTS types
    void set_chain_address(uint32_t chain) noexcept {
        set_u32(20, chain);
    }

    [[nodiscard]] uint32_t get_chain_address() const noexcept {
        return get_u32(20);
    }

    // Hash address (bytes 24-27) - for WOTS_HASH
    void set_hash_address(uint32_t hash) noexcept {
        set_u32(24, hash);
    }

    [[nodiscard]] uint32_t get_hash_address() const noexcept {
        return get_u32(24);
    }

    // Tree height (bytes 20-23) - for TREE and FORS_TREE types
    void set_tree_height(uint32_t height) noexcept {
        set_u32(20, height);
    }

    [[nodiscard]] uint32_t get_tree_height() const noexcept {
        return get_u32(20);
    }

    // Tree index (bytes 24-27) - for TREE and FORS types
    void set_tree_index(uint32_t index) noexcept {
        set_u32(24, index);
    }

    [[nodiscard]] uint32_t get_tree_index() const noexcept {
        return get_u32(24);
    }

    /**
     * Get 22-byte compressed address for SHA2 variants.
     *
     * Layout (FIPS 205 Section 11.2.1):
     *   Bytes 0-2:   Offset 1-3 (layer address, 3 LSB)
     *   Bytes 3-10:  Offset 4-11 (tree address)
     *   Bytes 11:    Offset 15 (type, LSB)
     *   Bytes 12-21: Offset 16-25 (type-specific fields)
     */
    [[nodiscard]] std::array<uint8_t, 22> get_compressed_adrs() const noexcept {
        std::array<uint8_t, 22> compressed{};
        // Layer address (3 bytes from offset 1-3)
        std::memcpy(&compressed[0], &data_[1], 3);
        // Tree address (8 bytes from offset 4-11)
        std::memcpy(&compressed[3], &data_[4], 8);
        // Type (1 byte from offset 15)
        compressed[11] = data_[15];
        // Type-specific (10 bytes from offset 16-25)
        std::memcpy(&compressed[12], &data_[16], 10);
        return compressed;
    }

private:
    std::array<uint8_t, SIZE> data_;

    // Helper: set 32-bit big-endian value
    void set_u32(size_t offset, uint32_t value) noexcept {
        data_[offset + 0] = static_cast<uint8_t>(value >> 24);
        data_[offset + 1] = static_cast<uint8_t>(value >> 16);
        data_[offset + 2] = static_cast<uint8_t>(value >> 8);
        data_[offset + 3] = static_cast<uint8_t>(value);
    }

    // Helper: get 32-bit big-endian value
    [[nodiscard]] uint32_t get_u32(size_t offset) const noexcept {
        return (static_cast<uint32_t>(data_[offset + 0]) << 24) |
               (static_cast<uint32_t>(data_[offset + 1]) << 16) |
               (static_cast<uint32_t>(data_[offset + 2]) << 8) |
               (static_cast<uint32_t>(data_[offset + 3]));
    }

    // Helper: set 64-bit big-endian value
    void set_u64(size_t offset, uint64_t value) noexcept {
        data_[offset + 0] = static_cast<uint8_t>(value >> 56);
        data_[offset + 1] = static_cast<uint8_t>(value >> 48);
        data_[offset + 2] = static_cast<uint8_t>(value >> 40);
        data_[offset + 3] = static_cast<uint8_t>(value >> 32);
        data_[offset + 4] = static_cast<uint8_t>(value >> 24);
        data_[offset + 5] = static_cast<uint8_t>(value >> 16);
        data_[offset + 6] = static_cast<uint8_t>(value >> 8);
        data_[offset + 7] = static_cast<uint8_t>(value);
    }

    // Helper: get 64-bit big-endian value
    [[nodiscard]] uint64_t get_u64(size_t offset) const noexcept {
        return (static_cast<uint64_t>(data_[offset + 0]) << 56) |
               (static_cast<uint64_t>(data_[offset + 1]) << 48) |
               (static_cast<uint64_t>(data_[offset + 2]) << 40) |
               (static_cast<uint64_t>(data_[offset + 3]) << 32) |
               (static_cast<uint64_t>(data_[offset + 4]) << 24) |
               (static_cast<uint64_t>(data_[offset + 5]) << 16) |
               (static_cast<uint64_t>(data_[offset + 6]) << 8) |
               (static_cast<uint64_t>(data_[offset + 7]));
    }
};

// Factory functions for creating specific address types

inline ADRS make_wots_hash_adrs(uint32_t layer, uint64_t tree, uint32_t keypair) {
    ADRS adrs;
    adrs.set_layer_address(layer);
    adrs.set_tree_address(tree);
    adrs.set_type(AddressType::WOTS_HASH);
    adrs.set_key_pair_address(keypair);
    return adrs;
}

inline ADRS make_wots_pk_adrs(uint32_t layer, uint64_t tree, uint32_t keypair) {
    ADRS adrs;
    adrs.set_layer_address(layer);
    adrs.set_tree_address(tree);
    adrs.set_type(AddressType::WOTS_PK);
    adrs.set_key_pair_address(keypair);
    return adrs;
}

inline ADRS make_tree_adrs(uint32_t layer, uint64_t tree) {
    ADRS adrs;
    adrs.set_layer_address(layer);
    adrs.set_tree_address(tree);
    adrs.set_type(AddressType::TREE);
    return adrs;
}

inline ADRS make_fors_tree_adrs(uint64_t tree, uint32_t keypair) {
    ADRS adrs;
    adrs.set_layer_address(0);
    adrs.set_tree_address(tree);
    adrs.set_type(AddressType::FORS_TREE);
    adrs.set_key_pair_address(keypair);
    return adrs;
}

inline ADRS make_fors_roots_adrs(uint64_t tree, uint32_t keypair) {
    ADRS adrs;
    adrs.set_layer_address(0);
    adrs.set_tree_address(tree);
    adrs.set_type(AddressType::FORS_ROOTS);
    adrs.set_key_pair_address(keypair);
    return adrs;
}

inline ADRS make_wots_prf_adrs(uint32_t layer, uint64_t tree, uint32_t keypair) {
    ADRS adrs;
    adrs.set_layer_address(layer);
    adrs.set_tree_address(tree);
    adrs.set_type(AddressType::WOTS_PRF);
    adrs.set_key_pair_address(keypair);
    return adrs;
}

inline ADRS make_fors_prf_adrs(uint64_t tree, uint32_t keypair) {
    ADRS adrs;
    adrs.set_layer_address(0);
    adrs.set_tree_address(tree);
    adrs.set_type(AddressType::FORS_PRF);
    adrs.set_key_pair_address(keypair);
    return adrs;
}

} // namespace slhdsa

#endif // SLHDSA_ADDRESS_HPP
