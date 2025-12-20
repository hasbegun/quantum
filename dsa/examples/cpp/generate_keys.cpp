/**
 * Post-Quantum Key Generation Tool
 *
 * Generates ML-DSA or SLH-DSA key pairs and saves them to files.
 *
 * Usage:
 *   ./generate_keys <algorithm> <output_dir>
 *
 * Examples:
 *   ./generate_keys mldsa44 /keys
 *   ./generate_keys mldsa65 /keys
 *   ./generate_keys slh-shake-128f /keys
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <filesystem>

#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"

namespace fs = std::filesystem;

// Get current ISO timestamp
std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// Write binary file
bool write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return file.good();
}

// Write JSON metadata
bool write_metadata(const std::string& path,
                    const std::string& algorithm,
                    const std::string& type,
                    size_t pk_size,
                    size_t sk_size,
                    const std::string& pk_file,
                    const std::string& sk_file) {
    std::ofstream file(path);
    if (!file) return false;

    file << "{\n";
    file << "  \"algorithm\": \"" << algorithm << "\",\n";
    file << "  \"type\": \"" << type << "\",\n";
    file << "  \"created\": \"" << get_timestamp() << "\",\n";
    file << "  \"public_key_size\": " << pk_size << ",\n";
    file << "  \"secret_key_size\": " << sk_size << ",\n";
    file << "  \"public_key_file\": \"" << pk_file << "\",\n";
    file << "  \"secret_key_file\": \"" << sk_file << "\"\n";
    file << "}\n";

    return file.good();
}

// Generate ML-DSA keys
template<typename DSA>
bool generate_mldsa(const std::string& name, const std::string& output_dir) {
    DSA dsa;

    std::cout << "Generating " << name << " keys..." << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    auto [pk, sk] = dsa.keygen();
    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "  Key generation completed in " << ms << " ms" << std::endl;

    // Create filenames
    std::string prefix = name;
    std::transform(prefix.begin(), prefix.end(), prefix.begin(), ::tolower);

    std::string pk_file = prefix + "_public.key";
    std::string sk_file = prefix + "_secret.key";
    std::string meta_file = prefix + "_metadata.json";

    std::string pk_path = output_dir + "/" + pk_file;
    std::string sk_path = output_dir + "/" + sk_file;
    std::string meta_path = output_dir + "/" + meta_file;

    // Write files
    if (!write_file(pk_path, pk)) {
        std::cerr << "Error: Failed to write public key" << std::endl;
        return false;
    }

    if (!write_file(sk_path, sk)) {
        std::cerr << "Error: Failed to write secret key" << std::endl;
        return false;
    }

    if (!write_metadata(meta_path, name, "ML-DSA (FIPS 204)",
                        pk.size(), sk.size(), pk_file, sk_file)) {
        std::cerr << "Error: Failed to write metadata" << std::endl;
        return false;
    }

    std::cout << "\nKeys generated successfully!" << std::endl;
    std::cout << "\n  Algorithm:    " << name << std::endl;
    std::cout << "  Type:         ML-DSA (FIPS 204)" << std::endl;
    std::cout << "  Public Key:   " << pk.size() << " bytes -> " << pk_file << std::endl;
    std::cout << "  Secret Key:   " << sk.size() << " bytes -> " << sk_file << std::endl;
    std::cout << "  Metadata:     " << meta_file << std::endl;

    return true;
}

// Generate SLH-DSA keys
template<typename DSA>
bool generate_slhdsa(const std::string& name, const std::string& output_dir) {
    DSA dsa;

    std::cout << "Generating " << name << " keys..." << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    auto [sk, pk] = dsa.keygen();
    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "  Key generation completed in " << ms << " ms" << std::endl;

    // Create filenames (replace - with _)
    std::string prefix = name;
    std::transform(prefix.begin(), prefix.end(), prefix.begin(), ::tolower);
    std::replace(prefix.begin(), prefix.end(), '-', '_');

    std::string pk_file = prefix + "_public.key";
    std::string sk_file = prefix + "_secret.key";
    std::string meta_file = prefix + "_metadata.json";

    std::string pk_path = output_dir + "/" + pk_file;
    std::string sk_path = output_dir + "/" + sk_file;
    std::string meta_path = output_dir + "/" + meta_file;

    // Write files
    if (!write_file(pk_path, pk)) {
        std::cerr << "Error: Failed to write public key" << std::endl;
        return false;
    }

    if (!write_file(sk_path, sk)) {
        std::cerr << "Error: Failed to write secret key" << std::endl;
        return false;
    }

    if (!write_metadata(meta_path, name, "SLH-DSA (FIPS 205)",
                        pk.size(), sk.size(), pk_file, sk_file)) {
        std::cerr << "Error: Failed to write metadata" << std::endl;
        return false;
    }

    std::cout << "\nKeys generated successfully!" << std::endl;
    std::cout << "\n  Algorithm:    " << name << std::endl;
    std::cout << "  Type:         SLH-DSA (FIPS 205)" << std::endl;
    std::cout << "  Public Key:   " << pk.size() << " bytes -> " << pk_file << std::endl;
    std::cout << "  Secret Key:   " << sk.size() << " bytes -> " << sk_file << std::endl;
    std::cout << "  Metadata:     " << meta_file << std::endl;

    return true;
}

void print_usage() {
    std::cout << "Post-Quantum Key Generator (C++)" << std::endl;
    std::cout << std::string(50, '=') << std::endl;
    std::cout << "\nUsage: generate_keys <algorithm> [output_dir]" << std::endl;
    std::cout << "\nML-DSA algorithms (fast, smaller signatures):" << std::endl;
    std::cout << "  mldsa44          - Category 1 (128-bit security)" << std::endl;
    std::cout << "  mldsa65          - Category 3 (192-bit security)" << std::endl;
    std::cout << "  mldsa87          - Category 5 (256-bit security)" << std::endl;
    std::cout << "\nSLH-DSA algorithms (hash-based, conservative):" << std::endl;
    std::cout << "  slh-shake-128f   - SHAKE, fast variant" << std::endl;
    std::cout << "  slh-shake-128s   - SHAKE, small signatures" << std::endl;
    std::cout << "  slh-shake-192f   - SHAKE, Category 3, fast" << std::endl;
    std::cout << "  slh-shake-192s   - SHAKE, Category 3, small" << std::endl;
    std::cout << "  slh-shake-256f   - SHAKE, Category 5, fast" << std::endl;
    std::cout << "  slh-shake-256s   - SHAKE, Category 5, small" << std::endl;
    std::cout << "  slh-sha2-128f    - SHA2, fast variant" << std::endl;
    std::cout << "  slh-sha2-128s    - SHA2, small signatures" << std::endl;
    std::cout << "  slh-sha2-192f    - SHA2, Category 3, fast" << std::endl;
    std::cout << "  slh-sha2-192s    - SHA2, Category 3, small" << std::endl;
    std::cout << "  slh-sha2-256f    - SHA2, Category 5, fast" << std::endl;
    std::cout << "  slh-sha2-256s    - SHA2, Category 5, small" << std::endl;
    std::cout << "\nExamples:" << std::endl;
    std::cout << "  generate_keys mldsa44 /keys" << std::endl;
    std::cout << "  generate_keys slh-shake-128f /keys" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 0;
    }

    std::string algorithm = argv[1];
    std::string output_dir = argc > 2 ? argv[2] : "/keys";

    // Convert to lowercase
    std::transform(algorithm.begin(), algorithm.end(), algorithm.begin(), ::tolower);

    // Create output directory if it doesn't exist
    fs::create_directories(output_dir);

    std::cout << "Output directory: " << output_dir << std::endl;
    std::cout << std::endl;

    bool success = false;

    // ML-DSA algorithms
    if (algorithm == "mldsa44") {
        success = generate_mldsa<mldsa::MLDSA44>("MLDSA44", output_dir);
    } else if (algorithm == "mldsa65") {
        success = generate_mldsa<mldsa::MLDSA65>("MLDSA65", output_dir);
    } else if (algorithm == "mldsa87") {
        success = generate_mldsa<mldsa::MLDSA87>("MLDSA87", output_dir);
    }
    // SLH-DSA SHAKE algorithms
    else if (algorithm == "slh-shake-128f") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f", output_dir);
    } else if (algorithm == "slh-shake-128s") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHAKE_128s>("SLH-DSA-SHAKE-128s", output_dir);
    } else if (algorithm == "slh-shake-192f") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHAKE_192f>("SLH-DSA-SHAKE-192f", output_dir);
    } else if (algorithm == "slh-shake-192s") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHAKE_192s>("SLH-DSA-SHAKE-192s", output_dir);
    } else if (algorithm == "slh-shake-256f") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHAKE_256f>("SLH-DSA-SHAKE-256f", output_dir);
    } else if (algorithm == "slh-shake-256s") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHAKE_256s>("SLH-DSA-SHAKE-256s", output_dir);
    }
    // SLH-DSA SHA2 algorithms
    else if (algorithm == "slh-sha2-128f") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f", output_dir);
    } else if (algorithm == "slh-sha2-128s") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHA2_128s>("SLH-DSA-SHA2-128s", output_dir);
    } else if (algorithm == "slh-sha2-192f") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHA2_192f>("SLH-DSA-SHA2-192f", output_dir);
    } else if (algorithm == "slh-sha2-192s") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHA2_192s>("SLH-DSA-SHA2-192s", output_dir);
    } else if (algorithm == "slh-sha2-256f") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHA2_256f>("SLH-DSA-SHA2-256f", output_dir);
    } else if (algorithm == "slh-sha2-256s") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHA2_256s>("SLH-DSA-SHA2-256s", output_dir);
    } else {
        std::cerr << "Error: Unknown algorithm '" << algorithm << "'" << std::endl;
        std::cerr << "\nRun without arguments to see available algorithms." << std::endl;
        return 1;
    }

    if (success) {
        std::cout << "\nWARNING: Keep your secret key secure!" << std::endl;
        return 0;
    }

    return 1;
}
