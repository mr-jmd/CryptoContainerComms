#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <vector>
#include <set>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Función para decodificar Base64
std::vector<unsigned char> base64Decode(const std::string& encoded) {
    BIO *bio, *b64;
    int decodeLen = encoded.length();
    std::vector<unsigned char> decoded(decodeLen);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(encoded.data(), encoded.length());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int length = BIO_read(bio, decoded.data(), decodeLen);
    decoded.resize(length);

    BIO_free_all(bio);
    return decoded;
}

class TransactionServer {
private:
    int port;
    std::string shared_secret;
    std::set<std::string> processed_transactions;

public:
    TransactionServer(int p, const std::string& secret) 
        : port(p), shared_secret(secret) {}

    std::string hmacSha256(const std::string& data, const std::string& key) {
        unsigned char* digest;
        unsigned int digest_len;

        digest = HMAC(EVP_sha256(), key.c_str(), key.length(),
                     (unsigned char*)data.c_str(), data.length(),
                     NULL, &digest_len);

        std::stringstream ss;
        for(unsigned int i = 0; i < digest_len; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
        }

        return ss.str();
    }

    bool validateDynamicToken(const std::string& token, const std::string& transaction_id) {
        size_t colon_pos = token.find(':');
        if (colon_pos == std::string::npos) return false;

        std::string timestamp_str = token.substr(0, colon_pos);
        std::string received_hash = token.substr(colon_pos + 1);

        auto now = std::chrono::system_clock::now();
        auto current_time = std::chrono::system_clock::to_time_t(now);
        long long timestamp = std::stoll(timestamp_str);

        if (abs(current_time - timestamp) > 30) {
            std::cout << "Token expired. Time difference: " << abs(current_time - timestamp) << " seconds" << std::endl;
            return false;
        }

        std::string data = timestamp_str + shared_secret + transaction_id;
        std::string expected_hash = hmacSha256(data, shared_secret);

        return received_hash == expected_hash;
    }

    std::string aesDecrypt(const std::vector<unsigned char>& ciphertext,
                           const std::string& key,
                           const std::vector<unsigned char>& iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                          (unsigned char*)key.c_str(), iv.data());

        std::vector<unsigned char> plaintext(ciphertext.size() + AES_BLOCK_SIZE);
        int len;
        int plaintext_len;

        EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                         ciphertext.data(), ciphertext.size());
        plaintext_len = len;

        EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
    }

    std::string processTransaction(const std::string& encrypted_packet) {
        try {
            json packet = json::parse(encrypted_packet);

            std::string iv_b64 = packet["iv"];
            std::string encrypted_data_b64 = packet["encrypted_data"];
            std::string received_signature = packet["signature"];

            std::vector<unsigned char> iv = base64Decode(iv_b64);
            std::vector<unsigned char> ciphertext = base64Decode(encrypted_data_b64);
            std::string encrypted_str(ciphertext.begin(), ciphertext.end());

            std::string expected_signature = hmacSha256(encrypted_str, shared_secret);
            if (received_signature != expected_signature) {
                return "{\"status\":\"error\",\"message\":\"Invalid signature\"}";
            }

            std::string aes_key = shared_secret.substr(0, 32);
            std::string decrypted_json = aesDecrypt(ciphertext, aes_key, iv);
            json transaction = json::parse(decrypted_json);

            std::string transaction_id = transaction["transaction_id"];
            std::string dynamic_token = transaction["dynamic_token"];

            if (!validateDynamicToken(dynamic_token, transaction_id)) {
                return "{\"status\":\"error\",\"message\":\"Invalid or expired token\"}";
            }

            if (processed_transactions.find(transaction_id) != processed_transactions.end()) {
                return "{\"status\":\"error\",\"message\":\"Duplicate transaction\"}";
            }

            processed_transactions.insert(transaction_id);

            std::cout << "=== Transacción Procesada ===" << std::endl;
            std::cout << "ID: " << transaction["transaction_id"] << std::endl;
            std::cout << "De: " << transaction["from_account"] << std::endl;
            std::cout << "Para: " << transaction["to_account"] << std::endl;
            std::cout << "Monto: $" << transaction["amount"] << std::endl;
            std::cout << "Descripción: " << transaction["description"] << std::endl;
            std::cout << "Timestamp: " << transaction["timestamp"] << std::endl;
            std::cout << "=============================" << std::endl;

            json response;
            response["status"] = "success";
            response["message"] = "Transaction processed successfully";
            response["transaction_id"] = transaction_id;
            response["processed_at"] = std::time(nullptr);

            return response.dump();

        } catch (const std::exception& e) {
            std::cerr << "Error processing transaction: " << e.what() << std::endl;
            return "{\"status\":\"error\",\"message\":\"Processing error\"}";
        }
    }

    void start() {
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd == 0) {
            std::cerr << "Socket creation failed" << std::endl;
            return;
        }

        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

        struct sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            std::cerr << "Bind failed" << std::endl;
            return;
        }

        if (listen(server_fd, 3) < 0) {
            std::cerr << "Listen failed" << std::endl;
            return;
        }

        std::cout << "Servidor iniciado en puerto " << port << std::endl;

        while (true) {
            struct sockaddr_in client_addr;
            socklen_t addrlen = sizeof(client_addr);
            int client_socket = accept(server_fd, (struct sockaddr*)&client_addr, &addrlen);

            if (client_socket < 0) {
                std::cerr << "Accept failed" << std::endl;
                continue;
            }

            char buffer[4096] = {0};
            int bytes_read = read(client_socket, buffer, 4096);

            if (bytes_read > 0) {
                std::string encrypted_packet(buffer, bytes_read);
                std::string response = processTransaction(encrypted_packet);
                send(client_socket, response.c_str(), response.length(), 0);
            }

            close(client_socket);
        }

        close(server_fd);
    }
};

int main() {
    TransactionServer server(8080, "mi_clave_secreta_super_segura_32chars");
    server.start();
    return 0;
}
