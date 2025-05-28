#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>  // Para gethostbyname
#include <errno.h>  // Para strerror
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <vector>
#include <uuid/uuid.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Función para codificar en Base64
std::string base64Encode(const std::vector<unsigned char>& data) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data.data(), data.size());
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);

    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(b64);

    return encoded;
}

class TransactionClient {
private:
    std::string server_ip;
    int server_port;
    std::string shared_secret;

public:
    TransactionClient(const std::string& ip, int port, const std::string& secret) 
        : server_ip(ip), server_port(port), shared_secret(secret) {}

    std::string generateUUID() {
        uuid_t uuid;
        uuid_generate_random(uuid);
        char uuid_str[37];
        uuid_unparse(uuid, uuid_str);
        return std::string(uuid_str);
    }

    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        return std::to_string(time_t);
    }

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

    std::string generateDynamicToken(const std::string& transaction_id) {
        std::string timestamp = getCurrentTimestamp();
        std::string data = timestamp + shared_secret + transaction_id;
        std::string hash = hmacSha256(data, shared_secret);
        return timestamp + ":" + hash;
    }

    std::vector<unsigned char> aesEncrypt(const std::string& plaintext, 
                                          const std::string& key, 
                                          std::vector<unsigned char>& iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        iv.resize(AES_BLOCK_SIZE);
        RAND_bytes(iv.data(), AES_BLOCK_SIZE);

        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                          (unsigned char*)key.c_str(), iv.data());

        std::vector<unsigned char> ciphertext(plaintext.length() + AES_BLOCK_SIZE);
        int len;
        int ciphertext_len;

        EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                         (unsigned char*)plaintext.c_str(), plaintext.length());
        ciphertext_len = len;

        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);
        ciphertext.resize(ciphertext_len);

        return ciphertext;
    }

    bool sendTransaction(const std::string& from_account, 
                         const std::string& to_account,
                         double amount, 
                         const std::string& description) {

        json transaction;
        transaction["transaction_id"] = generateUUID();
        transaction["timestamp"] = getCurrentTimestamp();
        transaction["from_account"] = from_account;
        transaction["to_account"] = to_account;
        transaction["amount"] = amount;
        transaction["description"] = description;
        transaction["dynamic_token"] = generateDynamicToken(transaction["transaction_id"]);

        std::string json_str = transaction.dump();

        std::string aes_key = shared_secret.substr(0, 32);
        std::vector<unsigned char> iv;
        std::vector<unsigned char> encrypted = aesEncrypt(json_str, aes_key, iv);

        std::string encrypted_str(encrypted.begin(), encrypted.end());
        std::string signature = hmacSha256(encrypted_str, shared_secret);

        json packet;
        packet["iv"] = base64Encode(iv);
        packet["encrypted_data"] = base64Encode(encrypted);
        packet["signature"] = signature;

        return sendToServer(packet.dump());
    }

    bool sendToServer(const std::string& data) {
        const int MAX_RETRIES = 15;
        const int RETRY_DELAY = 2; // segundos
        
        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            std::cout << "🔄 Intento de conexión " << attempt << "/" << MAX_RETRIES 
                      << " al servidor: " << server_ip << ":" << server_port << std::endl;
            
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                std::cerr << "❌ Error creating socket: " << strerror(errno) << std::endl;
                return false;
            }

            struct sockaddr_in server_addr;
            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(server_port);
            
            // Intentar resolver el hostname primero
            struct hostent* host_entry = gethostbyname(server_ip.c_str());
            if (host_entry != nullptr) {
                memcpy(&server_addr.sin_addr, host_entry->h_addr_list[0], host_entry->h_length);
                std::cout << "🔍 Hostname resuelto correctamente" << std::endl;
            } else if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
                std::cerr << "❌ No se pudo resolver hostname ni IP: " << server_ip << std::endl;
                close(sock);
                return false;
            }

            // Configurar timeout para la conexión
            struct timeval timeout;
            timeout.tv_sec = 10;
            timeout.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

            std::cout << "🔌 Intentando conectar..." << std::endl;
            if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
                std::cerr << "❌ Intento " << attempt << " falló: " << strerror(errno) << std::endl;
                if (attempt < MAX_RETRIES) {
                    std::cerr << "⏳ Reintentando en " << RETRY_DELAY << " segundos..." << std::endl;
                    close(sock);
                    sleep(RETRY_DELAY);
                    continue;
                } else {
                    std::cerr << "💀 Todos los intentos fallaron." << std::endl;
                    close(sock);
                    return false;
                }
            }

            // Conexión exitosa
            std::cout << "✅ Conectado al servidor exitosamente!" << std::endl;
            
            // Enviar datos
            ssize_t sent = send(sock, data.c_str(), data.length(), 0);
            if (sent < 0) {
                std::cerr << "❌ Error enviando datos: " << strerror(errno) << std::endl;
                close(sock);
                return false;
            }

            std::cout << "📤 Enviados " << sent << " bytes al servidor" << std::endl;

            // Recibir respuesta
            char buffer[4096] = {0};
            ssize_t bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);

            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';
                std::cout << "📥 Respuesta del servidor: " << buffer << std::endl;
            } else if (bytes_received == 0) {
                std::cout << "🔌 Servidor cerró la conexión" << std::endl;
            } else {
                std::cerr << "❌ Error recibiendo respuesta: " << strerror(errno) << std::endl;
            }

            close(sock);
            return true;
        }
        
        return false;
    }
};

int main() {
    // Usar el nombre del servicio Docker como está definido en docker-compose.yml
    TransactionClient client("transaction-server", 8080, "mi_clave_secreta_super_segura_32chars");

    std::cout << "=== Sistema de Transacciones Seguras ===" << std::endl;
    std::cout << "Enviando transacción de prueba..." << std::endl;

    bool success = client.sendTransaction(
        "1234567890", "0987654321", 1000.50, "Transferencia segura"
    );

    if (success) {
        std::cout << "✅ Transacción enviada exitosamente!" << std::endl;
    } else {
        std::cout << "❌ Error al enviar transacción" << std::endl;
    }

    return 0;
}