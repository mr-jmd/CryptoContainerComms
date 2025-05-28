FROM ubuntu:22.04

# Instalar dependencias
RUN apt-get update && apt-get install -y \
    g++ \
    cmake \
    make \
    libssl-dev \
    libuuid1 \
    uuid-dev \
    nlohmann-json3-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Crear directorio de trabajo
WORKDIR /app

# Copiar el código fuente
COPY server.cpp .

# Compilar el servidor
RUN g++ -std=c++17 -o server server.cpp -lssl -lcrypto -luuid -pthread

# Exponer el puerto
EXPOSE 8080

# Comando para ejecutar el servidor
CMD ["./server"]