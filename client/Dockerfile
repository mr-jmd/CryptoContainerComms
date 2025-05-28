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
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Crear directorio de trabajo
WORKDIR /app

# Copiar el código fuente
COPY client.cpp .

# Compilar el cliente
RUN g++ -std=c++17 -o client client.cpp -lssl -lcrypto -luuid

# Comando por defecto
CMD ["./client"]