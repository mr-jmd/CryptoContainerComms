Sistema de Transacciones Seguras con Clave Dinámica
Un sistema de comunicación segura entre contenedores Docker que implementa un mecanismo de autenticación similar al sistema de clave dinámica de Bancolombia, utilizando algoritmos criptográficos avanzados.
* Arquitectura del Sistema
  
![image](https://github.com/user-attachments/assets/913a75a1-8f9a-4df3-9f88-8b775a6aa47b)

* Algoritmos Criptográficos Implementados
1. HMAC-SHA256

Uso: Generación de tokens dinámicos y verificación de integridad
Clave: Secreto compartido entre cliente y servidor
Estructura del token: timestamp:hmac(timestamp + secret + transaction_id)

2. AES-256-CBC

Uso: Cifrado simétrico de las transacciones
Clave: Primeros 32 caracteres del secreto compartido
IV: Generado aleatoriamente para cada transacción

3. SHA-256

Uso: Funciones hash internas y verificaciones de integridad
Implementación: A través de OpenSSL

4. Generación de Números Aleatorios

Uso: IVs para AES, UUIDs para transacciones
Fuente: OpenSSL RAND_bytes()

* Medidas de Seguridad

* Tokens con Tiempo Limitado: Ventana de validez de 30 segundos
* Protección contra Replay Attacks: Control de transacciones duplicadas
* Cifrado Extremo a Extremo: AES-256-CBC para todos los datos
* Verificación de Integridad: HMAC-SHA256 de datos cifrados
* Identificadores Únicos: UUIDs v4 para cada transacción
* Comunicación Segura: Sockets TCP con validación completa

* Estructura de Transacción
  
```json
{
  "transaction_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "1704067200",
  "from_account": "1234567890",
  "to_account": "0987654321",
  "amount": 1000.50,
  "description": "Transferencia segura",
  "dynamic_token": "1704067200:a1b2c3d4e5f6..."
}
```

* Instalación y Despliegue
Prerrequisitos

Docker 20.10+
Docker Compose 2.0+
Git

Opción 1: Construcción Local
bash# Clonar el repositorio

# Detener contenedores actuales
docker-compose down

# Construir las imágenes
docker-compose build --no-cache

# Ejecutar el sistema
docker-compose up
