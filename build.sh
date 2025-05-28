#!/bin/bash

# Script para construir y desplegar el sistema de transacciones seguras
# Uso: ./build.sh [--no-cache] [--push]

set -e

echo "=== Sistema de Transacciones Seguras ==="
echo "Iniciando proceso de construcción..."

# Configuración
DOCKER_HUB_USER="tu_usuario_dockerhub"  # Cambiar por tu usuario real de Docker Hub
CLIENT_IMAGE="secure-transaction-client"
SERVER_IMAGE="secure-transaction-server"
VERSION="1.0.0"

# Procesar argumentos
NO_CACHE=""
PUSH_IMAGES=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --no-cache)
            NO_CACHE="--no-cache"
            shift
            ;;
        --push)
            PUSH_IMAGES=true
            shift
            ;;
        *)
            echo "Uso: $0 [--no-cache] [--push]"
            exit 1
            ;;
    esac
done

# Función para verificar si Docker está ejecutándose
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        echo "Error: Docker no está ejecutándose o no tienes permisos"
        exit 1
    fi
}

# Función para construir imagen
build_image() {
    local dockerfile=$1        # Ruta al Dockerfile
    local image_name=$2        # Nombre de la imagen
    local tag=$3               # Versión/tag
    local context_dir=$(dirname "$dockerfile")  # Contexto = carpeta del Dockerfile

    echo "Construyendo $image_name:$tag..."
    docker build $NO_CACHE -f "$dockerfile" -t "$image_name:$tag" -t "$image_name:latest" "$context_dir"

    # Verificar tamaño de la imagen
    local size=$(docker images --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}" | grep "$image_name:$tag" | awk '{print $2}')
    echo "Tamaño de $image_name:$tag: $size"
}

# Función para etiquetar para Docker Hub
tag_for_hub() {
    local image_name=$1
    local version=$2

    docker tag $image_name:latest $DOCKER_HUB_USER/$image_name:$version
    docker tag $image_name:latest $DOCKER_HUB_USER/$image_name:latest
}

# Función para subir a Docker Hub
push_to_hub() {
    local image_name=$1
    local version=$2

    echo "Subiendo $image_name a Docker Hub..."
    docker push $DOCKER_HUB_USER/$image_name:$version
    docker push $DOCKER_HUB_USER/$image_name:latest
}

# Verificaciones iniciales
check_docker

# Limpiar contenedores existentes si existen
echo "Limpiando contenedores existentes..."
docker-compose down 2>/dev/null || true

# Construir imágenes
echo "=== Construyendo Imágenes ==="
build_image "./server/Dockerfile" $SERVER_IMAGE $VERSION
build_image "./client/Dockerfile" $CLIENT_IMAGE $VERSION

# Etiquetar para Docker Hub si se va a subir
if [ "$PUSH_IMAGES" = true ]; then
    echo "=== Etiquetando para Docker Hub ==="
    tag_for_hub $SERVER_IMAGE $VERSION
    tag_for_hub $CLIENT_IMAGE $VERSION

    # Verificar login en Docker Hub
    if ! docker info | grep -q "Username:"; then
        echo "Por favor, haz login en Docker Hub:"
        docker login
    fi

    # Subir imágenes
    echo "=== Subiendo a Docker Hub ==="
    push_to_hub $SERVER_IMAGE $VERSION
    push_to_hub $CLIENT_IMAGE $VERSION
fi

# Mostrar resumen
echo "=== Resumen de Construcción ==="
echo "Imágenes construidas:"
docker images | grep -E "(secure-transaction|REPOSITORY)"

echo ""
echo "=== Instrucciones de Uso ==="
echo "1. Para ejecutar el sistema completo:"
echo "   docker-compose up"
echo ""
echo "2. Para ejecutar en segundo plano:"
echo "   docker-compose up -d"
echo ""
echo "3. Para ver logs:"
echo "   docker-compose logs -f"
echo ""
echo "4. Para detener:"
echo "   docker-compose down"
echo ""

if [ "$PUSH_IMAGES" = true ]; then
    echo "5. Las imágenes están disponibles en Docker Hub:"
    echo "   - $DOCKER_HUB_USER/$SERVER_IMAGE:$VERSION"
    echo "   - $DOCKER_HUB_USER/$CLIENT_IMAGE:$VERSION"
fi

echo "=== Construcción Completada ==="
