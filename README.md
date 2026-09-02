# Gryptography API Server

Gryptography (or **Grypto**) is a lightweight, Java-based authentication service that implements a custom RSA-based challenge-response authentication flow. It is designed to be minimal, with few dependencies, and provides a simple way to manage client identities and issue JWT tokens upon successful verification.

## 🚀 Key Features

- **RSA Challenge-Response**: Secure authentication using RSA encryption and digital signatures.
- **Client Identity Management**: Automated generation and storage of RSA key pairs for clients.
- **JWT Token Issuance**: Generates compact, RS256-signed JSON Web Tokens for authenticated sessions.
- **Web Dashboard**: Built-in dashboard to monitor registered clients and their public keys.
- **Low Dependency**: Built using standard Java libraries, with minimal external dependencies like SnakeYAML and Pebble templates.
- **YAML Storage**: Simple file-based storage for client public keys.

## 🛠 Tech Stack

- **Language**: Java 18
- **Build Tool**: Maven
- **Template Engine**: [Pebble](https://pebbletemplates.io/)
- **YAML Parser**: [SnakeYAML](https://bitbucket.org/snakeyaml/snakeyaml/src/master/)
- **Logging**: SLF4J with Logback

## 📂 Project Structure

- `src/main/java/net/coffeetariat/gryptography/api`: HTTP server logic and API endpoints.
- `src/main/java/net/coffeetariat/gryptography/auth`: Core authentication logic, including challenge generation and JWT signing.
- `src/main/java/net/coffeetariat/gryptography/lib`: Cryptography and storage utilities.
- `src/main/resources`: Pebble templates, static assets, and joke data.

## 📡 API Reference

The server runs on port `8080` by default.

### 🏥 System
- `GET /health`: Returns `ok` if the server is running.
- `GET /`: Dashboard UI showing registered clients.

### 👥 Client Management
- `GET /api/clients/{clientId}/public-key`: Retrieves the PEM-encoded public key for a given client.
- `GET /api/clients/{clientId}/new-private-key`: Generates a new RSA key pair for the client. The public key is stored on the server, and the private key is returned in the response body (PEM).

### 🔐 Authentication Flow
- `GET /api/challenge?clientId={id}`: Generates a challenge. Returns a `sessionId` and a joke question encrypted with the client's public key. Supports `Accept: application/json` (default) or `application/yaml`.
- `POST /api/answer?clientId={id}`: Verifies the client's answer. Requires `sessionId` and the signed answer in the request body (`application/x-www-form-urlencoded`). Returns a JSON JWT if successful.

## 🏗 Setup and Usage

### Prerequisites
- JDK 18 or higher
- Maven 3.6+

### Build
To build the project and create a shaded executable JAR:
```bash
mvn clean package
```

### Run
To start the server:
```bash
java -jar target/net.coffeetariat.gryptography-1.0-SNAPSHOT.jar [port]
```
The default port is `8080`.

### Configuration
- **Public Keys**: Stored in `clients-and-public-keys.yaml` in the working directory.
- **Private Keys (Optional)**: If the environment variable `TRACK_PRIVATE_KEYS=true` is set, the server will also track private keys in `clients-and-private-keys.yaml` (intended for demo/testing purposes only).

## ⚠️ Security Note
This project uses a custom joke-based challenge-response mechanism. While it demonstrates RSA and JWT concepts, it should be thoroughly reviewed before being used in production environments, particularly regarding session management and entropy of the challenges.
