# Secure Messaging Application with Diffie-Hellman Key Exchange

## Project Overview

This project implements a secure messaging application using the Diffie-Hellman key exchange method to securely share encryption keys between a client and a server. The application demonstrates the principles of secure communication over a network.

## Features

- **Secure Key Exchange**: Utilizes Diffie-Hellman to securely generate and share keys without transmitting them directly.
- **Multiple Messages**: Supports the sending and receiving of multiple messages.
- **Environment Configuration**: Uses environment variables for configuration settings.

## Prerequisites

- Go (version 1.15 or later)
- Access to a terminal for running the server and client

## Installation

1. **Clone the Repository**:
   ```bash
   git clone <your-repo-url>
   cd <your-repo-name>
    ```
2. **Create Up An Enviroment Files For Each Service and Add This**:
    ```Bash
    PRIME_NUMBER=2
    ```
3. **Do Not forget This Line for Client ENV**
     *we need this line for uncontainerised runtime env*
    ```
    SERVER_ADRESS=http://localhost:17
    ```
3. **To run Client and Server please Run This Code**
    ```Bash
    docker compose up
    ```