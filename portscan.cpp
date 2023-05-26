/* 	Garrett Jennings | ZID: Z1927185
	
	I certify that this is my own work and where appropriate an extension 
	of the starter code provided for the assignment.
*/

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/err.h>

constexpr char SERVER_IP[] = "10.158.56.43";
constexpr int START_PORT = 9000;
constexpr int END_PORT = 9100;
constexpr int KEY_SIZE = 16;

/**
 * Scans UDP ports until one responds with a key
 * @param out_key Buffer that receives the key
 * @return success
 */
bool scan_udp(unsigned char *out_key)
{
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
  {
    perror("Failed to create socket");
    exit(EXIT_FAILURE);
  }

  // Setup struct for the target address
  struct sockaddr_in target;
  memset(&target, 0, sizeof(target));
  target.sin_family = AF_INET;
  target.sin_addr.s_addr = inet_addr(SERVER_IP);

  // Set the timeout for how long to wait for a response
  struct timeval read_timeout;
  read_timeout.tv_sec = 0;
  read_timeout.tv_usec = 200000;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));

  char buffer[1024];

  for (int port = START_PORT; port <= END_PORT; ++port)
  {
    // Set the port and send "group 5"
    target.sin_port = htons(port);

    if (sendto(sock, "group 5", 7, 0, (struct sockaddr *)&target, sizeof(target)) < 0)
    {
      perror("UDP sendto");
      exit(EXIT_FAILURE);
    }

    // Receive a response
    socklen_t addrlen = sizeof(target);
    ssize_t num_received = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&target, &addrlen);

    // Check if response was received and continue to next port if not
    if (num_received < 0)
    {
      if (errno == EWOULDBLOCK)
      {
        std::cout << '.' << std::flush;
        continue;
      }
      else
      {
        perror("UDP recvfrom");
        exit(EXIT_FAILURE);
      }
    }

    if (num_received == KEY_SIZE)
    {
      // Copy key to output buffer and print which port it was received from
      memcpy(out_key, buffer, KEY_SIZE);
      auto time = std::time(nullptr);
      std::cout << std::endl
                << "Received key from port " << port << " at " << std::asctime(std::localtime(&time));
      close(sock);
      return true;
    }
    else
    {
      buffer[num_received] = '\0';
      std::cerr << std::endl
                << "Received UDP response with length not equal to key size: " << buffer << std::endl;
    }
  }

  close(sock);
  return false;
}

/**
 * Prints any error messages, frees the context, and exits the program
 */
void handle_evp_error(EVP_CIPHER_CTX *ctx)
{
  ERR_print_errors_fp(stderr);
  if (ctx != NULL)
  {
    EVP_CIPHER_CTX_free(ctx);
  }
  exit(EXIT_FAILURE);
}

/**
 * Reads from the socket, decrypts the message with the key, and prints the key
 * @param sock The socket to read from
 * @param key The decryption key
 * @return success
 */
bool decrypt_from_socket(int sock, const unsigned char *const key)
{
  unsigned char read_buffer[1024];
  unsigned char decrypted_buffer[1025];

  // Create and initialize cipher context
  const EVP_CIPHER *cipher = EVP_rc4();
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
  {
    close(sock);
    handle_evp_error(ctx);
  }

  if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, NULL))
  {
    close(sock);
    handle_evp_error(ctx);
  }

  ssize_t read_length;
  int decrypted_length;

  // Read from the socket until the end is reached
  while ((read_length = read(sock, read_buffer, sizeof(read_buffer))) != 0)
  {
    // Print if there was an error while reading
    if (read_length < 0)
    {
      EVP_CIPHER_CTX_free(ctx);
      close(sock);
      perror("TCP read");
      exit(EXIT_FAILURE);
    }

    // Update the decryption context with the next block of ciphertext
    if (!EVP_DecryptUpdate(ctx, decrypted_buffer, &decrypted_length, read_buffer, read_length))
    {
      close(sock);
      handle_evp_error(ctx);
    }

    // Output the decrypted text
    std::cout.write(reinterpret_cast<char *>(decrypted_buffer), decrypted_length);
  }

  // Get any remaining decrypted data
  if (!EVP_DecryptFinal_ex(ctx, decrypted_buffer, &decrypted_length))
  {
    close(sock);
    handle_evp_error(ctx);
  }

  // Write the last block of data
  std::cout.write(reinterpret_cast<char *>(decrypted_buffer), decrypted_length);

  EVP_CIPHER_CTX_free(ctx);

  return true;
}

/**
 * Scan the tcp ports for a message, decrypt it with the key, and print it
 * @param key The decryption key
 * @return success
 */
bool scan_tcp(const unsigned char *const key)
{
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
  {
    perror("Failed to create socket");
    exit(EXIT_FAILURE);
  }

  // Setup struct for the target address
  struct sockaddr_in target;
  memset(&target, 0, sizeof(target));
  target.sin_family = AF_INET;
  target.sin_addr.s_addr = inet_addr(SERVER_IP);

  for (int port = START_PORT; port <= END_PORT; ++port)
  {
    // Set the target port and connect to it
    target.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *)&target, sizeof(target)) < 0)
    {
      // Check if the connection was refused and continue to the next port if so
      if (errno == ECONNREFUSED)
      {
        std::cout << '.' << std::flush;
        continue;
      }
      else
      {
        perror("TCP connect");
        exit(EXIT_FAILURE);
      }
    }

    // Send the group message to the server
    if (write(sock, "group 5", 7) < 0)
    {
      perror("TCP write");
      exit(EXIT_FAILURE);
    }

    auto time = std::time(nullptr);
    std::cout << std::endl
              << "Received message from port " << port << " at " << std::asctime(std::localtime(&time));
    std::cout << "The message is: " << std::endl
              << std::endl;

    // Read the message, decrypt it, and write it to output
    bool read_success = decrypt_from_socket(sock, key);
    close(sock);
    return read_success;
  }

  return false;
}

int main()
{
  unsigned char key[KEY_SIZE];

  // Scan for the key on udp ports
  bool success = scan_udp(key);

  if (!success)
  {
    std::cerr << "Failed to get key from UDP" << std::endl;
    return 1;
  }

  std::cout << "The key is: ";
  for (int i = 0; i < KEY_SIZE; ++i)
  {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key[i]);
  }
  std::cout << std::dec << std::endl;

  // Scan and print the message from tpc ports
  if (!scan_tcp(key))
  {
    std::cerr << "Failed to get the message from TCP" << std::endl;
  }

  return 0;
}
