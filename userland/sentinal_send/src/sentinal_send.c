/*
 * SentinalOS Encrypted File Transfer Application
 * Pentagon-Level Security Communications
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <getopt.h>
#include <termios.h>
#include <stdbool.h>
#include "crypto.h"

#define VERSION "1.0.0-Pentagon"
#define MAX_FILENAME 256
#define MAX_PASSWORD 128
#define BUFFER_SIZE 8192
#define SALT_SIZE 16

/* Command line options */
struct options {
    char *input_file;
    char *output_file;
    char *password;
    char *source_system;
    char *dest_system;
    uint8_t classification;
    uint8_t user_clearance;
    bool encrypt_mode;
    bool decrypt_mode;
    bool verbose;
    bool force_overwrite;
};

/* File header for encrypted files */
struct file_header {
    uint8_t magic[8];           /* "SENTINAL" */
    uint8_t version[4];         /* Version info */
    uint8_t classification;     /* Security classification */
    uint8_t flags;              /* Various flags */
    uint16_t reserved;          /* Reserved for future use */
    uint8_t salt[SALT_SIZE];    /* Password salt */
    uint8_t iv[AES_BLOCK_SIZE]; /* Initialization vector */
    uint64_t original_size;     /* Original file size */
    uint32_t checksum;          /* Integrity checksum */
    uint32_t header_checksum;   /* Header checksum */
} __attribute__((packed));

/* Classification levels */
static const char *classification_names[] = {
    "UNCLASSIFIED",
    "CONFIDENTIAL", 
    "SECRET",
    "TOP SECRET",
    "PENTAGON"
};

static void print_banner(void) {
    printf("\n");
    printf(" ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗ █████╗ ██╗         ███████╗███████╗███╗   ██╗██████╗ \n");
    printf(" ███████║██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔══██╗██║         ██╔════╝██╔════╝████╗  ██║██╔══██╗\n");
    printf(" ███████║███████╗██╔██╗ ██║   ██║   ██║██╔██╗ ██║███████║██║         ███████╗█████╗  ██╔██╗ ██║██║  ██║\n");
    printf(" ╚════██║██╔════╝██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══██║██║         ╚════██║██╔══╝  ██║╚██╗██║██║  ██║\n");
    printf(" ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║██║  ██║███████╗    ███████║███████╗██║ ╚████║██████╔╝\n");
    printf(" ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═══╝╚═════╝ \n");
    printf("\n");
    printf("                    Pentagon-Level Secure File Transfer System v%s\n", VERSION);
    printf("                           Classification: TOP SECRET // SI // NOFORN\n");
    printf("\n");
}

static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("Pentagon-Level Secure File Transfer Application\n\n");
    printf("Options:\n");
    printf("  -e, --encrypt              Encrypt mode\n");
    printf("  -d, --decrypt              Decrypt mode\n");
    printf("  -i, --input FILE           Input file\n");
    printf("  -o, --output FILE          Output file\n");
    printf("  -p, --password PASS        Encryption password\n");
    printf("  -s, --source SYSTEM        Source system identifier\n");
    printf("  -t, --target SYSTEM        Target system identifier\n");
    printf("  -c, --classification LEVEL Classification level (0-4)\n");
    printf("                             0=UNCLASSIFIED, 1=CONFIDENTIAL\n");
    printf("                             2=SECRET, 3=TOP SECRET, 4=PENTAGON\n");
    printf("  -u, --clearance LEVEL      User security clearance (0-4)\n");
    printf("  -v, --verbose              Verbose output\n");
    printf("  -f, --force                Force overwrite existing files\n");
    printf("  -h, --help                 Show this help\n");
    printf("\nExamples:\n");
    printf("  %s -e -i document.txt -o document.enc -c 4 -s WORKSTATION -t SERVER\n", program_name);
    printf("  %s -d -i document.enc -o document.txt -u 4\n", program_name);
    printf("\nSecurity Notes:\n");
    printf("  • All communications are logged and audited\n");
    printf("  • User clearance must meet or exceed file classification\n");
    printf("  • Passwords are derived using secure key derivation\n");
    printf("  • Files are encrypted using AES-256-CBC with random IV\n");
}

static char *secure_getpass(const char *prompt) {
    static char password[MAX_PASSWORD];
    struct termios old_flags, new_flags;
    
    printf("%s", prompt);
    fflush(stdout);
    
    /* Disable echo */
    tcgetattr(STDIN_FILENO, &old_flags);
    new_flags = old_flags;
    new_flags.c_lflag &= ~ECHO;
    new_flags.c_lflag |= ECHONL;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_flags);
    
    /* Read password */
    if (fgets(password, sizeof(password), stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_flags);
        return NULL;
    }
    
    /* Restore echo */
    tcsetattr(STDIN_FILENO, TCSANOW, &old_flags);
    
    /* Remove newline */
    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
    }
    
    return password;
}

static uint32_t calculate_checksum(const uint8_t *data, size_t len) {
    uint32_t checksum = 0;
    for (size_t i = 0; i < len; i++) {
        checksum = (checksum << 1) ^ data[i];
    }
    return checksum;
}

static int encrypt_file(const struct options *opts) {
    struct aes_context aes_ctx;
    struct security_context sec_ctx;
    struct file_header header;
    uint8_t key[AES_KEY_SIZE];
    uint8_t buffer[BUFFER_SIZE];
    int input_fd, output_fd;
    struct stat file_stat;
    
    printf("[ENCRYPT] Initializing Pentagon-level encryption...\n");
    
    /* Create security context */
    if (create_security_context(&sec_ctx, opts->classification, 
                               opts->source_system, opts->dest_system) != 0) {
        fprintf(stderr, "Error: Failed to create security context\n");
        return -1;
    }
    
    /* Verify user clearance */
    if (verify_security_clearance(&sec_ctx, opts->user_clearance) != 0) {
        fprintf(stderr, "Error: Insufficient security clearance\n");
        fprintf(stderr, "Required: %s, User has: %s\n",
                classification_names[opts->classification],
                classification_names[opts->user_clearance]);
        return -1;
    }
    
    /* Open input file */
    input_fd = open(opts->input_file, O_RDONLY);
    if (input_fd < 0) {
        fprintf(stderr, "Error: Cannot open input file '%s': %s\n", 
                opts->input_file, strerror(errno));
        return -1;
    }
    
    /* Get file statistics */
    if (fstat(input_fd, &file_stat) != 0) {
        fprintf(stderr, "Error: Cannot stat input file: %s\n", strerror(errno));
        close(input_fd);
        return -1;
    }
    
    /* Create output file */
    int flags = O_WRONLY | O_CREAT;
    if (!opts->force_overwrite) {
        flags |= O_EXCL;
    } else {
        flags |= O_TRUNC;
    }
    
    output_fd = open(opts->output_file, flags, 0600);
    if (output_fd < 0) {
        fprintf(stderr, "Error: Cannot create output file '%s': %s\n", 
                opts->output_file, strerror(errno));
        close(input_fd);
        return -1;
    }
    
    /* Initialize header */
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, "SENTINAL", 8);
    header.version[0] = 1;
    header.version[1] = 0;
    header.version[2] = 0;
    header.version[3] = 0;
    header.classification = opts->classification;
    header.flags = 0x01; /* Encrypted flag */
    header.original_size = file_stat.st_size;
    
    /* Generate salt and IV */
    if (generate_random_salt(header.salt, SALT_SIZE) != 0 ||
        generate_random_iv(header.iv) != 0) {
        fprintf(stderr, "Error: Failed to generate cryptographic parameters\n");
        close(input_fd);
        close(output_fd);
        return -1;
    }
    
    /* Derive key from password */
    if (derive_key_from_password(opts->password, header.salt, key) != 0) {
        fprintf(stderr, "Error: Key derivation failed\n");
        close(input_fd);
        close(output_fd);
        return -1;
    }
    
    /* Initialize AES */
    if (aes_init(&aes_ctx, key, header.iv) != 0) {
        fprintf(stderr, "Error: AES initialization failed\n");
        close(input_fd);
        close(output_fd);
        return -1;
    }
    
    /* Calculate header checksum */
    header.header_checksum = calculate_checksum((uint8_t*)&header, 
                                               sizeof(header) - sizeof(header.header_checksum));
    
    /* Write header */
    if (write(output_fd, &header, sizeof(header)) != sizeof(header)) {
        fprintf(stderr, "Error: Failed to write header\n");
        aes_cleanup(&aes_ctx);
        close(input_fd);
        close(output_fd);
        return -1;
    }
    
    /* Encrypt file data */
    printf("[ENCRYPT] Processing %ld bytes with AES-256-CBC...\n", file_stat.st_size);
    
    size_t total_encrypted = 0;
    ssize_t bytes_read;
    
    while ((bytes_read = read(input_fd, buffer, BUFFER_SIZE)) > 0) {
        /* Pad to block size */
        size_t padded_size = ((bytes_read + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        if (padded_size > bytes_read) {
            memset(buffer + bytes_read, padded_size - bytes_read, padded_size - bytes_read);
        }
        
        /* Encrypt */
        if (aes_encrypt_cbc(&aes_ctx, buffer, padded_size, buffer) != 0) {
            fprintf(stderr, "Error: Encryption failed\n");
            aes_cleanup(&aes_ctx);
            close(input_fd);
            close(output_fd);
            return -1;
        }
        
        /* Write encrypted data */
        if (write(output_fd, buffer, padded_size) != padded_size) {
            fprintf(stderr, "Error: Failed to write encrypted data\n");
            aes_cleanup(&aes_ctx);
            close(input_fd);
            close(output_fd);
            return -1;
        }
        
        total_encrypted += padded_size;
        
        if (opts->verbose) {
            printf("\r[ENCRYPT] Progress: %zu/%zu bytes", total_encrypted, 
                   (size_t)file_stat.st_size);
            fflush(stdout);
        }
    }
    
    if (opts->verbose) {
        printf("\n");
    }
    
    /* Cleanup */
    aes_cleanup(&aes_ctx);
    secure_memset(key, 0, sizeof(key));
    secure_memset(buffer, 0, sizeof(buffer));
    close(input_fd);
    close(output_fd);
    
    printf("[ENCRYPT] File successfully encrypted\n");
    printf("[ENCRYPT] Classification: %s\n", classification_names[opts->classification]);
    printf("[ENCRYPT] Output: %s\n", opts->output_file);
    
    /* Audit log */
    audit_log_operation(&sec_ctx, "FILE_ENCRYPT", opts->input_file);
    
    return 0;
}

int main(int argc, char *argv[]) {
    struct options opts = {0};
    int opt;
    
    static struct option long_options[] = {
        {"encrypt",        no_argument,       0, 'e'},
        {"decrypt",        no_argument,       0, 'd'},
        {"input",          required_argument, 0, 'i'},
        {"output",         required_argument, 0, 'o'},
        {"password",       required_argument, 0, 'p'},
        {"source",         required_argument, 0, 's'},
        {"target",         required_argument, 0, 't'},
        {"classification", required_argument, 0, 'c'},
        {"clearance",      required_argument, 0, 'u'},
        {"verbose",        no_argument,       0, 'v'},
        {"force",          no_argument,       0, 'f'},
        {"help",           no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    /* Default values */
    opts.classification = 4; /* Pentagon level */
    opts.user_clearance = 0; /* Must be specified */
    opts.source_system = "UNKNOWN";
    opts.dest_system = "UNKNOWN";
    
    print_banner();
    
    /* Parse command line */
    while ((opt = getopt_long(argc, argv, "edi:o:p:s:t:c:u:vfh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'e':
                opts.encrypt_mode = true;
                break;
            case 'd':
                opts.decrypt_mode = true;
                break;
            case 'i':
                opts.input_file = optarg;
                break;
            case 'o':
                opts.output_file = optarg;
                break;
            case 'p':
                opts.password = optarg;
                break;
            case 's':
                opts.source_system = optarg;
                break;
            case 't':
                opts.dest_system = optarg;
                break;
            case 'c':
                opts.classification = atoi(optarg);
                if (opts.classification > 4) {
                    fprintf(stderr, "Error: Invalid classification level\n");
                    return 1;
                }
                break;
            case 'u':
                opts.user_clearance = atoi(optarg);
                if (opts.user_clearance > 4) {
                    fprintf(stderr, "Error: Invalid clearance level\n");
                    return 1;
                }
                break;
            case 'v':
                opts.verbose = true;
                break;
            case 'f':
                opts.force_overwrite = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    /* Validate arguments */
    if (!opts.encrypt_mode && !opts.decrypt_mode) {
        fprintf(stderr, "Error: Must specify either -e (encrypt) or -d (decrypt)\n");
        return 1;
    }
    
    if (opts.encrypt_mode && opts.decrypt_mode) {
        fprintf(stderr, "Error: Cannot specify both encrypt and decrypt modes\n");
        return 1;
    }
    
    if (!opts.input_file || !opts.output_file) {
        fprintf(stderr, "Error: Must specify input and output files\n");
        return 1;
    }
    
    /* Get password if not provided */
    if (!opts.password) {
        opts.password = secure_getpass("Enter encryption password: ");
        if (!opts.password) {
            fprintf(stderr, "Error: Failed to read password\n");
            return 1;
        }
    }
    
    /* Execute operation */
    int result;
    if (opts.encrypt_mode) {
        result = encrypt_file(&opts);
    } else {
        /* TODO: Implement decrypt_file() */
        fprintf(stderr, "Error: Decrypt mode not yet implemented\n");
        result = -1;
    }
    
    /* Clear password from memory */
    if (opts.password) {
        secure_memset(opts.password, 0, strlen(opts.password));
    }
    
    return result ? 1 : 0;
}