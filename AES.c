#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define Nb 4
#define TRUE 1
#define FALSE 0

#define MAX_MSG_LEN 256
#define KEY_LEN 16

typedef unsigned int word;
typedef unsigned char byte;
typedef int BOOLEAN;

char ent[128];
char sal[128];
char archivoLlave[128];
byte* datos;
byte* llave;
FILE *fpllave;
BOOLEAN cifrar = TRUE;
unsigned long tamArchivo;
int tipo;
int Nk = 4;
int Nr = 10;

const word rcon[] = {0x00000000, 0x01000000, 0x02000000,
0x04000000, 0x08000000, 0x10000000,
0x20000000, 0x40000000, 0x80000000,
0x1b000000, 0x36000000};


byte sbox[] = {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

byte inv_sbox[] = {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};

void subBytes();
void shiftRows();
void mixColumns();
int mulPol();
void imprimeEstado();
void uso();
void substring();
byte* leeDatos();
void cifraODescifra();
void ProcesaArgv();
void ProcesaArgv(int argc, char *argv[], byte** mensaje, int* tamMensaje, byte** llave);
void cifraODescifra(byte* datos, int tamDatos, byte* llave);

int main() {
    char mensaje[MAX_MSG_LEN];
    char llaveHex[KEY_LEN * 2 + 1]; // Cada byte en hex ocupa 2 caracteres
    unsigned char llave[KEY_LEN];

    // Pedir mensaje
    printf("Ingrese el mensaje a cifrar: ");
    fgets(mensaje, MAX_MSG_LEN, stdin);
    mensaje[strcspn(mensaje, "\n")] = 0; // Eliminar salto de línea

    // Pedir llave en formato hexadecimal
    printf("Ingrese la llave en hexadecimal (16 bytes, 32 caracteres): ");
    fgets(llaveHex, sizeof(llaveHex), stdin);
    llaveHex[strcspn(llaveHex, "\n")] = 0;

    // Verificar la longitud de la llave
    if (strlen(llaveHex) != 32) {
        printf("Error: La llave debe tener exactamente 32 caracteres hexadecimales.\n");
        exit(1);
    }

    // Convertir la llave de hexadecimal a bytes
    for (int i = 0; i < KEY_LEN; i++) {
        if (sscanf(llaveHex + 2 * i, "%2hhx", &llave[i]) != 1) {
            printf("Error: La llave ingresada no es válida.\n");
            exit(1);
        }
    }

    // Asegurar que Nk y Nr están bien definidos (para AES-128)
    Nk = 4;
    Nr = 10;

    // Mensajes de depuración
    printf("\nDatos recibidos:\n");
    printf("Mensaje: %s\n", mensaje);
    printf("Longitud del mensaje: %d\n", (int)strlen(mensaje));
    printf("Llave en bytes: ");
    for (int i = 0; i < KEY_LEN; i++) {
        printf("%02x ", llave[i]);
    }
    printf("\n");
    printf("Nk: %d, Nr: %d\n\n", Nk, Nr);

    // Verificar que el mensaje no esté vacío antes de cifrar
    if (strlen(mensaje) == 0) {
        printf("Error: El mensaje no puede estar vacío.\n");
        exit(1);
    }

    // Llamamos a la función de cifrado/descifrado
    cifraODescifra((unsigned char*)mensaje, strlen(mensaje), llave);

    return 0;
}


word toWord(byte a, byte b, byte c, byte d) {
    return (a & 0xff) << 24 | (b & 0x00ff) << 16 | (c & 0x0000ff) << 8 | d;
}


byte xtime(byte a) {
    return (a << 1 ^ ((a & 0x80) ? 0x1b : 0)) & 0xff;
}

byte xtime9(byte i) {
    byte i2 = xtime(i), i4 = xtime(i2), i8 = xtime(i4);
    return i8 ^ i;
}

byte xtime11(byte i) {
    byte i2 = xtime(i), i4 = xtime(i2), i8 = xtime(i4);
    return i8 ^ i2 ^ i;
}

byte xtime13(byte i) {
    byte i2 = xtime(i), i4 = xtime(i2), i8 = xtime(i4);
    return i8 ^ i4 ^ i;
}

byte xtime14(byte i) {
    byte i2 = xtime(i), i4 = xtime(i2), i8 = xtime(i4);
    return i8 ^ i4 ^ i2;
}

word subWord(word w) {
    word result = 0;
    for (int i = 0; i < 4; i++) result ^= sbox[(w >> (3 - i) * 8) & 0x000000ff] << (3 - i) * 8;
    return result;
}

word rotWord(word w) {
    return (w << 8 | w >> 24) & 0xffffffff;
}

void copySubArray(word* in, word* out, int i, int j) {
    for (int k = 0 ; i < j; i++, k++) out[k] = in[i];
}

void copySubArrayByte(byte* in, byte* out, int i, int j) {
    for (int k = 0 ; i < j; i++, k++) out[k] = in[i];
}

void subBytes(byte* state) {
    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

void shiftRows(byte* state) {
    byte* s = (byte*) malloc(16 * sizeof(byte));
    for (int r = 1; r < 4; r++) {
        for (int c = 0; c < Nb; c++) {
            s[c * 4 + r] = state[((c * 4 + r) + (4 * r)) % 16];
        }
        for (int c = 0; c < Nb; c++) {
            state[c * 4 + r] = s[c * 4 + r];
        }
    }
    free(s);
}

void mixColumns(byte* state) {
    for (int i = 0; i < 16; i += 4) {
        byte s0 = state[i], s1 = state[i + 1], s2 = state[i + 2], s3 = state[i + 3];
        state[i] = xtime(s0) ^ (s1 ^ xtime(s1)) ^ s2 ^ s3;
        state[i + 1] = s0 ^ xtime(s1) ^ (s2 ^ xtime(s2)) ^ s3;
        state[i + 2] = s0 ^ s1 ^ xtime(s2) ^ (s3 ^ xtime(s3));
        state[i + 3] = (s0 ^ xtime(s0)) ^ s1 ^ s2 ^ xtime(s3);
    }
}



void keyExpansion(byte* key, word* w, int nk) {
    word temp;
    int i = 0;
    while (i < nk) {
        w[i] = toWord(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
        i += 1;
    }
    i = nk;
    while (i < Nb * (Nr + 1)) {
        temp = w[i - 1];
        if (i % nk == 0)                temp = subWord(rotWord(temp)) ^ rcon[i / nk];
        else if (nk > 6 && i % nk == 4) temp = subWord(temp);
        w[i] = w[i - nk] ^ temp;
        i = i + 1;
    }
}

void addRoundKey(byte* state, word* key) {
    for (int i = 0; i < 4; i++) {
        state[i * 4] ^= key[i] >> 24 & 0x000000ff;
        state[(i * 4) + 1] ^= key[i] >> 16 & 0x000000ff;
        state[(i * 4) + 2] ^= key[i] >> 8 & 0x000000ff;
        state[(i * 4) + 3] ^= key[i] & 0x000000ff;
    }
}



void cipher(byte* in, byte* out, word* w) {
        byte* state = (byte*) malloc(4*Nb*sizeof(byte));
        word* aux = (word *) calloc(Nb,  sizeof(word));
    
        memcpy(state, in, 16);
        copySubArray(w, aux, 0, Nb);
        addRoundKey(state, aux);
    
        for (int i = 1; i < Nr; i++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        copySubArray(w, aux, i * Nb, (i + 1) * Nb);
        addRoundKey(state, aux);
    }

    subBytes(state);
    shiftRows(state);
    copySubArray(w, aux, Nr * Nb, (Nr + 1) * Nb);
    addRoundKey(state, aux);
    memcpy(out, state, 16);
    free(aux);
    free(state);
}

void invShiftRows(byte* state) {
    byte* s = (byte*) malloc(16 * sizeof(byte));
    for (int r = 1; r < 4; r++) {
        for (int c = 0; c < Nb; c++) {
            s[((c * 4 + r) + 4*r) % 16] = state[c * 4 + r];
        }
        for (int c = 0; c < Nb; c++) {
            state[c * 4 + r] = s[c * 4 + r];
        }
    }
    free(s);
}

void invSubBytes(byte* state) {
    for (int i = 0; i < 16; i++) state[i] = inv_sbox[state[i]];
}

void invMixColumns(byte* state) {
    int i;
    for (i = 0; i < 16; i += 4) {
        byte s0 = state[i], s1 = state[i + 1], s2 = state[i + 2], s3 = state[i + 3];
        state[i] = xtime14(s0) ^ xtime11(s1) ^ xtime13(s2) ^ xtime9(s3);
        state[i + 1] = xtime9(s0) ^ xtime14(s1) ^ xtime11(s2) ^ xtime13(s3);
        state[i + 2] = xtime13(s0) ^ xtime9(s1) ^ xtime14(s2) ^ xtime11(s3);
        state[i + 3] = xtime11(s0) ^ xtime13(s1) ^ xtime9(s2) ^ xtime14(s3);
    }
}

void invCipher(byte* in, byte* out, word* w) {
    byte* state = (byte*) malloc(4*Nb*sizeof(byte));
    word* aux = (word *) calloc(Nb,  sizeof(word));

    memcpy(state, in, 16);

    copySubArray(w, aux, Nr*Nb, (Nr + 1) * Nb);
    addRoundKey(state, aux);

    for (int i = Nr - 1; i > 0; i--) {
        invShiftRows(state);
        invSubBytes(state);
        copySubArray(w, aux, i*Nb, (i + 1) * Nb);
        addRoundKey(state, aux);
        invMixColumns(state);
    }

    invShiftRows(state);
    invSubBytes(state);
    copySubArray(w, aux, 0, Nb);
    addRoundKey(state, aux);
    memcpy(out, state, 16);
    free(aux);
    free(state);
}

void imprimeEstado(byte* state) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", state[j * 4 + i]);
        }
        printf("\n");
    }
}

void substring(char s[], char sub[], int p, int l) {
    int c = 0;
    while (c < l) {
        sub[c] = s[p+c-1];
        c++;
    }
    sub[c] = '\0';
}

void cifra(byte* input, byte* output, word* expandedKeys, int longEnt, int* longSal) {
    int longPad = 16 - (longEnt % 16);
    byte* state = (byte*) calloc(4 *Nb, sizeof(byte));
    byte* out = (byte*) calloc(4 * Nb, sizeof(byte));
    for(int i=0; i < longPad; i++) {
        input[longEnt + i] = (unsigned int)longPad;
    }
    *longSal = longEnt + longPad;  /* La longitud del buffer por cifrar. */
    /* ¡A cifrar! */
    for(int i=0; i < *longSal; i+=16) {
        copySubArrayByte(input, state, i, i + 16);
        cipher(state, out, expandedKeys);
        for (int j = 0; j < 16; j++) {
            output[i+j] = out[j];
        }
    }
}

void descifra(byte* input, byte* output, word* expandedKeys, int longEnt,int *longSal) {
    byte* state = (byte*) calloc(4 * Nb, sizeof(byte));
    byte* out = (byte*) calloc(4 * Nb, sizeof(byte));
    /* ¡A descifrar! */
    for (int i = 0; i < longEnt; i += 16) {
        copySubArrayByte(input, state, i, i + 16);
        invCipher(state, out, expandedKeys);
        for (int j = 0; j < 16; j++) {
            output[i+j] = out[j];
        }
    }
    *longSal = longEnt - (byte) output[longEnt - 1];  /* Quitamos padding. */
}
void cifraODescifra(byte* datos, int tamDatos, byte* llave) {
    int tamSalida;
    byte* salida = (byte*) calloc(tamDatos + 16, sizeof(byte));
    word* w = (word*) calloc(Nb * (Nr + 1), sizeof(word));

    keyExpansion(llave, w, Nk);

    if (cifrar) {
        cifra(datos, salida, w, tamDatos, &tamSalida);
        printf("Mensaje cifrado: ");
    } else {
        descifra(datos, salida, w, tamDatos, &tamSalida);
        printf("Mensaje descifrado: ");
    }

    for (int i = 0; i < tamSalida; i++) {
        printf("%02x ", salida[i]);
    }
    printf("\n");

    free(salida);
    free(w);
}

byte* leeDatos(char* nombre) {
    FILE *archivo;
    int pad;
    byte* datos;
    archivo = fopen(nombre, "rb");
    if (!archivo) {
        fprintf(stderr, "No se puede abrir el archivo %s\n", nombre);
        exit(1);
    }
    fseek(archivo, 0, SEEK_END);
    tamArchivo = ftell(archivo);
    pad = 16 - (tamArchivo % 16);
    fseek(archivo, 0, SEEK_SET);
    datos = malloc(tamArchivo + pad);
    if (!datos) {
        fprintf(stderr, "Error de memoria!");
        fclose(archivo);
        exit(1);
    }
    fread(datos, tamArchivo, 1, archivo);
    fclose(archivo);
    return datos;
}


void ProcesaArgv(int argc, char *argv[], byte** mensaje, int* tamMensaje, byte** llave) {
    if (argc < 3) {
        printf("\nUso: aes [-c | -d] [-128 | -192 | -256] \"mensaje\" \"llave\"\n");
        printf("Ejemplo: aes -c -128 \"Hola, mundo!\" \"00112233445566778899aabbccddeeff\"\n");
        exit(1);
    }

    // Determinar si se cifra o descifra
    if (argv[1][0] == '-') {
        switch (argv[1][1]) {
        case 'c':
            cifrar = TRUE;
            break;
        case 'd':
            cifrar = FALSE;
            break;
        default:
            printf("Opción inválida. Usa -c para cifrar o -d para descifrar.\n");
            exit(1);
        }
    }

    // Determinar el tipo de clave (128, 192, 256 bits)
    if (strcmp(argv[2], "-128") == 0) {
        tipo = 128; Nk = 4; Nr = 10;
    } else if (strcmp(argv[2], "-192") == 0) {
        tipo = 192; Nk = 6; Nr = 12;
    } else if (strcmp(argv[2], "-256") == 0) {
        tipo = 256; Nk = 8; Nr = 14;
    } else {
        printf("Tipo de clave inválido. Usa -128, -192 o -256.\n");
        exit(1);
    }

    // Leer mensaje de la línea de comandos
    *tamMensaje = strlen(argv[3]);
    *mensaje = (byte*) malloc((*tamMensaje) + 16);  // Asegurar espacio para padding
    memcpy(*mensaje, argv[3], *tamMensaje);

    // Leer llave en hexadecimal
    int longClave = tipo / 8;  // 16 bytes para 128-bit, 24 para 192-bit, 32 para 256-bit
    *llave = (byte*) malloc(longClave);
    for (int i = 0; i < longClave; i++) {
        sscanf(&argv[4][i * 2], "%2hhx", &((*llave)[i]));  // Convertir hex a byte
    }
}

