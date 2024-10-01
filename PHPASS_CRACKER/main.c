
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>
#include <winerror.h>
#include <stdio.h>
#include <sal.h>
#include <bcrypt.h>


#pragma comment(lib, "bcrypt.lib")
#define HASH_LENGTH 16


const BYTE* itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

void encode64(const unsigned char* input, int count, char* output) {
    int cur = 0;
    int output_index = 0;

    while (cur < count) {
        int value = input[cur++];
        output[output_index++] = itoa64[value & 0x3f];

        if (cur < count) {
            value |= (input[cur] << 8);
        }
        output[output_index++] = itoa64[(value >> 6) & 0x3f];

        if (cur >= count) {
            break;
        }

        cur++;
        if (cur < count) {
            value |= (input[cur] << 16);
        }
        output[output_index++] = itoa64[(value >> 12) & 0x3f];

        if (cur >= count) {
            break;
        }

        cur++;
        output[output_index++] = itoa64[(value >> 18) & 0x3f];
    }
}

ULONG get_round(PBYTE setting) {
    for (ULONG i = 0; i < 63; i++) {
        if (setting[3] == itoa64[i])
            return pow(2,i);
    }
}

void print_hash(PBYTE hash, ULONG length) {
    for (size_t i = 0; i < length; i++) {
        printf("%c", hash[i]);
    }
    printf("\n");
}


void
ReportError(
    _In_    DWORD       dwErrCode
)
{
    wprintf(L"Error: 0x%08x (%d)\n", dwErrCode, dwErrCode);
}



void compute_hash(PBYTE input, ULONG input_len, BCRYPT_ALG_HANDLE hAlgorithm ,BCRYPT_ALG_HANDLE hHash, PBYTE Hash) {

    NTSTATUS    Status;

    Status = BCryptCreateHash(hAlgorithm, &hHash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(Status))
    {
        ReportError(Status);
    }

    Status = BCryptHashData(hHash,input, input_len,0);
    if (!NT_SUCCESS(Status))
    {
        ReportError(Status);
    }

    Status = BCryptFinishHash(hHash,Hash,HASH_LENGTH, 0);

    if (!NT_SUCCESS(Status))
    {
        ReportError(Status);
    }

    BCryptDestroyHash(hHash);

}


void crypt_private(PBYTE password, ULONG password_lenght, PBYTE setting, PBYTE output) {
    BYTE salt[8];
    ULONG concat_len = password_lenght;
    PBYTE concat = (BYTE*)(PBYTE)HeapAlloc(GetProcessHeap(), 0, 8 +password_lenght);
    BCRYPT_ALG_HANDLE hAlgorithm;
    BCRYPT_HASH_HANDLE hHash;

    BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_MD5_ALGORITHM, NULL, BCRYPT_HASH_REUSABLE_FLAG);
    BCryptCreateHash(hAlgorithm, &hHash, NULL, 0, NULL, 0, 0);

    
    
    if (concat == NULL) {
        ReportError(ERROR_OUTOFMEMORY);
        return;  // Gérer l'erreur d'allocation
    }
    memcpy(salt, setting + 4, 8);
    memcpy(concat, salt, 8);
    memcpy(concat + 8, password, password_lenght);

    ULONG concat_lenght = 8 + password_lenght;

    PBYTE hash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, HASH_LENGTH);
    compute_hash(concat, concat_lenght, hAlgorithm,hHash,hash);


    ULONG temp_lenght = password_lenght + HASH_LENGTH;
    ULONG round;

    round = get_round(setting);
    for (int i = 0; i < round; i++) {
        PBYTE temp = (PBYTE)HeapAlloc(GetProcessHeap(), 0, temp_lenght);
        memcpy(temp, hash, HASH_LENGTH);
        memcpy(temp + HASH_LENGTH, password, password_lenght);
        compute_hash(temp, temp_lenght ,hAlgorithm, hHash,hash);
        if (temp != NULL) {
            HeapFree(GetProcessHeap(), 0, temp);
        }
        
    }

    unsigned char final_hash[22];
    encode64(hash, 16, final_hash);

    memcpy(output, setting, 12);
    memcpy(output + 12, final_hash,22);

    if (concat != NULL) {
        HeapFree(GetProcessHeap(), 0, concat);
    }

    if (hash != NULL) {
        HeapFree(GetProcessHeap(), 0, hash);
    }

    if (hHash != NULL) {
        BCryptDestroyHash(hHash);
    }

    if (hAlgorithm != NULL) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }

}


BOOL check_password(BYTE* Hash, BYTE* password, ULONG password_lenght) {
    BYTE computed_hash[34];
    crypt_private(password, password_lenght, Hash, computed_hash);
    return (memcmp(computed_hash,Hash,34) == 0);
}

int main() {


    FILE* file = fopen("input.txt", "r");
    if (file == NULL) {
        perror("Erreur d'ouverture du fichier");
        return 1;
    }

    char line[256];

    int cpt = 0;
    while (fgets(line, sizeof(line), file)) {

        line[strcspn(line, "\n")] = '\0';

        const char delimiter[] = ":";

        char* token = strtok(line, delimiter);

        PBYTE password = NULL;
        PBYTE HASH = NULL;
        ULONG password_lenght;
        int index = 1;


        while (token != NULL) {
            if (index == 1) {
                password_lenght = strlen(token);
                password = (PBYTE)HeapAlloc(GetProcessHeap(), 0, password_lenght);
                memcpy(password, token, password_lenght);
            }
            if (index == 2) {
                HASH = (PBYTE)HeapAlloc(GetProcessHeap(), 0,34);
                memcpy(HASH, token, 34);
            }
            index++;

            token = strtok(NULL, delimiter);
        }

        cpt += 1;
        if (password != NULL && HASH != NULL){
        if (check_password(HASH, password, password_lenght)) {
            printf("\npassword found : ");
            print_hash(password, password_lenght);
            printf("---------------------\n");
        }
        }
        if (HASH != NULL) {
            HeapFree(GetProcessHeap(), 0, HASH);
        }

        if (password != NULL) {
            HeapFree(GetProcessHeap(), 0, password);
        }

        if (cpt % 1000 == 0) {
            printf("Nomber of hash computed : %d \n", cpt);
        }
            

    }

    fclose(file);
    printf("\nPress a key to quit ....");
    getchar();

}
