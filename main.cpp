#include <stdio.h>

#define MAX_NAME_LEN 256
#define MAX_ELE_NUM 128

struct ms_dos {
    char fields[0x3C];
    long e_lfanew;
};

struct image_file_header {
    short fields[10];
};

struct image_data_directory {
    int virturaladdress;
    int size;
};
struct image_optional_header {
    short fields_words[9];
    char fields_bytes[2];
    int fields_dwords[19];
    image_data_directory datadirectory[2]; /* only include the import directory*/
};

struct image_nt_headers {
    int signature;
    struct image_file_header fileheader;
    struct image_optional_header optionalheader;
};

struct image_import_descriptor {
    union {
        int characteristics;
        int originalfirstthunk;
    };
    int timedatestamp;
    int forwarderchain;
    int name;
    int firstthunk;
};

struct image_import_by_name {
    short hint;
    char Name[256];
};

struct image_thunk_data {
    union {
        int forwarderstring;
        int function;
        int ordinal;
        int addressofdata;
    }u1;

};

int rva2offset(char* addr) {
    return *((int*)addr);
}
int main()
{
    FILE* pe;
    struct ms_dos ms_dos;
    struct image_nt_headers image_nt_headers;
    struct image_data_directory* datadirectory;
    struct image_data_directory importdirectory;
    struct image_import_descriptor image_import_descriptor[MAX_ELE_NUM], *desc;
    struct image_thunk_data image_thunk_datas[MAX_ELE_NUM], *thunk_desc;
    struct image_import_by_name image_import_by_name;
    int size;
    char name[256];
    if ((pe = fopen("C:\\Users\\sjx\\Documents\\test1\\LoadOrd.exe", "r")) == NULL) {
        printf("cannot open the pe file\n");
        return -1;
    }
    size = fread(&ms_dos, sizeof(ms_dos), 1, pe);

    fseek(pe, ms_dos.e_lfanew, SEEK_SET);
    size = fread(&image_nt_headers, sizeof(image_nt_headers), 1, pe);
    datadirectory = image_nt_headers.optionalheader.datadirectory;
    importdirectory = datadirectory[1];
    printf("import table va:%#x, size:%#x\n", importdirectory.virturaladdress, importdirectory.size);
    fseek(pe, importdirectory.virturaladdress, SEEK_SET);
    
    size = fread(&image_import_descriptor, sizeof(struct image_import_descriptor), MAX_ELE_NUM, pe);
    for (int i = 0; i < MAX_ELE_NUM; i++) {
        desc = image_import_descriptor + i;
        if (desc->originalfirstthunk == NULL) {
            break;
        }
        printf("\nname rva:%#x\toriginalFirstThunk rva: %#x\t", desc->name, desc->originalfirstthunk);

        // name
        fseek(pe, desc->name, SEEK_SET);
        // assume the lenght of the dll name no more than 255
        fread(name, sizeof(char), 256, pe);
        printf("dll name:%s\n", name);

        // INT
        fseek(pe, desc->originalfirstthunk, SEEK_SET);
        fread(image_thunk_datas, sizeof(image_thunk_datas), 1, pe);
        for (int i = 0; i < MAX_ELE_NUM; i++) {
            thunk_desc = image_thunk_datas + i;
            if (thunk_desc->u1.addressofdata == 0) {
                break;
            }
            printf("import by");
            if (thunk_desc->u1.ordinal & 0x80000000) {
                printf(" api hint\n");        
            }
            else {
                    
                fseek(pe, thunk_desc->u1.ordinal, SEEK_SET);
                // assume the lenght of the dll name no more than 255
                fread(&image_import_by_name, sizeof(image_import_by_name), 1, pe);
                printf(" name : %s\n", image_import_by_name.Name);
            }
                
        }
    }
    return 0;
}
