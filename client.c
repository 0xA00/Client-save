#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <dirent.h>
#include <jansson.h>
#include <openssl/sha.h>

char *ip;
int port;
#define FALSE 0
#define TRUE 7




int verbose = FALSE;
int GLOBAL_CONFIG = FALSE;
int IsFolder = FALSE;
int IsHTTP = FALSE;

void print_help()
{
    printf("Usage: client [options]\n");
    printf("Options:\n");
    printf("  -h, --help\t\t\tPrint this help message and exit\n");
    printf("  -v, --verbose\t\t\tVerbose output\n");
    printf("  -cc, --customconfig\t\t\tcustom .saveconfig will be used\n");
    printf("  -i, --ip\t\t\tIP address of the server\n");
    printf("  -p, --port\t\t\tPort of the server\n");
    printf("      -https\t\t\tUse HTTPS protocol\n");
}

size_t read_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
    FILE *file = (FILE *)stream;
    if (!file)
        return 0; // Return 0 if the file pointer is NULL

    size_t bytesRead = fread(ptr, size, nmemb, file);
    return bytesRead;
}

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
    size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
    return written;
}

struct ResponseData{
    char *data;
    size_t size;
};

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t real_size = size * nmemb;
    struct ResponseData *mem = (struct ResponseData *)userp;

    char *ptr = realloc(mem->data, mem->size + real_size + 1);
    if (ptr == NULL)
    {
        printf("[-]Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, real_size);
    mem->size += real_size;
    mem->data[mem->size] = 0;

    return real_size;
}

int is_allowed_extension(const char *file_path, char **extensions, int sizearray)
{
    char *extension = strrchr(file_path, '.');
    //if extension is null, rewrite extension to dotfile
    if (extension == NULL)
    {
        extension = "dotfile";
    }
    
    if (extension != NULL)
    {
        for (int i = 0; i < sizearray; i++)
        {
            char *extensionformat = extensions[i];
            extensionformat[strcspn(extensionformat, "\n")] = 0;

            if (strcmp(extension, extensionformat) == 0)
            {
                return TRUE;
            }
        }
    }
    return FALSE;
}

int compute_sha256(const char *file_path, unsigned char output[SHA256_DIGEST_LENGTH])
{
    FILE *file = fopen(file_path, "rb");
    if (!file)
    {
        perror("Error opening file\n");
        return 1;
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const int bufSize = 32768;
    unsigned char *buffer = malloc(bufSize);
    int bytesRead = 0;
    if (!buffer)
    {
        fprintf(stderr, "Unable to allocate buffer\n");
        return 1;
    }
    while ((bytesRead = fread(buffer, 1, bufSize, file)))
    {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    SHA256_Final(output, &sha256);
    fclose(file);
    free(buffer);
    return 0;
}

int is_hash_same(const char *file_path, const char *url, json_t *root)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if(compute_sha256(file_path, hash) != 0){
        fprintf(stderr, "Error computing hash\n");
        return 0;
    }

    char le_hash_string[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(&le_hash_string[i * 2], "%02x", hash[i]);
    }
    //from the file_path , remove the first /
    file_path = file_path + 1;
   

    json_t *value_json = json_object_get(root, file_path);
    char *value = json_string_value(value_json);
    if (value == NULL)
    {
        return FALSE;
    }
    if (strcmp(le_hash_string, value) == 0)
    {
        return TRUE;
    }
    return FALSE;
    
}

char* replace_space(const char *str){
    int space_count = 0;
    for(int i = 0; str[i]; i++){
        if(str[i] == ' '){
            space_count++;
        }
    }
    char *new_str = malloc(strlen(str) + space_count * 2 + 1);
    if (!new_str){
        perror("Error allocating memory\n");
        return NULL;
    }
    int j = 0;
    for (int i = 0; str[i]; i++)
    {
        if (str[i] == ' ')
        {
            new_str[j++] = '%';
            new_str[j++] = '2';
            new_str[j++] = '0';
        }
        else
        {
            new_str[j++] = str[i];
        }
    }
    new_str[j] = '\0';

    return new_str;
    }
    


CURLcode send_file(const char *file_path, const char *url){
    //cut file_path to get only the file name
    char *file_name = strrchr(file_path, '/');
    printf("[+]Sending file %s\n", file_name);
    printf("[+]Sending to %s\n", url);
    FILE *file = fopen(file_path, "rb");
    if (!file){
        perror("Error opening file\n");
        return CURLE_READ_ERROR;
    }

    CURL *curl = curl_easy_init();
    if(!curl){
        fclose(file);
        return CURLE_FAILED_INIT;
    }

    struct curl_httppost *formpost = NULL;
    struct curl_httppost *lastptr = NULL;
    struct curl_slist *headerlist = NULL;

    curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "file", CURLFORM_FILE, file_path, CURLFORM_END);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/save-cert.pem");

    curl_easy_setopt(curl,CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl,CURLOPT_READDATA, file);

    if(verbose == TRUE){
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }

    CURLcode res = curl_easy_perform(curl);

    curl_formfree(formpost);
    curl_slist_free_all(headerlist);
    curl_easy_cleanup(curl);
    fclose(file);

    return res;
    }

    void send_directory( char *dir_path, const char *url, char **extensions, int sizearray, json_t *root)
    {
        DIR *dir;
        struct dirent *entry;
        struct stat file_info;
        dir = opendir(dir_path);
        if (!dir)
        {
            perror("Error opening directory\n");
            return;
        }
        while ((entry = readdir(dir)) != NULL)
        {
            char file_path[1024];
            snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);
            if (stat(file_path, &file_info) == 0)
            {
                if (S_ISDIR(file_info.st_mode))
                {
                    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                    {
                        continue;
                    }

                    send_directory(file_path, url, extensions, sizearray,root);
                }
                else
                {
                    if(strcmp(entry->d_name, ".saveconfig") == 0){
                        continue;
                    }
                    if (is_allowed_extension(file_path, extensions,sizearray) == TRUE)
                    {
                        if (is_hash_same(file_path, url, root) == TRUE)
                        {
                            printf("[+]File %s already up to date.\n", file_path);
                            continue;
                        }
                        


                    printf("[+]File found: %s\n", file_path);
                    char *serveraddrcommandpush = malloc(strlen(url) + strlen(dir_path) + 1);
                    strcpy(serveraddrcommandpush, url);
                    
                    char *new_dir_path = replace_space(dir_path);

                    strcat(serveraddrcommandpush, new_dir_path);

                    CURLcode res = send_file(file_path, serveraddrcommandpush);
                    if(res != CURLE_OK){
                        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                    }
                    if (res == CURLE_OK)
                    {
                        printf("[+]File sent.\n");
                    }
                }

            }
        }
    }
    
    closedir(dir);
    }

void get_hash(const char *file_path, const char *url, struct ResponseData *response_data)
    {
        CURL *curl = curl_easy_init();
        if (!curl)
        {
            perror("Error initializing curl\n");
            return;
        }
        FILE *file = fopen(file_path, "rb");
        if (!file)
        {
            perror("Error opening file\n");
            return;
        }

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response_data);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
        curl_easy_setopt(curl, CURLOPT_READDATA, file);
        curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/save-cert.pem");
        if (verbose == TRUE)
        {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }
        
        
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            exit(1);
        }
        curl_easy_cleanup(curl);
        fclose(file);
    }


    void setArguments(char argc, char *argv[]){

        for (int i = 1; i < argc; i++)
        {
            if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
            {
                print_help();
                return 0;
            }
            else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            {
                verbose = TRUE;
            }
            else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--ip") == 0)
            {
                ip = argv[i + 1];
            }
            else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0)
            {
                //if argv+1 is -https , set IsHTTP to TRUE
                if (strcmp(argv[i + 1], "-https") == 0)
                {
                    IsHTTP = TRUE;
                    port = atoi(argv[i + 2]);
                }
                else{
                    port = atoi(argv[i + 1]);
                }

                
                
                
            }
            else if (strcmp(argv[i], "-cc") == 0 || strcmp(argv[i], "--customconfig") == 0)
            {
                GLOBAL_CONFIG = TRUE;
            }
        }
    }

    void checkIpnPort(char *ip, int port){
        if (ip == NULL || port == 0)
        {
            printf("[-]Please set ip and port.\n");
            return 0;
        }
    }

    void checkCommandError(char *command){
        if (command == NULL)
        {
            printf("[-]Please set a command.\n");
            return 0;
        }
        if (command[0] == '-' || (command[0] == '-' && command[1] == '-'))
        {
            printf("[-]Please set a command.\n");
            return 0;
        }
    }

    void checkFile(char *directory){
        if (directory == NULL)
        {
            printf("[-]Please set a directory/file.\n");
            return 0;
        }
        // if directory start with - or --, exit
        if (directory[0] == '-' || (directory[0] == '-' && directory[1] == '-'))
        {
            printf("[-]Please set a directory/file.\n");
            return 0;
        }
    }

    void isFileOrFolder(char *directory){
        struct stat st = {0};
        if (stat(directory, &st) == -1)
        {
            printf("[-]argument not found.\n");
            return 0;
        }
        char *real_path = realpath(directory, NULL);
        //check if it is directory or a file
        if (real_path == NULL)
        {
            printf("[-]File not found.\n");
            return 0;
        }
        if (verbose == TRUE)
        {
            if (S_ISDIR(st.st_mode))
            {
                IsFolder = TRUE;
                printf("[+]Directory found: %s\n", directory);
            }
            else
            {
                printf("[+]File found: %s\n", directory);
            }
        }
    }

    void checkEveryFileInFolder(char *file_path,json_t *root){
        DIR *dir;
        struct dirent *entry;
        struct stat file_info;
        char *dir_path = file_path;

        dir = opendir(file_path);
        if (!dir)
        {
            perror("Error opening directory\n");
            return;
        }
    
        while ((entry = readdir(dir)) != NULL)
        {
            char file_path[1024];

            size_t len = strlen(dir_path);
            if (dir_path[len - 1] == '/')
            {
                snprintf(file_path, sizeof(file_path), "%s%s", dir_path, entry->d_name);
            }
            else
            {
                snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);
            }

            if (stat(file_path, &file_info) == 0)
            {
                if (S_ISDIR(file_info.st_mode))
                {
                    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                    {
                        continue;
                    }
                    
                    checkEveryFileInFolder(file_path,root);
                }
                else
                {
                    if(strcmp(entry->d_name, ".saveconfig") == 0){
                        continue;
                    }
                    else{
                        
                        
                        json_t *value_json = json_object_get(root, file_path+1);
                        //if value_json is null, continue
                        if (value_json == NULL)
                        {
                            remove(file_path);
                        }
                        

                        
                    }
                }
            }
        }
    }

    void deleteEmptyDirs(const char *dir_path)
    {
        DIR *dir = opendir(dir_path);
        if (dir == NULL)
        {
            return;
        }

        int isEmpty = 1;
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
        {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
            {
                isEmpty = 0;
                break;
            }
        }
        closedir(dir);

        if (isEmpty)
        {
            rmdir(dir_path);
        }
        else
        {
            dir = opendir(dir_path);
            while ((entry = readdir(dir)) != NULL)
            {
                if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
                {
                    char path[1024];
                    snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
                    deleteEmptyDirs(path);
                }
            }
            closedir(dir);
        }
    }

    void getFile(const char *file_path, const char *url){
        CURL *curl = curl_easy_init();
        if (curl)
        {
            FILE *file = fopen(file_path, "wb");
            if (!file)
            {
                perror("Error opening file_path : %s\n");
                return;
            }

            

        curl_easy_setopt(curl,CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/save-cert.pem");
        if (verbose == TRUE)
        {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }



        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);
        fclose(file);
        }
    }

    struct Node{
        char *file;
        struct Node *next;
    };

    int exists_in_hashes(char *file, struct Node *hashes)
    {
        struct Node *node = hashes;
        while (node)
        {
            if (strcmp(node->file, file) == 0)
            {
                return 1;
            }
            node = node->next;
        }
        return 0;
    }

    void sendRmSignal(const char *url, const char *file)
    {
        //replace url space with %20
        char *newurl = malloc(strlen(url) + strlen(file) + 1);
        strcpy(newurl, url);
        newurl = replace_space(newurl);
        //replace file space with %20
        char *newfile = malloc(strlen(file) + 1);
        strcpy(newfile, file);
        newfile = replace_space(newfile);

        CURL *curl = curl_easy_init();
        if (curl)
        {
            char *serveraddrcommandrm = malloc(strlen(newurl) + strlen(newfile) + 12);
            strcpy(serveraddrcommandrm, newurl);
            strcat(serveraddrcommandrm, "files/rm/");
            strcat(serveraddrcommandrm, newfile);
            curl_easy_setopt(curl, CURLOPT_URL, serveraddrcommandrm);
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
            curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/save-cert.pem");
            if (verbose == TRUE)
            {
                curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
            }
            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK)
            {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            }
            curl_easy_cleanup(curl);
            free(serveraddrcommandrm);
        }
    }

    void checkFilesAndSendRm(const char *file_path, const char *url, json_t *root)
    {
        const char *key;
        json_t *value;

        json_object_foreach(root, key, value)
        {
            
           //change space to %20
            char *newurl = malloc(strlen(url) + strlen(key) + 1);
            strcpy(newurl, url);

            newurl = replace_space(newurl);
            //same for key
            char *newkey = malloc(strlen(key) + 1);
            strcpy(newkey, key);
           

            //add a / to the start of the key
            char *newkey2 = malloc(strlen(newkey) + 2);
            strcpy(newkey2, "/");
            strcat(newkey2, newkey);


            

            FILE *file = fopen(newkey2, "r");

            if (file)
            {
                printf("[+]File found: %s\n", newkey);
                fclose(file);
            }
            else
            {
              printf("[+]File not found: %s\n", newkey);
                sendRmSignal(newurl, newkey);
            }
        }
    }

    void getFileByHash(const char *file_path, const char *url, json_t *root){

        const char *key;
        json_t *value;

        json_object_foreach(root, key, value){
            if(!json_is_string(value)){
                fprintf(stderr, "Invalid hash value for %s\n", key);
                continue;
            }
            
            const char *expected_hash = json_string_value(value);

            char file_path[1024];
           
           
            snprintf(file_path, sizeof(file_path)+2, "%s/%s", file_path, key);

            //strcat url with file_path
            char *newurl = malloc(strlen(url) + strlen(key) + 1);
            strcpy(newurl, url);
            strcat(newurl, key);
            


          
            newurl = replace_space(newurl);
            
           
            
            
            
            FILE *file = fopen(file_path, "rb");
            if(!file){
                getFile(file_path, newurl);
                continue;
            }

            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            char buffer[BUFSIZ];
            int bytes_read;
            while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) != 0)
            {
                SHA256_Update(&sha256, buffer, bytes_read);
            }
            SHA256_Final(hash, &sha256);
            fclose(file);

            char le_vrai_hash[SHA256_DIGEST_LENGTH * 2 + 1];
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            {
                sprintf(&le_vrai_hash[i * 2], "%02x", hash[i]);
            }

            if (strcmp(expected_hash, le_vrai_hash) != 0)
            {
                getFile(file_path, newurl);
            }

        
        }


        
    }

    void checkCertificate(){
        //check if certificate exist in /etc/ssl/certs
        char *cert_path = "/etc/ssl/certs/save-cert.pem";
        //if certificate doesn't exist, return error

        FILE *file = fopen(cert_path, "r");
        if (!file)
        {
            printf("[-]Certificate not found.\n");
            exit(1);
        }
    }

        int main(char argc, char *argv[])
    {

        checkCertificate();
        char *home = getenv("HOME");
        char *command = argv[1];
        struct ResponseData response_datahash = {0};

        if (argc == 1)
        {
            print_help();
            return 0;
        }

        setArguments(argc, argv);

        // check if ip and port are set
        checkIpnPort(ip, port);

        if (verbose == TRUE)
        {
            if (IsHTTP== TRUE)
            {
                printf("[+]HTTPS protocol\n");
            }
            else
            {
                printf("[+]HTTP protocol\n");
            }
            
        }
        
        

        checkCommandError(command);

        if (strcmp(command,"push")==0){
        //check if folder or file
        char *directory = argv[2];
        //check if it is directory or a file
        checkFile(directory);
        isFileOrFolder(directory);
        char *saveconfig;
        char *real_path;
        if (IsFolder == TRUE)
        {
            if (GLOBAL_CONFIG==FALSE)
            {
                saveconfig = malloc(strlen(home) + 13);
                saveconfig = strcat(home, "/.saveconfig");
                if(access(saveconfig, F_OK) == -1){
                    printf("[-]No config file found, creating one...\n");
                    FILE *fp = fopen(saveconfig, "w");
                    fprintf(fp, "## Save config file\n");
                    fprintf(fp, "## Add extensions to save here, one per line\n");
                    fprintf(fp, "## Example: .txt\n");
                    fprintf(fp, "## if you want to save extensionless files, add a dotfile\n");
                    fprintf(fp, "## Example: dotfile\n");
                    fclose(fp);

                    printf("[+]Config file created, please edit it and try again.\n");
                    return 0;
                }
                else{
                    printf("[+]Config file found, reading...\n");
                }

            }
            else
            {
                // check if ~/.saveconfig exist in the folder you said
                char *dir = argv[2];
                if (dir == NULL)
                {
                    printf("[-]Please set a directory.\n");
                    return 0;
                }
                // if directory start with - or --, exit
                if (dir[0] == '-' || (dir[0] == '-' && dir[1] == '-'))
                {
                    printf("[-]Please set a directory.\n");
                    return 0;
                }
                struct stat st = {0};
                if (stat(dir, &st) == -1)
                {
                    printf("[-]Directory not found.\n");
                    return 0;
                }
                real_path = realpath(dir, NULL);
                saveconfig = malloc(strlen(real_path) + 13);
                saveconfig = strcat(real_path, "/.saveconfig");
                if (access(saveconfig, F_OK) == -1)
                {
                    printf("[-]No config file found, please create one.\n");
                    return 0;
                }
            }
            FILE *fp = fopen(saveconfig, "r");
            char *line = NULL;
            size_t len = 0;
            ssize_t read;
            if (fp == NULL)
            {
                printf("[-]Error reading config file.\n");
                return 0;
            }
            char **extensions = NULL;
            int i = 0;
            
            while ((read = getline(&line, &len, fp)) != -1)
            {
                //if line empty or commented by ##, skip
                if ((line[0] == '#' && line[1] == '#') || line[0] == '\n')
                    continue;
                extensions = realloc(extensions, (i + 1) * sizeof(char *));
                extensions[i] = malloc(strlen(line) + 1);
                strcpy(extensions[i], line);
                i++;
            }
            fclose(fp);
            if (line)
                free(line);

            //if no extensions found, exit
            if (i == 0)
            {
                printf("[-]No extensions found in config file.\n");
                return 0;
            }

            if (verbose == TRUE)
            {
                // print extensions
                printf("[+]Extensions found:\n");
                for (int j = 0; j < i; j++)
                {
                    printf("%s", extensions[j]);
                }

                // print ip and port
                printf("[+]IP: %s\n", ip);
                printf("[+]Port: %d\n", port);
                printf("[+]Command: %s\n", command);
            }
            char *real_path = realpath(directory, NULL);

            char *serveraddrhttp = malloc(strlen(ip) + 7);
            if(IsHTTP == TRUE)
            strcpy(serveraddrhttp, "https://");
            else
            strcpy(serveraddrhttp, "http://");
            strcat(serveraddrhttp, ip);
            strcat(serveraddrhttp, ":");
            char portstr[6];
            sprintf(portstr, "%d", port);
            strcat(serveraddrhttp, portstr);
            strcat(serveraddrhttp, "/");
            char *serveraddrcommandpush = malloc(strlen(serveraddrhttp) + strlen(directory) + 12);
            strcpy(serveraddrcommandpush, serveraddrhttp);
            strcat(serveraddrcommandpush, "files/push");

            char *serveraddrcommandgethash = malloc(strlen(serveraddrhttp) + strlen(directory) + 12);
            strcpy(serveraddrcommandgethash, serveraddrhttp);
            strcat(serveraddrcommandgethash, "files/hash/");

            char *serveraddrcommandRM = malloc(strlen(serveraddrhttp) + strlen(directory) + 12);
            strcpy(serveraddrcommandRM, serveraddrhttp);
            
            if (verbose == TRUE)
            {
                printf("[+]Server address: %s\n", serveraddrhttp);
            }

            curl_global_init(CURL_GLOBAL_ALL);

            get_hash(real_path, serveraddrcommandgethash, &response_datahash);

            json_error_t error;
            json_t *root = json_loads(response_datahash.data, 0, &error);
            if (!root)
            {
                fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
                return 1;
            }

            send_directory(real_path, serveraddrcommandpush, extensions, i, root);
            checkFilesAndSendRm(real_path, serveraddrcommandRM, root);
            curl_global_cleanup();

            //free memory
            free(serveraddrhttp);
            free(serveraddrcommandpush);
            free(serveraddrcommandgethash);
            free(real_path);
            json_decref(root);
            free(response_datahash.data);
        }

        else{
            char *file_path = argv[2];
            char *real_path = realpath(file_path, NULL);
            if (real_path == NULL)
            {
                printf("[-]File not found.\n");
                return 0;
            }
            if (verbose == TRUE)
            {
                printf("[+]File found: %s\n", file_path);
            }
            char *serveraddrhttp = malloc(strlen(ip) + 7);
            if (IsHTTP == TRUE)
                strcpy(serveraddrhttp, "https://");
            else
                strcpy(serveraddrhttp, "http://");
            strcat(serveraddrhttp, ip);
            strcat(serveraddrhttp, ":");
            char portstr[6];
            sprintf(portstr, "%d", port);
            strcat(serveraddrhttp, portstr);
            strcat(serveraddrhttp, "/");
            char *serveraddrcommandpush = malloc(strlen(serveraddrhttp) + strlen(file_path) + 12);
            strcpy(serveraddrcommandpush, serveraddrhttp);
            strcat(serveraddrcommandpush, "files/push");

            char *serveraddrcommandgethash = malloc(strlen(serveraddrhttp) + strlen(file_path) + 12);
            strcpy(serveraddrcommandgethash, serveraddrhttp);
            strcat(serveraddrcommandgethash, "files/hash/");

            if (verbose == TRUE)
            {
                printf("[+]Server address: %s\n", serveraddrhttp);
            }

            curl_global_init(CURL_GLOBAL_ALL);

            get_hash(real_path, serveraddrcommandgethash, &response_datahash);

            json_error_t error;
            json_t *root = json_loads(response_datahash.data, 0, &error);
            if (!root)
            {
                fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
                return 1;
            }
            //concatenate serveraddrcommandpush and the path leading to the file
            //get real_path and delete everything after the last /
            char *file_name = strrchr(real_path, '/');
            char *new_real_path = malloc(strlen(real_path) + 1);
            strncpy(new_real_path, real_path, file_name - real_path);
            new_real_path[file_name - real_path] = '\0';
            strcat(serveraddrcommandpush, new_real_path);            
            //if hash is the same, don't send
            if (is_hash_same(real_path, serveraddrcommandgethash, root) == TRUE)
            {
                printf("[+]File already up to date.\n");
                return 0;
            }
            send_file(real_path, serveraddrcommandpush);
            curl_global_cleanup();
        
        }
        
        


       printf("[+]Everything sent.\n");
    }
    else if(strcmp(command, "pull") == 0)
    {
        char *type = argv[2];
        if(strcmp(type,"-d")==0){
            IsFolder = TRUE;
        }
        else if(strcmp(type,"-f")==0){
            IsFolder = FALSE;
        }
        else{
            printf("[-]Please set a type.\n");
            return 0;
        }
        char *directory = argv[3];

        checkFile(directory);
        
        if (IsFolder==FALSE)
        {
            //get hash
            char *serveraddrhttp = malloc(strlen(ip) + 7);
            if (IsHTTP == TRUE)
                strcpy(serveraddrhttp, "https://");
            else
                strcpy(serveraddrhttp, "http://");
            strcat(serveraddrhttp, ip);
            strcat(serveraddrhttp, ":");
            char portstr[6];
            sprintf(portstr, "%d", port);
            strcat(serveraddrhttp, portstr);
            strcat(serveraddrhttp, "/");
            char *serveraddrcommandgethash = malloc(strlen(serveraddrhttp) + strlen(directory) + 12);
            strcpy(serveraddrcommandgethash, serveraddrhttp);
            strcat(serveraddrcommandgethash, "files/hash");

            char *serveraddrcommandpull = malloc(strlen(serveraddrhttp) + strlen(directory) + 12);
            strcpy(serveraddrcommandpull, serveraddrhttp);
            strcat(serveraddrcommandpull, "files/pull/");
            if (verbose == TRUE)
            {
                printf("[+]Server address: %s\n", serveraddrhttp);
            }

            //get the path from where you execute the command and add the directory
            char cwd[1024];
            getcwd(cwd, sizeof(cwd));
            char *file_path = malloc(strlen(cwd) + strlen(directory) + 1);
            strcpy(file_path, cwd);
            strcat(file_path, "/");
            strcat(file_path, directory);
            printf("[+]File found: %s\n", file_path);

            curl_global_init(CURL_GLOBAL_ALL);

            get_hash(directory, serveraddrcommandgethash, &response_datahash);

            json_error_t error;
            json_t *root = json_loads(response_datahash.data, 0, &error);
            if (!root)
            {
                fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
                return 1;
            }

            //if file doesn't even exist, get it
            if(access(file_path, F_OK) == -1){
                getFile(file_path, serveraddrcommandpull);
                return 0;
            }

            //if hash is the same, don't get
            if (is_hash_same(file_path, serveraddrcommandgethash, root) == TRUE) printf("[+] File already up to date.\n");
            else getFile(file_path, serveraddrcommandpull);
        }else{
            // get hash
            char *serveraddrhttp = malloc(strlen(ip) + 7);
            if (IsHTTP == TRUE)
                strcpy(serveraddrhttp, "https://");
            else
                strcpy(serveraddrhttp, "http://");
            strcat(serveraddrhttp, ip);
            strcat(serveraddrhttp, ":");
            char portstr[6];
            sprintf(portstr, "%d", port);
            strcat(serveraddrhttp, portstr);
            strcat(serveraddrhttp, "/");
            char *serveraddrcommandgethash = malloc(strlen(serveraddrhttp) + strlen(directory) + 12);
            strcpy(serveraddrcommandgethash, serveraddrhttp);
            strcat(serveraddrcommandgethash, "files/hash");


            if (verbose == TRUE)
            {
                printf("[+]Server address: %s\n", serveraddrhttp);
            }
            
            //get the path from where you execute the command and add the directory
            char cwd[1024];
            getcwd(cwd, sizeof(cwd));
            char *file_path = malloc(strlen(cwd) + strlen(directory) + 1);
            strcpy(file_path, cwd);
            strcat(file_path, "/");
            strcat(file_path, directory);
            printf("[+]Directory found: %s\n", file_path);
            //put the directory in the url
            char *new_dir_path = replace_space(file_path);
            printf("[+]New directory: %s\n", new_dir_path);
            
            
            
            

            curl_global_init(CURL_GLOBAL_ALL);
            
            strcat(serveraddrcommandgethash, new_dir_path);

            char *serveraddrcommandpull = malloc(strlen(serveraddrhttp) + strlen(new_dir_path) + 12);

            strcpy(serveraddrcommandpull, serveraddrhttp);
            strcat(serveraddrcommandpull, "files/pull/");
                    

            get_hash(directory, serveraddrcommandgethash, &response_datahash);
            
            json_error_t error;
            json_t *root = json_loads(response_datahash.data, 0, &error);
            if (!root)
            {
                fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
                return 1;
            }
            

            getFileByHash(file_path, serveraddrcommandpull, root);
            checkEveryFileInFolder(file_path, root);
            deleteEmptyDirs(file_path);
            
            

            curl_global_cleanup();
        }
        
    }
    else{
        printf("[-]Command not found.\n");
        return 0;
    }
return 0;
}