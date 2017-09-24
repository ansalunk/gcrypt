#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define N_MODE "-d"
#define L_MODE "-l"
#define SHA_KEY_SIZE 16


char * in_file; // file generated after decryption i.e. with .uf extension
char * enc_file; // buffer to save the encrypted data received
int dec_mode; // Mode can be Local or Network. Specified from command line
char * port; // port to connect to the server

//server to listen incoming connections


//Generate HMAC value`
char * fetch_hmac( char * key, size_t size, char * cipher){
	
	gcry_error_t err;
	gcry_md_hd_t handle;
	char * hmac;//variable to strore the hmac value
	
	err = gcry_md_open(&handle, GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
	if(err){
		printf ("Failed to open handle for hmac\n");
		gcry_strerror(err);
		exit(-1);
	}
	err = gcry_md_enable(handle,GCRY_MD_SHA512);
	err = gcry_md_setkey(handle, key,SHA_KEY_SIZE );
	if(err){
		printf ("Failed to set key for hmac \n");
		gcry_strerror(err);
		exit(-1);
	}
	//HMAC generatiom
  	gcry_md_write(handle,cipher,size);
  	gcry_md_final(handle);
	
	hmac = gcry_md_read(handle , GCRY_MD_SHA512 );
	//Check if HMAC is generated 
	if(hmac == NULL ){
		printf ("hmac is null\n");
		// exit(-1);
	}
	return hmac;
}

char * decrypt_with_aes(char * key,char *enc_buffer, size_t size,char *hmac){
	gcry_cipher_hd_t h;
	gcry_error_t err;
	int IV[16] = {5844}; 

	char *hmac_d;
	char * out_buffer = malloc(size);
	
	// open cipher handle
	err = gcry_cipher_open(&h, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);
	if(err){
		printf ("Failed to open: \n");
		gcry_strerror(err);
		exit(-1);
	}
    // set the key for decryption
    err = gcry_cipher_setkey(h, key, SHA_KEY_SIZE);
    if(err){
		printf ("Failed to set key \n");
		gcry_strerror(err);
		exit(-1);
	}
	// set the IV for decryption
    err = gcry_cipher_setiv(h, &IV, 16);
    if(err){
		printf ("Failed to set IV: \n");
		gcry_strerror(err);
		exit(-1);
	}
	// decrypt
    err = gcry_cipher_decrypt(h, out_buffer, size, enc_buffer, size);
    if(err){
		printf ("Failed to decrypt file: \n");
		gcry_strerror(err);
		exit(-1);
	}

	hmac_d = fetch_hmac(key,size, enc_buffer);
	
	int i;
	//Error with exit code 62 if input HMAC is incorrect 
	for(i=0;i<64;i++){
		if (hmac_d[i] != hmac[i]){
			printf ("HMAC verification failed\n");
			exit(62);
		}
	}
	printf("HMAC Verified Successfully\n");

	FILE * file;

	//Open the file connection with write mode
	file = fopen(in_file,"w+b");
	
	//Check if file already exists if yes exit with code 33 else write to the file
	if (!file){
		printf ("File already exists\n");
		exit(33);
		
	}
	else{
		fwrite(out_buffer, size -16, 1, file);
		int index,itr;
		char * end = (out_buffer + size -16);
		for(itr=16;itr>0;itr--){

			if(end[itr-1] != 0){
				index = itr;

				itr = -1;
			}
		}
		fwrite(out_buffer+(size -16),index+1, 1, file);

		fclose(file);

	}
	return out_buffer;

}

void daemon(char * port){
	
	//socket handlers
  	int listen_handle;
    int con_handle;
	struct sockaddr_in saddr , caddr;
	
    int PORT = atoi(port);//cast the port to int
   	printf("%d\n", PORT );

    int addrlen = sizeof(caddr);

	//socket creation
    listen_handle = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_handle < 0)
    {
        printf("\n Failure creating Socket \n");
        exit(-1);
    }

    int bytes_total = 0;
    char r_buffer[256];
    memset(r_buffer, '0', sizeof(r_buffer));
    
    memset(&saddr, '0', sizeof(saddr));
    saddr.sin_family = AF_INET;//setting the address family for server_address which is same as the client socket i.e. 	AF_INET
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port = htons(PORT); //htons - conversion function that passes our port number in right network byte order i.e. it converts it to appropriate data format

	//bind the socket to our specified IP address and port

	if(bind(listen_handle, (struct sockaddr*)&saddr,sizeof(saddr)) == -1){
		printf("\n Error while binding to Server \n");
		close(listen_handle);
        exit(-1);
	}

	//listen function to listen for connections. second argument indicates how many connections can be waiting for server socket
    listen(listen_handle, 5);

    // write data from network to file
    FILE *f_out;
    f_out = fopen(enc_file, "w+b");
    if(f_out == NULL)
    {
        printf("Failure to open file");
     }

    printf("Waiting for connections.\n");
    while(1)
    {
	//Wait for the incoming connections
    	con_handle = accept(listen_handle, (struct sockaddr*)&caddr, (unsigned int *)&addrlen);
	    printf("Inbound File.\n");
	    while((bytes_total = read(con_handle, r_buffer, 256)) > 0)
	    {
	        fwrite(r_buffer, 1,bytes_total,f_out);
	        if(bytes_total < 256)
		    {
		        printf("File received from the client \n");
		        close(con_handle);
		        fclose(f_out);
		        return;
		    }
	    }
	    close(con_handle);
    }
}




//Fetch the inbound file
void decrypt( char * key, char * enc_buffer){
	
	

	FILE *file;
	
	//Open the file in read mode and read the encrypted data
	file=fopen(enc_buffer, "r");
		if (file == NULL) {
	  		printf("Can't open input file.\n");
	  		exit(0);
		}
	char * input_buffer, *hmac , *cipher;
	long int f_size;
	size_t buffer_size;

	//Calculate the file size
	fseek(file, 0, SEEK_END);
	f_size = ftell(file) - 1;
	
	//Below we do the adjustments to get the encrypted text and the HMAC
	//Allocate memory for HMAC 
	hmac = (char * ) malloc(64 * (sizeof(char)));
	//Allocate memory for the cipher text
	cipher = (char * ) malloc((f_size - 64) * (sizeof(char)));
	fseek (file, -65L, SEEK_END);
	
	//Read the HMAC value from the 64th position
	fread(hmac,sizeof(char),64,file);
	//Rewind to read the encrypted content
	rewind(file);
	fseek (file, 0, SEEK_SET);
	fread(cipher,sizeof(char),f_size-64,file);


	//Generating the file buffer for inbound file 
	char * buffer = 0;
	long length;
	FILE * f = fopen (enc_buffer, "rb");

	if (f)
	{
	  fseek (f, 0, SEEK_END);
	  length = ftell (f)-1;
	  fseek (f, 0, SEEK_SET);
	  buffer = malloc (length);
	  fread (buffer, sizeof(char), length, f);
		fclose (f);
}


	//Print the hash of the Encrypted file + HMAC
	print_sha_inbound_file(buffer, length);



	//Decrypt the file with cipher having size of f_size-64 with HMAC having size 64
	decrypt_with_aes(key, cipher, f_size-64,hmac);
	
}

void print_sha_inbound_file(char *inbound_buffer, size_t buffer_size){

	char *hash = (char *) malloc(64* (sizeof(char)));

	//method gcry_md_hash_buffer includes
	//GCRY_MD_SHA512 - Algorithm used for hash
	//hash - Outout the final hash value
	//input_buffer - file contents read from file and written to buffer
	//buffer_size - size of the input_buffer
	gcry_md_hash_buffer( GCRY_MD_SHA512, hash, inbound_buffer, buffer_size );
	
	
	int count;
	printf("\nPrinting the hash of the encrypted with hmac file\n\n");
	for(count = 0; count < 64; count++){
		printf("%02X ",(unsigned char)hash[count] );
	}
	printf("\n");
	printf("file length : %u\n",strlen(inbound_buffer)); 
	printf("\n\n");
		
	
}


int main(int argc, char *argv[]){
//verifying if the arguments from command line are correct
	char pwd[10];
	char key[SHA_KEY_SIZE];
	char *input_buffer;
	FILE *fp;
	size_t buffer_size;

	// Case 1 - incorrect command line input
	if(argc < 3){
		printf("Format for input is sundec <input file> [-d < port >][-l]\n");
  		exit(0);
	}
	
	//Case 2 - Missing Ip address or Port no followed by -d when arguments are 4
	if( argc<4){
		if((strcmp(argv[2], N_MODE) == 0)){
		printf("incorrect input ip address and port no neeeded \n");
  		exit(-1);
		}
	}
	//Case 3: If  mode is -d set mode to 1 
if( argc==4){	
	if((strcmp(argv[2], N_MODE) == 0)){
		dec_mode = 1; 
		in_file = argv[1] ;
		daemon(argv[3]); 
	}
}		//Case 4 : When the input is mode is -l set the mode to 0

	else if((strcmp(argv[2], L_MODE) == 0)){
		dec_mode = 0; 		
		in_file = (char *)malloc(strlen(argv[1])-3);
		strncpy(in_file,argv[1],(strlen(argv[1])-3));
		 
	}
 //initializing the library libgcrypt as specified in manual
	//Check for the version
	if (!gcry_check_version (GCRYPT_VERSION))
	 {
	   printf("libgcrypt version doesnt match \n");
	   exit(-1);
	 }
	gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
	
	//Fetch the password from the command line
	printf("Enter the Password: ");
	scanf("%s", pwd);

	//Key Generation
	int i, err;
		err = gcry_kdf_derive(pwd, strlen(pwd), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, "NaCl",
						strlen("NaCl"), 4096, SHA_KEY_SIZE, key);
	if(err){

		printf("\n Error : \n");
		gcry_strerror(err);
	}
	else{
		printf("Key: ");
			int i;
	for(i = 0; i < SHA_KEY_SIZE; i++){
		printf("%02X ",(unsigned char) key[i]);
	}
	printf("\n"); 
	}
	
	//If dec_mode is 0 - Local mode
	if(dec_mode == 0){
		
		decrypt(key,argv[1]);
		printf("file has been decrypted : %s file to %s\n",argv[1],in_file);
	}
	//If dec_mode is 1- Network mode

	if(dec_mode == 1){
		
		decrypt(key,enc_file);
		printf("file has been decrypted\n");
		remove(enc_file);
	}
	return 0;
}


